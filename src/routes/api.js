/**
 * WebSentinel-CS :: API Routes Handler (Hardenized P0 Architecture)
 * Dispatches and processes all /api/* endpoints with RBAC, CSRF, and Parameter Sanitization
 */

const { parseJsonBody } = require('../http/body');
const { sendJson, sendError, sendCsv } = require('../http/respond');
const { inspectPayload } = require('../engine/signatures');
const { auditTargetUrl } = require('../engine/scanner');
const { authenticateRequest, verifyScryptPassword } = require('../http/auth');
const { sanitizeAndValidateQuery, executeQueryWithWorker } = require('../engine/sql-runner');

const ALLOWED_SEVERITY = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
const ALLOWED_ACTIONS = new Set(['BLOCKED', 'FLAGGED', 'CHALLENGED', 'MONITORED', 'PASSED', 'LOGGED', 'AUDITED', 'DROPPED', 'IP_BLOCKED', 'REJECTED', 'AUTHORIZED']);
const ALLOWED_RISK_LEVELS = new Set(['CRITICAL', 'HIGH', 'ELEVATED', 'MEDIUM', 'LOW', 'NORMAL']);

function getEffectiveClientIp(req, bodyIp, auth, config) {
  // Only trust declared body IP if authenticated via API Key with 'ingest' scope
  if (auth && auth.type === 'api_key' && auth.scopes && auth.scopes.includes('ingest') && bodyIp) {
    return String(bodyIp).trim();
  }
  return req.socket.remoteAddress || '127.0.0.1';
}

function createApiHandler({ config, db, rateLimiter, stats }) {
  function logEvent(type, severity, sourceIp, target, ruleId, details, action = 'LOGGED') {
    const sev = ALLOWED_SEVERITY.has(severity) ? severity : 'INFO';
    const act = ALLOWED_ACTIONS.has(action) ? action : 'LOGGED';

    const event = {
      id: 'SEC-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substr(2, 4).toUpperCase(),
      timestamp: new Date().toISOString(),
      type,
      severity: sev,
      sourceIp: sourceIp || '127.0.0.1',
      target: target || '/api',
      ruleId: ruleId || 'RULE-GENERIC',
      details,
      action: act
    };

    db.insertIncident(event);

    if (sev === 'CRITICAL' || sev === 'HIGH') {
      stats.threatsDetected++;
    }
    return event;
  }

  return async function handleApi(req, res, parsedUrl) {
    const pathname = parsedUrl.pathname;
    const method = req.method;

    try {
      // -----------------------------------------------------------------------
      // Public Route: /healthz
      // -----------------------------------------------------------------------
      if (pathname === '/healthz') {
        return sendJson(res, 200, {
          status: 'UP',
          version: config.VERSION,
          engine: 'ACTIVE_ARMED',
          timestamp: new Date().toISOString()
        });
      }

      // -----------------------------------------------------------------------
      // Public Route: POST /api/auth/login
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/auth/login') {
        const body = await parseJsonBody(req, config.MAX_BODY_BYTES);
        const { username, password } = body;
        if (!username || !password) {
          return sendError(res, 400, 'Se requieren las credenciales de usuario y contraseña');
        }

        const user = db.findUserByUsername(username);
        if (!user || !verifyScryptPassword(password, user.salt, user.password_hash)) {
          return sendError(res, 401, 'Credenciales de acceso no válidas');
        }

        const session = db.createAuthSession(user.id, 8);
        if (!session) {
          return sendError(res, 500, 'No fue posible iniciar la sesión de usuario');
        }

        const isSecure = config.ENV === 'production' && req.socket.encrypted;
        const cookieHeader = `sentinel_session=${session.sessionId}; Path=/; HttpOnly; SameSite=Strict${isSecure ? '; Secure' : ''}`;

        return sendJson(res, 200, {
          success: true,
          user: { id: user.id, username: user.username, role: user.role },
          csrfToken: session.csrfToken
        }, { 'Set-Cookie': cookieHeader });
      }

      // -----------------------------------------------------------------------
      // Centralized Authentication Check for All Other /api/* Endpoints
      // -----------------------------------------------------------------------
      const auth = authenticateRequest(req, db, pathname);
      if (!auth.authenticated) {
        return sendError(res, auth.statusCode || 401, auth.message || 'No autorizado');
      }
      req.auth = auth;

      // -----------------------------------------------------------------------
      // Auth Route: GET /api/auth/me
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/auth/me') {
        return sendJson(res, 200, {
          authenticated: true,
          type: auth.type,
          user: auth.user || null,
          scopes: auth.scopes || null
        });
      }

      // -----------------------------------------------------------------------
      // Auth Route: POST /api/auth/logout
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/auth/logout') {
        if (auth.session) {
          db.deleteAuthSession(auth.session.id);
        }
        const cookieHeader = 'sentinel_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0';
        return sendJson(res, 200, { success: true }, { 'Set-Cookie': cookieHeader });
      }

      // -----------------------------------------------------------------------
      // GET /api/stats
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/stats') {
        const summary = db.getAnalyticsSummary();
        return sendJson(res, 200, {
          totalScans: stats.totalScans,
          threatsDetected: stats.threatsDetected,
          bruteForceBlocked: stats.bruteForceBlocked,
          inspectionsRun: stats.inspectionsRun,
          uptimeSeconds: Math.floor((Date.now() - stats.startTime) / 1000),
          totalPersistedIncidents: summary.totalIncidents,
          criticalCount: summary.criticalCount,
          engineStatus: 'ACTIVE_ARMED',
          storageEngine: 'SQLITE_PERSISTENT'
        });
      }

      // -----------------------------------------------------------------------
      // GET /api/events
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/events') {
        const severity = parsedUrl.searchParams.get('severity') || 'ALL';
        const limitParam = parsedUrl.searchParams.get('limit') || '100';
        const offsetParam = parsedUrl.searchParams.get('offset') || '0';

        const limit = Math.min(Math.max(1, parseInt(limitParam, 10) || 100), 500);
        const offset = Math.max(0, parseInt(offsetParam, 10) || 0);

        const rows = db.getIncidents(limit, severity, offset);
        return sendJson(res, 200, rows);
      }

      // -----------------------------------------------------------------------
      // GET /api/sql/summary
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/sql/summary') {
        const summary = db.getAnalyticsSummary();
        return sendJson(res, 200, summary);
      }

      // -----------------------------------------------------------------------
      // POST /api/sql/query (Hardened SQL Forensics Console)
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/sql/query') {
        // Strict RBAC: Only admin role allowed
        const userRole = (auth.user && auth.user.role) || auth.role;
        if (userRole !== 'admin') {
          return sendError(res, 403, 'Acceso denegado: La consola SQL requiere privilegios de administrador');
        }

        const body = await parseJsonBody(req, config.MAX_BODY_BYTES);
        const rawQuery = body.query || 'SELECT * FROM incidents ORDER BY timestamp DESC LIMIT 10';

        let cleanQuery;
        try {
          cleanQuery = sanitizeAndValidateQuery(rawQuery);
        } catch (valErr) {
          return sendError(res, 400, valErr.message);
        }

        const startTime = Date.now();
        const execResult = await executeQueryWithWorker(config.DB_PATH, cleanQuery, db, 3000);
        const durationMs = Date.now() - startTime;

        const userId = (auth.user && auth.user.id) || 'usr-admin';
        const rowsCount = execResult.rows ? execResult.rows.length : 0;

        db.insertAuditLog({
          userId,
          query: cleanQuery,
          durationMs,
          rowsReturned: rowsCount
        });

        if (execResult.timeout) {
          return sendError(res, 408, execResult.error);
        }

        if (!execResult.success) {
          return sendError(res, 400, execResult.error);
        }

        return sendJson(res, 200, {
          success: true,
          count: execResult.rows.length,
          durationMs,
          rows: execResult.rows
        });
      }

      // -----------------------------------------------------------------------
      // GET /api/export-csv
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/export-csv') {
        const rows = db.getIncidents(500, 'ALL');
        let csv = 'ID,TIMESTAMP,SEVERITY,TYPE,RULE_ID,SOURCE_IP,TARGET,ACTION,DETAILS\n';
        for (const ev of rows) {
          const cleanDetails = (ev.details || '').replace(/"/g, '""');
          csv += `"${ev.id}","${ev.timestamp}","${ev.severity}","${ev.type}","${ev.rule_id}","${ev.source_ip}","${ev.target}","${ev.action}","${cleanDetails}"\n`;
        }
        return sendCsv(res, 'websentinel-audit-events.csv', csv);
      }

      // -----------------------------------------------------------------------
      // POST /api/scan (SSRF-Protected URL Auditor)
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/scan') {
        const body = await parseJsonBody(req, config.MAX_BODY_BYTES);
        if (!body.url) {
          return sendError(res, 400, 'Parámetro URL requerido');
        }

        stats.totalScans++;
        const audit = await auditTargetUrl(body.url, config.SCAN_ALLOWLIST, 3, 5000);

        if (!audit.error) {
          const sev = audit.securityScore < 50 ? 'HIGH' : (audit.securityScore < 80 ? 'MEDIUM' : 'INFO');
          logEvent(
            'URL_AUDIT_PROBE',
            sev,
            req.socket.remoteAddress,
            body.url,
            'RULE-AUDIT-01',
            `Auditoría completada. Calificación: ${audit.securityScore}/100. Faltantes: ${audit.missingHeadersCount}. Latencia: ${audit.latencyMs}ms.`,
            'AUDITED'
          );
          db.saveScanResult(audit);
          return sendJson(res, 200, audit);
        } else {
          logEvent(
            'URL_AUDIT_FAILURE',
            'MEDIUM',
            req.socket.remoteAddress,
            body.url,
            'RULE-AUDIT-02',
            audit.error,
            'DROPPED'
          );
          return sendJson(res, 200, audit);
        }
      }

      // -----------------------------------------------------------------------
      // POST /api/analyze-request
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/analyze-request') {
        const data = await parseJsonBody(req, config.MAX_BODY_BYTES);
        stats.inspectionsRun++;
        const input = data.input || '';
        const honeypot = data.honeypot || '';
        const clientIp = getEffectiveClientIp(req, data.clientIp, auth, config);
        const target = data.targetEndpoint || '/api/v1/resource';

        const threats = inspectPayload(input, honeypot);

        if (threats.length > 0) {
          for (const t of threats) {
            logEvent(
              'INJECTION_THREAT',
              t.severity,
              clientIp,
              target,
              t.ruleId,
              `${t.name} (${t.cwe}). Muestra: "${input.substring(0, 48)}"`,
              'BLOCKED'
            );
          }
        } else {
          logEvent(
            'PAYLOAD_INSPECTED',
            'INFO',
            clientIp,
            target,
            'RULE-WAF-CLEAN',
            'Comprobación de integridad exitosa. Sin patrones maliciosos conocidos.',
            'PASSED'
          );
        }

        return sendJson(res, 200, {
          safe: threats.length === 0,
          threatCount: threats.length,
          threats
        });
      }

      // -----------------------------------------------------------------------
      // POST /api/record-login
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/record-login') {
        const data = await parseJsonBody(req, config.MAX_BODY_BYTES);
        const clientIp = getEffectiveClientIp(req, data.clientIp, auth, config);
        const identifier = data.identifier || data.email || 'anonymous';
        const isSuccess = Boolean(data.success);

        const rate = rateLimiter.evaluate(clientIp, !isSuccess);

        if (rate.isBlocked) {
          stats.bruteForceBlocked++;
          logEvent(
            'AUTH_BRUTEFORCE_MITIGATED',
            'CRITICAL',
            clientIp,
            '/auth/login',
            'RULE-RATE-001',
            `Límite de tasa excedido (${rate.recentFailures} fallos/min). IP en cooldown por ${rate.retryAfterSec}s.`,
            'IP_BLOCKED'
          );
        } else if (!isSuccess) {
          logEvent(
            'AUTH_FAILURE',
            rate.recentFailures >= 3 ? 'HIGH' : 'LOW',
            clientIp,
            '/auth/login',
            'RULE-AUTH-002',
            `Intento de autenticación fallido para identidad "${identifier}". Conteo acumulado: ${rate.recentFailures}/${rate.threshold}.`,
            'REJECTED'
          );
        } else {
          logEvent(
            'AUTH_SUCCESS',
            'INFO',
            clientIp,
            '/auth/login',
            'RULE-AUTH-001',
            `Autenticación exitosa confirmada para "${identifier}".`,
            'AUTHORIZED'
          );
        }

        return sendJson(res, 200, {
          status: rate.isBlocked ? 'BLOCKED' : (isSuccess ? 'AUTHORIZED' : 'DENIED'),
          rate
        });
      }

      // -----------------------------------------------------------------------
      // POST /api/simulate-attack
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/simulate-attack') {
        const data = await parseJsonBody(req, config.MAX_BODY_BYTES);
        const vector = data.vector || 'sqli';
        const fakeIp = `198.51.100.${Math.floor(Math.random() * 200) + 10}`;

        if (vector === 'sqli') {
          logEvent(
            'INJECTION_THREAT',
            'CRITICAL',
            fakeIp,
            '/api/records/query',
            'SIG-SQLI-001',
            "Ataque simulado: [SELECT * FROM users WHERE id = '' OR 1=1 --]. Interceptado por motor heurístico.",
            'BLOCKED'
          );
        } else if (vector === 'bruteforce') {
          for (let i = 0; i < 5; i++) {
            rateLimiter.evaluate(fakeIp, true);
          }
          stats.bruteForceBlocked++;
          logEvent(
            'AUTH_BRUTEFORCE_MITIGATED',
            'CRITICAL',
            fakeIp,
            '/auth/admin',
            'SIG-RATE-001',
            'Ataque de diccionario simulado: 5 intentos en 1.8s. Dirección IP bloqueada temporalmente.',
            'IP_BLOCKED'
          );
        } else if (vector === 'bot_honeypot') {
          logEvent(
            'BOT_ANOMALY',
            'HIGH',
            fakeIp,
            '/portal/contacto',
            'SIG-BOT-001',
            'Rastreador automatizado neutralizado: Campo trampa de verificación poblado con valor sintético.',
            'REJECTED'
          );
        } else if (vector === 'xss') {
          logEvent(
            'INJECTION_THREAT',
            'HIGH',
            fakeIp,
            '/portal/comentarios',
            'SIG-XSS-001',
            'Inyección XSS reflejada detectada: [<script>document.cookie</script>]. Sanitización forzada.',
            'BLOCKED'
          );
        }

        return sendJson(res, 200, { success: true, vector, simulatedIp: fakeIp });
      }

      // -----------------------------------------------------------------------
      // GET /api/sessions
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/sessions') {
        const limitParam = parsedUrl.searchParams.get('limit') || '50';
        const offsetParam = parsedUrl.searchParams.get('offset') || '0';
        const limit = Math.min(Math.max(1, parseInt(limitParam, 10) || 50), 500);
        const offset = Math.max(0, parseInt(offsetParam, 10) || 0);

        const sessions = db.getUserSessions(limit, offset);
        return sendJson(res, 200, sessions);
      }

      // -----------------------------------------------------------------------
      // GET /api/sessions/activities
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/sessions/activities') {
        const sessionId = parsedUrl.searchParams.get('sessionId');
        if (!sessionId) {
          return sendError(res, 400, 'sessionId requerido');
        }
        const activities = db.getSessionActivities(sessionId);
        return sendJson(res, 200, activities);
      }

      // -----------------------------------------------------------------------
      // POST /api/sessions/login
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/sessions/login') {
        const data = await parseJsonBody(req, config.MAX_BODY_BYTES);
        const clientIp = getEffectiveClientIp(req, data.ip, auth, config);

        const sessId = db.createSession({
          user_identifier: data.user || 'usuario.anonimo',
          role: data.role || 'USUARIO',
          ip_address: clientIp,
          login_portal: data.portal || '/auth/login',
          user_agent: req.headers['user-agent'] || 'WebClient'
        });
        return sendJson(res, 200, { success: true, sessionId: sessId });
      }

      // -----------------------------------------------------------------------
      // POST /api/sessions/activity
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/sessions/activity') {
        const data = await parseJsonBody(req, config.MAX_BODY_BYTES);
        const riskLevel = (data.riskLevel || 'NORMAL').toUpperCase();

        if (!ALLOWED_RISK_LEVELS.has(riskLevel)) {
          return sendError(res, 400, `Nivel de riesgo inválido. Opciones válidas: ${Array.from(ALLOWED_RISK_LEVELS).join(', ')}`);
        }

        db.recordActivity(
          data.sessionId,
          data.actionType || 'GENERIC_ACTION',
          data.endpoint || '/api',
          data.description || 'Acción ejecutada',
          riskLevel
        );
        return sendJson(res, 200, { success: true });
      }

      // -----------------------------------------------------------------------
      // POST /api/sessions/logout
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/sessions/logout') {
        const data = await parseJsonBody(req, config.MAX_BODY_BYTES);
        const ok = db.closeSession(data.sessionId);
        return sendJson(res, 200, { success: ok });
      }

      // -----------------------------------------------------------------------
      // POST /api/sessions/simulate
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/sessions/simulate') {
        const roles = ['USUARIO_OPERADOR', 'ADMINISTRADOR_PRUEBAS', 'ANALISTA_DEMO'];
        const users = ['usuario_demo_01@test.local', 'operador_prueba@test.local', 'admin_demo@test.local'];
        const portals = ['/portal/login', '/dashboard/panel', '/modulo/formularios'];
        const ips = ['192.168.1.105', '10.0.0.45', '127.0.0.1'];

        const chosenRole = roles[Math.floor(Math.random() * roles.length)];
        const chosenUser = users[Math.floor(Math.random() * users.length)];
        const chosenPortal = portals[Math.floor(Math.random() * portals.length)];
        const chosenIp = ips[Math.floor(Math.random() * ips.length)];

        const sessId = db.createSession({
          user_identifier: chosenUser,
          role: chosenRole,
          ip_address: chosenIp,
          login_portal: chosenPortal,
          user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/127.0.0.0'
        });

        db.recordActivity(sessId, 'CONSULTA_DATOS', chosenPortal, 'Consulta de verificación realizada en el sistema.', 'NORMAL');
        db.recordActivity(sessId, 'ACTUALIZACION_REGISTRO', '/api/registros/save', 'Validación de formulario de prueba completada.', 'NORMAL');

        return sendJson(res, 200, { success: true, sessionId: sessId, user: chosenUser });
      }

      // If no API route matched
      return sendError(res, 404, `Endpoint API ${pathname} no encontrado`);
    } catch (err) {
      const status = err.statusCode || 500;
      return sendError(res, status, err.message);
    }
  };
}

module.exports = { createApiHandler };
