/**
 * WebSentinel-CS :: API Routes Handler
 * Dispatches and processes all /api/* endpoints
 */

const { parseJsonBody } = require('../http/body');
const { sendJson, sendError, sendCsv } = require('../http/respond');
const { inspectPayload } = require('../engine/signatures');
const { auditTargetUrl } = require('../engine/scanner');

function createApiHandler({ db, rateLimiter, stats }) {
  function logEvent(type, severity, sourceIp, target, ruleId, details, action = 'LOGGED') {
    const event = {
      id: 'SEC-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substr(2, 4).toUpperCase(),
      timestamp: new Date().toISOString(),
      type,
      severity,
      sourceIp: sourceIp || '127.0.0.1',
      target: target || '/api',
      ruleId: ruleId || 'RULE-GENERIC',
      details,
      action
    };

    db.insertIncident(event);

    if (severity === 'CRITICAL' || severity === 'HIGH') {
      stats.threatsDetected++;
    }
    return event;
  }

  return async function handleApi(req, res, parsedUrl) {
    const pathname = parsedUrl.pathname;
    const method = req.method;

    try {
      // GET /api/stats
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

      // GET /api/events
      if (method === 'GET' && pathname === '/api/events') {
        const severity = parsedUrl.searchParams.get('severity') || 'ALL';
        const limit = parsedUrl.searchParams.get('limit') || '100';
        const rows = db.getIncidents(limit, severity);
        return sendJson(res, 200, rows);
      }

      // GET /api/sql/summary
      if (method === 'GET' && pathname === '/api/sql/summary') {
        const summary = db.getAnalyticsSummary();
        return sendJson(res, 200, summary);
      }

      // POST /api/sql/query
      if (method === 'POST' && pathname === '/api/sql/query') {
        const body = await parseJsonBody(req);
        const query = body.query || 'SELECT * FROM incidents ORDER BY timestamp DESC LIMIT 10';
        try {
          const rows = db.runReadOnlyQuery(query);
          return sendJson(res, 200, { success: true, count: rows.length, rows });
        } catch (err) {
          return sendJson(res, 400, { success: false, error: err.message });
        }
      }

      // GET /api/export-csv
      if (method === 'GET' && pathname === '/api/export-csv') {
        const rows = db.getIncidents(500, 'ALL');
        let csv = 'ID,TIMESTAMP,SEVERITY,TYPE,RULE_ID,SOURCE_IP,TARGET,ACTION,DETAILS\n';
        for (const ev of rows) {
          const cleanDetails = (ev.details || '').replace(/"/g, '""');
          csv += `"${ev.id}","${ev.timestamp}","${ev.severity}","${ev.type}","${ev.rule_id}","${ev.source_ip}","${ev.target}","${ev.action}","${cleanDetails}"\n`;
        }
        return sendCsv(res, 'websentinel-audit-events.csv', csv);
      }

      // POST /api/scan
      if (method === 'POST' && pathname === '/api/scan') {
        const body = await parseJsonBody(req);
        if (!body.url) {
          return sendError(res, 400, 'Parámetro URL requerido');
        }

        stats.totalScans++;
        const audit = await auditTargetUrl(body.url);

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
        }

        db.saveScanResult(audit);
        return sendJson(res, 200, audit);
      }

      // POST /api/analyze-request
      if (method === 'POST' && pathname === '/api/analyze-request') {
        const data = await parseJsonBody(req);
        stats.inspectionsRun++;
        const input = data.input || '';
        const honeypot = data.honeypot || '';
        const clientIp = data.clientIp || req.socket.remoteAddress || '127.0.0.1';
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

      // POST /api/record-login
      if (method === 'POST' && pathname === '/api/record-login') {
        const data = await parseJsonBody(req);
        const clientIp = data.clientIp || req.socket.remoteAddress || '127.0.0.1';
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

      // POST /api/simulate-attack
      if (method === 'POST' && pathname === '/api/simulate-attack') {
        const data = await parseJsonBody(req);
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

      // GET /api/sessions
      if (method === 'GET' && pathname === '/api/sessions') {
        const limit = parsedUrl.searchParams.get('limit') || '50';
        const sessions = db.getUserSessions(limit);
        return sendJson(res, 200, sessions);
      }

      // GET /api/sessions/activities
      if (method === 'GET' && pathname === '/api/sessions/activities') {
        const sessionId = parsedUrl.searchParams.get('sessionId');
        if (!sessionId) {
          return sendError(res, 400, 'sessionId requerido');
        }
        const activities = db.getSessionActivities(sessionId);
        return sendJson(res, 200, activities);
      }

      // POST /api/sessions/login
      if (method === 'POST' && pathname === '/api/sessions/login') {
        const data = await parseJsonBody(req);
        const sessId = db.createSession({
          user_identifier: data.user || 'usuario.anonimo',
          role: data.role || 'USUARIO',
          ip_address: data.ip || req.socket.remoteAddress || '127.0.0.1',
          login_portal: data.portal || '/auth/login',
          user_agent: req.headers['user-agent'] || 'WebClient'
        });
        return sendJson(res, 200, { success: true, sessionId: sessId });
      }

      // POST /api/sessions/activity
      if (method === 'POST' && pathname === '/api/sessions/activity') {
        const data = await parseJsonBody(req);
        db.recordActivity(
          data.sessionId,
          data.actionType || 'GENERIC_ACTION',
          data.endpoint || '/api',
          data.description || 'Acción ejecutada',
          data.riskLevel || 'NORMAL'
        );
        return sendJson(res, 200, { success: true });
      }

      // POST /api/sessions/logout
      if (method === 'POST' && pathname === '/api/sessions/logout') {
        const data = await parseJsonBody(req);
        const ok = db.closeSession(data.sessionId);
        return sendJson(res, 200, { success: ok });
      }

      // POST /api/sessions/simulate
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
