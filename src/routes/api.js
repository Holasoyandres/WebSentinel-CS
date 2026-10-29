/**
 * WebSentinel-CS :: API Routes Handler (Hardenized P1.2 & FASE 2 Architecture)
 * Dispatches and processes all /api/* endpoints with RBAC, CSRF, Permissions Matrix,
 * Brute-Force Throttling, Persistent IP Reputation, and Cryptographic Audit Verification.
 */

const crypto = require('node:crypto');
const { parseJsonBody } = require('../http/body');
const { sendJson, sendError, sendCsv } = require('../http/respond');
const { inspectPayload } = require('../engine/signatures');
const { auditTargetUrl } = require('../engine/scanner');
const { authenticateRequest, verifyScryptPassword, parseCookies } = require('../http/auth');
const { verifyAuthorization } = require('../http/permissions');
const { sanitizeAndValidateQuery, executeQueryWithWorker } = require('../engine/sql-runner');

const ALLOWED_SEVERITY = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
const ALLOWED_ACTIONS = new Set(['BLOCKED', 'FLAGGED', 'CHALLENGED', 'MONITORED', 'PASSED', 'LOGGED', 'AUDITED', 'DROPPED', 'IP_BLOCKED', 'REJECTED', 'AUTHORIZED']);
const ALLOWED_RISK_LEVELS = new Set(['CRITICAL', 'HIGH', 'ELEVATED', 'MEDIUM', 'LOW', 'NORMAL']);

const DUMMY_SALT = '00000000000000000000000000000000';
const DUMMY_HASH = '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';

function getEffectiveClientIp(req, bodyIp, auth, config) {
  // Only trust declared body IP if authenticated via API Key with 'ingest' scope
  if (auth && auth.type === 'api_key' && auth.scopes && auth.scopes.includes('ingest') && bodyIp) {
    return String(bodyIp).trim();
  }
  if (config.TRUST_PROXIES || process.env.TRUST_PROXIES === 'true') {
    const xff = req.headers['x-forwarded-for'];
    if (xff && typeof xff === 'string') {
      const parts = xff.split(',').map(s => s.trim()).filter(Boolean);
      if (parts.length > 0) {
        return parts[parts.length - 1];
      }
    }
  }
  return req.socket.remoteAddress || '127.0.0.1';
}

function sanitizeCsvCell(val) {
  if (val === null || val === undefined) return '';
  let str = String(val);
  // Prepend single quote if cell starts with formula trigger (=, +, -, @, \t, \r)
  if (/^[=+\-@\t\r]/.test(str)) {
    str = "'" + str;
  }
  return str.replace(/"/g, '""');
}

function createApiHandler({ config, db, rateLimiter, stats }) {
  const activeSqlQueriesByUser = new Set();
  const sseClients = new Set();

  // Heartbeat ping every 15s to keep connections alive through proxies
  const ssePingInterval = setInterval(() => {
    if (sseClients.size === 0) return;
    for (const client of sseClients) {
      try {
        client.write(': ping\n\n');
      } catch (_) {
        sseClients.delete(client);
      }
    }
  }, 15000);
  if (ssePingInterval.unref) ssePingInterval.unref();

  function logEvent(type, severity, sourceIp, target, ruleId, details, action = 'LOGGED', isSimulated = false) {
    const sev = ALLOWED_SEVERITY.has(severity) ? severity : 'INFO';
    const act = ALLOWED_ACTIONS.has(action) ? action : 'LOGGED';

    const event = {
      id: 'SEC-' + crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      type,
      severity: sev,
      sourceIp: sourceIp || '127.0.0.1',
      target: target || '/api',
      ruleId: ruleId || 'RULE-GENERIC',
      details,
      action: act,
      isSimulated: Boolean(isSimulated)
    };

    db.insertIncident(event);

    if (!isSimulated && (sev === 'CRITICAL' || sev === 'HIGH')) {
      stats.threatsDetected++;
    }

    // Broadcast in real-time to active SSE clients
    if (sseClients.size > 0) {
      const sseMsg = `event: incident\ndata: ${JSON.stringify(event)}\n\n`;
      for (const client of sseClients) {
        try {
          client.write(sseMsg);
        } catch (_) {
          sseClients.delete(client);
        }
      }
    }

    return event;
  }

  return async function handleApi(req, res, parsedUrl) {
    const pathname = parsedUrl.pathname;
    const method = req.method;

    try {
      // -----------------------------------------------------------------------
      // Public Route: /healthz (Real Database SELECT 1 Verification)
      // -----------------------------------------------------------------------
      if (pathname === '/healthz') {
        try {
          db.raw.prepare('SELECT 1 as ok').get();
          return sendJson(res, 200, {
            status: 'UP',
            database: 'OK',
            version: config.VERSION,
            engine: 'ACTIVE_ARMED',
            uptime: Math.floor((Date.now() - stats.startTime) / 1000),
            timestamp: new Date().toISOString()
          });
        } catch (err) {
          return sendJson(res, 503, {
            status: 'DOWN',
            database: 'ERROR',
            error: err.message,
            timestamp: new Date().toISOString()
          });
        }
      }

      // -----------------------------------------------------------------------
      // Public Route: /readyz
      // -----------------------------------------------------------------------
      if (pathname === '/readyz') {
        try {
          db.raw.prepare('SELECT 1 as ok').get();
          return sendJson(res, 200, { ready: true });
        } catch (err) {
          return sendJson(res, 503, { ready: false, error: err.message });
        }
      }

      // -----------------------------------------------------------------------
      // Public Route: POST /api/auth/login (Brute-Force & Timing Hardened)
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/auth/login') {
        const body = await parseJsonBody(req, config.MAX_BODY_BYTES);
        const { username, password } = body;

        // Strict Type and Bounds Validation
        if (typeof username !== 'string' || typeof password !== 'string') {
          return sendError(res, 400, 'Los campos de usuario y contraseña deben ser cadenas de texto');
        }

        const cleanUsername = username.trim();
        if (cleanUsername.length < 1 || cleanUsername.length > 64 || password.length < 1 || password.length > 128) {
          return sendError(res, 400, 'Longitud de credenciales fuera de rango permitido');
        }

        // Client IP extraction (respecting TRUST_PROXIES)
        let clientIp = req.socket.remoteAddress || '127.0.0.1';
        if (config.TRUST_PROXIES || process.env.TRUST_PROXIES === 'true') {
          const xff = req.headers['x-forwarded-for'];
          if (xff && typeof xff === 'string') {
            const parts = xff.split(',').map(s => s.trim()).filter(Boolean);
            if (parts.length > 0) {
              clientIp = parts[parts.length - 1];
            }
          }
        }

        const ipKey = `ip:${clientIp}`;
        const userKey = `user:${cleanUsername.toLowerCase()}`;

        // Hard Rate Limiting ONLY by IP (prevents user lockout DoS)
        const ipLimit = db.checkLoginRateLimit(ipKey);
        if (ipLimit.isLocked) {
          db.incrementBlockedAttempts(ipKey);
          res.setHeader('Retry-After', String(ipLimit.retryAfterSec));
          return sendError(res, 429, 'Demasiados intentos fallidos de autenticación desde esta IP. Intente más tarde.');
        }

        // Progressive Delay by Username (prevents brute force while never completely locking legitimate user)
        const userFailures = db.getUserLoginFailures(userKey);
        if (userFailures > 0) {
          const baseUnit = (config.ENV === 'test' || process.env.NODE_ENV === 'test') ? 20 : 1000;
          const delayMs = Math.min(30000, Math.pow(2, Math.min(userFailures - 1, 5)) * baseUnit);
          await new Promise(r => setTimeout(r, delayMs));
        }

        // Timing Attack Mitigation: Equalize CPU work with dummy scrypt
        const user = db.findUserByUsername(cleanUsername);
        let isValid = false;

        if (!user) {
          verifyScryptPassword(password, DUMMY_SALT, DUMMY_HASH);
        } else {
          isValid = verifyScryptPassword(password, user.salt, user.password_hash);
        }

        if (!isValid) {
          const ipFail = db.recordLoginFailure(ipKey, 5, 15);
          db.recordLoginFailure(userKey, 999999, 0); // Increment progressive user failure counter without hard lock

          if (ipFail.shouldAlert) {
            logEvent(
              'AUTH_BRUTEFORCE',
              'CRITICAL',
              clientIp,
              '/api/auth/login',
              'RULE-RATE-001',
              `Umbral de 5 fallos alcanzado para IP '${clientIp}'. Enfriamiento forzado por 15 minutos.`,
              'IP_BLOCKED'
            );
          }

          if (ipFail.isLocked && ipFail.failures > 5) {
            res.setHeader('Retry-After', String(ipFail.retryAfterSec));
            return sendError(res, 429, 'Demasiados intentos fallidos de autenticación desde esta IP. Intente más tarde.');
          }

          return sendError(res, 401, 'Credenciales de acceso no válidas');
        }

        // Successful Authentication: Reset Rate Limits
        db.resetLoginRateLimit(ipKey);
        db.resetLoginRateLimit(userKey);

        const session = db.createAuthSession(user.id, 8);
        if (!session) {
          return sendError(res, 500, 'No fue posible inicializar la sesión de analista');
        }

        db.insertAuditLog({
          action: 'LOGIN',
          userId: user.id,
          ip: clientIp,
          details: 'Inicio de sesión exitoso en el panel'
        });

        const isTls = Boolean(req.socket.encrypted);
        const isProxyHttps = (config.TRUST_PROXIES || process.env.TRUST_PROXIES === 'true') && req.headers['x-forwarded-proto'] === 'https';
        const isSecure = config.ENV === 'production' && (isTls || isProxyHttps);
        const cookieHeader = `sentinel_session=${session.rawToken}; Path=/; HttpOnly; SameSite=Strict${isSecure ? '; Secure' : ''}`;

        return sendJson(res, 200, {
          success: true,
          user: { id: user.id, username: user.username, role: user.role },
          csrfToken: session.csrfToken
        }, { 'Set-Cookie': cookieHeader });
      }

      // -----------------------------------------------------------------------
      // Centralized Authentication Check for All Protected /api/* Endpoints
      // -----------------------------------------------------------------------
      const auth = authenticateRequest(req, db, pathname);
      if (!auth.authenticated) {
        return sendError(res, auth.statusCode || 401, auth.message || 'No autorizado');
      }
      req.auth = auth;

      // -----------------------------------------------------------------------
      // Centralized Permissions Matrix Enforcement (FASE 1.1)
      // -----------------------------------------------------------------------
      const authCheck = verifyAuthorization(auth, pathname, method);
      if (!authCheck.allowed) {
        return sendError(res, authCheck.statusCode || 403, authCheck.message);
      }

      // -----------------------------------------------------------------------
      // Test Trigger Route: 500 Error Masking Verification
      // -----------------------------------------------------------------------
      if (pathname === '/api/test-500-trigger') {
        throw new Error('Triggered deliberate internal exception for testing 500 response handling');
      }

      // -----------------------------------------------------------------------
      // Auth Route: GET /api/auth/me
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/auth/me') {
        return sendJson(res, 200, {
          authenticated: true,
          type: auth.type,
          user: auth.user || null,
          scopes: auth.scopes || null,
          demoMode: Boolean(config.DEMO_MODE)
        });
      }

      // -----------------------------------------------------------------------
      // Auth Route: POST /api/auth/logout
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/auth/logout') {
        if (auth.session) {
          db.revokeAuthSession(auth.session.rawToken || auth.session.token_hash);
        }
        const userId = (auth.user && auth.user.id) || 'usr-anonymous';
        const clientIp = req.socket.remoteAddress || '127.0.0.1';
        db.insertAuditLog({
          action: 'LOGOUT',
          userId,
          ip: clientIp,
          details: 'Cierre voluntario de sesión de panel'
        });

        const cookieHeader = 'sentinel_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0';
        return sendJson(res, 200, { success: true }, { 'Set-Cookie': cookieHeader });
      }

      // -----------------------------------------------------------------------
      // GET /api/stats (Database-Backed Persistent Telemetry)
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/stats') {
        const summary = db.getAnalyticsSummary(false);
        return sendJson(res, 200, {
          totalScans: summary.totalScans,
          threatsDetected: summary.threatsDetected,
          bruteForceBlocked: summary.bruteForceBlocked,
          inspectionsRun: summary.inspectionsRun,
          uptimeSeconds: Math.floor((Date.now() - stats.startTime) / 1000),
          totalPersistedIncidents: summary.totalIncidents,
          criticalCount: summary.criticalCount,
          highCount: summary.highCount,
          engineStatus: 'ACTIVE_ARMED',
          storageEngine: 'SQLITE_PERSISTENT'
        });
      }

      // -----------------------------------------------------------------------
      // GET /api/events (Search, Pagination, Date Filtering & Segregation)
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/events') {
        const severity = parsedUrl.searchParams.get('severity') || 'ALL';
        const limitParam = parsedUrl.searchParams.get('limit') || '100';
        const offsetParam = parsedUrl.searchParams.get('offset') || '0';
        const includeSimulated = parsedUrl.searchParams.get('includeSimulated') === 'true';
        const from = parsedUrl.searchParams.get('from');
        const to = parsedUrl.searchParams.get('to');
        const search = parsedUrl.searchParams.get('search');

        const limit = Math.min(Math.max(1, parseInt(limitParam, 10) || 100), 500);
        const offset = Math.max(0, parseInt(offsetParam, 10) || 0);

        const rows = db.getIncidents({ limit, severity, offset, includeSimulated, from, to, search });
        const total = db.getIncidentsCount ? db.getIncidentsCount(severity, includeSimulated, from, to, search) : rows.length;

        res.setHeader('X-Total-Count', String(total));
        return sendJson(res, 200, rows);
      }

      // -----------------------------------------------------------------------
      // Real-Time SSE Stream: GET /api/v1/stream
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/v1/stream') {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache, no-transform',
          'Connection': 'keep-alive',
          'X-Accel-Buffering': 'no',
          'Access-Control-Allow-Origin': req.headers.origin || '*'
        });

        res.write(`event: connected\ndata: ${JSON.stringify({ time: new Date().toISOString(), status: 'STREAM_CONNECTED' })}\n\n`);

        sseClients.add(res);
        req.on('close', () => {
          sseClients.delete(res);
        });
        return;
      }

      // -----------------------------------------------------------------------
      // GET /api/sql/summary
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/sql/summary') {
        const summary = db.getAnalyticsSummary(false);
        return sendJson(res, 200, summary);
      }

      // -----------------------------------------------------------------------
      // POST /api/sql/query (Hardened SQL Forensics Console with Concurrency Cap)
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/sql/query') {
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

        const userId = (auth.user && auth.user.id) || 'usr-admin';
        if (activeSqlQueriesByUser.has(userId)) {
          return sendError(res, 429, 'Ya existe una consulta SQL concurrente en ejecución para este usuario');
        }
        activeSqlQueriesByUser.add(userId);

        try {
          const startTime = Date.now();
          const execResult = await executeQueryWithWorker(config.DB_PATH, cleanQuery, db, 3000);
          const durationMs = Date.now() - startTime;

          const rowsCount = execResult.rows ? execResult.rows.length : 0;

          db.insertAuditLog({
            action: 'SQL_QUERY',
            userId,
            ip: req.socket.remoteAddress || '127.0.0.1',
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
        } finally {
          activeSqlQueriesByUser.delete(userId);
        }
      }

      // -----------------------------------------------------------------------
      // GET /api/export-csv (Formula Injection Sanitized & Date Filtered)
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/export-csv') {
        const includeSimulated = parsedUrl.searchParams.get('includeSimulated') === 'true';
        const from = parsedUrl.searchParams.get('from');
        const to = parsedUrl.searchParams.get('to');
        const severity = parsedUrl.searchParams.get('severity') || 'ALL';
        const search = parsedUrl.searchParams.get('search');

        const rows = db.getIncidents({ limit: 5000, severity, offset: 0, includeSimulated, from, to, search });

        const userId = (auth.user && auth.user.id) || 'usr-analyst';
        const clientIp = req.socket.remoteAddress || '127.0.0.1';
        db.insertAuditLog({
          action: 'EXPORT_CSV',
          userId,
          ip: clientIp,
          details: `Exportación de ${rows.length} eventos (includeSimulated=${includeSimulated}, from=${from || '*'}, to=${to || '*'})`,
          rowsReturned: rows.length
        });

        let csv = 'ID,TIMESTAMP,SEVERITY,TYPE,RULE_ID,SOURCE_IP,TARGET,ACTION,IS_SIMULATED,DETAILS\n';
        for (const ev of rows) {
          csv += `"${sanitizeCsvCell(ev.id)}","${sanitizeCsvCell(ev.timestamp)}","${sanitizeCsvCell(ev.severity)}","${sanitizeCsvCell(ev.type)}","${sanitizeCsvCell(ev.rule_id)}","${sanitizeCsvCell(ev.source_ip)}","${sanitizeCsvCell(ev.target)}","${sanitizeCsvCell(ev.action)}",${ev.is_simulated || 0},"${sanitizeCsvCell(ev.details)}"\n`;
        }
        return sendCsv(res, 'websentinel-audit-events.csv', csv);
      }

      // -----------------------------------------------------------------------
      // POST /api/scan (SSRF-Protected URL Auditor with CIDR & DNS Pinning)
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/scan') {
        const body = await parseJsonBody(req, config.MAX_BODY_BYTES);
        if (!body.url) {
          return sendError(res, 400, 'Parámetro URL requerido');
        }

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
      // POST /api/analyze-request (WAF Anomaly Scoring & Inspection)
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/analyze-request') {
        const data = await parseJsonBody(req, config.MAX_BODY_BYTES);
        const input = data.input || '';
        const honeypot = data.honeypot || '';
        const clientIp = getEffectiveClientIp(req, data.clientIp, auth, config);
        const target = data.targetEndpoint || '/api/v1/resource';

        const threshold = config.ANOMALY_THRESHOLD || 5;
        const inspection = inspectPayload(input, honeypot, threshold);

        let recordedIncidentId = null;

        if (inspection.action === 'BLOCK') {
          db.incrementDailyInspection(true);
          for (const t of inspection.triggeredRules) {
            const ev = logEvent(
              'INJECTION_THREAT',
              t.severity,
              clientIp,
              target,
              t.id,
              `${t.name} (${t.cwe}). Muestra: "${String(input).substring(0, 48)}"`,
              'BLOCKED'
            );
            if (!recordedIncidentId) recordedIncidentId = ev.id;
          }
        } else if (inspection.action === 'FLAG') {
          db.incrementDailyInspection(true);
          for (const t of inspection.triggeredRules) {
            const ev = logEvent(
              'SUSPICIOUS_PAYLOAD',
              t.severity,
              clientIp,
              target,
              t.id,
              `Anomalía sospechosa detectada: ${t.name} (${t.cwe}). Puntaje: ${t.score}/${threshold}`,
              'FLAGGED'
            );
            if (!recordedIncidentId) recordedIncidentId = ev.id;
          }
        } else {
          db.incrementDailyInspection(false);
          if (config.STORE_PASSED_EVENTS) {
            const ev = logEvent(
              'PAYLOAD_INSPECTED',
              'INFO',
              clientIp,
              target,
              'RULE-WAF-CLEAN',
              'Comprobación de integridad exitosa. Sin patrones maliciosos conocidos.',
              'PASSED'
            );
            recordedIncidentId = ev.id;
          }
        }

        return sendJson(res, 200, {
          safe: inspection.safe,
          action: inspection.action,
          status: inspection.status,
          scoreTotal: inspection.scoreTotal,
          threshold: inspection.threshold,
          threatCount: inspection.threatCount,
          threats: inspection.threats,
          triggeredRules: inspection.triggeredRules,
          incidentId: recordedIncidentId
        });
      }

      // -----------------------------------------------------------------------
      // POST /api/v1/events (Dedicated Ingestion Endpoint for Pre-Analyzed Events)
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/v1/events') {
        const body = await parseJsonBody(req, config.MAX_BODY_BYTES);

        const { type, severity, ruleId, sourceIp, target, details, action, isSimulated } = body;

        // Strict Schema & Type Validation
        if (
          typeof type !== 'string' ||
          typeof severity !== 'string' ||
          typeof ruleId !== 'string' ||
          typeof sourceIp !== 'string' ||
          typeof target !== 'string' ||
          typeof details !== 'string' ||
          typeof action !== 'string'
        ) {
          return sendError(res, 400, 'Esquema de evento inválido: todos los campos obligatorios deben ser cadenas de texto');
        }

        const cleanType = type.trim();
        const cleanSev = severity.toUpperCase().trim();
        const cleanRuleId = ruleId.trim();
        const cleanSourceIp = sourceIp.trim();
        const cleanTarget = target.trim();
        const cleanDetails = details.trim();
        const cleanAction = action.toUpperCase().trim();

        if (
          cleanType.length < 1 || cleanType.length > 64 ||
          cleanRuleId.length < 1 || cleanRuleId.length > 64 ||
          cleanSourceIp.length < 1 || cleanSourceIp.length > 64 ||
          cleanTarget.length < 1 || cleanTarget.length > 255 ||
          cleanDetails.length < 1 || cleanDetails.length > 65535
        ) {
          return sendError(res, 400, 'Longitud de campos de evento fuera del rango permitido');
        }

        if (!ALLOWED_SEVERITY.has(cleanSev)) {
          return sendError(res, 400, `Nivel de severidad inválido: "${cleanSev}". Valores permitidos: ${Array.from(ALLOWED_SEVERITY).join(', ')}`);
        }

        if (!ALLOWED_ACTIONS.has(cleanAction)) {
          return sendError(res, 400, `Acción inválida: "${cleanAction}". Valores permitidos: ${Array.from(ALLOWED_ACTIONS).join(', ')}`);
        }

        const event = {
          id: 'SEC-' + crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          type: cleanType,
          severity: cleanSev,
          sourceIp: cleanSourceIp,
          target: cleanTarget,
          ruleId: cleanRuleId,
          details: cleanDetails,
          action: cleanAction,
          isSimulated: Boolean(isSimulated)
        };

        db.insertIncident(event);

        if (!event.isSimulated && (cleanSev === 'CRITICAL' || cleanSev === 'HIGH')) {
          stats.threatsDetected++;
        }

        return sendJson(res, 201, {
          success: true,
          eventId: event.id
        });
      }

      // -----------------------------------------------------------------------
      // POST /api/record-login (Persistent Telemetry Rate Limiter in ip_reputation)
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/record-login') {
        const data = await parseJsonBody(req, config.MAX_BODY_BYTES);
        const clientIp = getEffectiveClientIp(req, data.clientIp, auth, config);
        const identifier = data.identifier || data.email || 'anonymous';
        const isSuccess = Boolean(data.success);

        const rep = db.recordIpAttempt(clientIp, isSuccess, 5, 15);

        if (rep.isBlocked) {
          logEvent(
            'AUTH_BRUTEFORCE_MITIGATED',
            'CRITICAL',
            clientIp,
            '/auth/login',
            'RULE-RATE-001',
            `Límite de tasa excedido en telemetría para ${clientIp}. Bloqueo persistente activo en ip_reputation.`,
            'IP_BLOCKED'
          );
        } else if (!isSuccess) {
          logEvent(
            'AUTH_FAILURE',
            rep.failedAttempts >= 3 ? 'HIGH' : 'LOW',
            clientIp,
            '/auth/login',
            'RULE-AUTH-002',
            `Intento de autenticación fallido para identidad "${identifier}". Conteo acumulado: ${rep.failedAttempts}/5.`,
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
          status: rep.isBlocked ? 'BLOCKED' : (isSuccess ? 'AUTHORIZED' : 'DENIED'),
          rate: {
            isBlocked: rep.isBlocked,
            recentFailures: rep.failedAttempts,
            threshold: 5,
            retryAfterSec: rep.isBlocked ? 900 : 0
          }
        });
      }

      // -----------------------------------------------------------------------
      // GET /api/v1/ip/:ip/status (Persistent IP Reputation Query)
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname.startsWith('/api/v1/ip/') && pathname.endsWith('/status')) {
        const parts = pathname.split('/');
        const targetIp = parts[4];
        if (!targetIp) {
          return sendError(res, 400, 'Dirección IP requerida');
        }
        const rep = db.getIpReputation(targetIp);
        return sendJson(res, 200, rep);
      }

      // -----------------------------------------------------------------------
      // GET /api/v1/integrity/verify (Cryptographic SHA-256 Chain Verification)
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/v1/integrity/verify') {
        const userRole = (auth.user && auth.user.role) || auth.role;
        if (userRole !== 'admin') {
          return sendError(res, 403, 'Acceso denegado: La verificación de integridad requiere privilegios de administrador');
        }

        const report = db.verifyIncidentLogIntegrity();
        return sendJson(res, 200, report);
      }

      // -----------------------------------------------------------------------
      // Admin: GET /api/v1/admin/api-keys
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/v1/admin/api-keys') {
        const userRole = (auth.user && auth.user.role) || auth.role;
        if (userRole !== 'admin') {
          return sendError(res, 403, 'Acceso denegado: Requiere rol de administrador');
        }
        const keys = db.getAllApiKeys();
        return sendJson(res, 200, keys);
      }

      // -----------------------------------------------------------------------
      // Admin: POST /api/v1/admin/api-keys
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/v1/admin/api-keys') {
        const userRole = (auth.user && auth.user.role) || auth.role;
        if (userRole !== 'admin') {
          return sendError(res, 403, 'Acceso denegado: Requiere rol de administrador');
        }

        const body = await parseJsonBody(req, config.MAX_BODY_BYTES);
        const name = (body.name || '').trim();
        const scopes = (body.scopes || 'read').trim();

        if (!name || name.length > 64) {
          return sendError(res, 400, 'El nombre de la clave es obligatorio (máximo 64 caracteres)');
        }

        const rawKey = 'ws_live_' + crypto.randomBytes(16).toString('hex');
        const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
        const id = 'key-' + crypto.randomUUID();

        db.createApiKey(id, name, keyHash, scopes);

        db.insertAuditLog({
          action: 'CREATE_API_KEY',
          userId: auth.user ? auth.user.id : 'usr-admin',
          ip: req.socket.remoteAddress || '127.0.0.1',
          details: `Creación de API key "${name}" con scopes [${scopes}]`
        });

        return sendJson(res, 201, {
          success: true,
          id,
          name,
          scopes,
          key: rawKey
        });
      }

      // -----------------------------------------------------------------------
      // Admin: DELETE /api/v1/admin/api-keys/:id
      // -----------------------------------------------------------------------
      if (method === 'DELETE' && pathname.startsWith('/api/v1/admin/api-keys/')) {
        const userRole = (auth.user && auth.user.role) || auth.role;
        if (userRole !== 'admin') {
          return sendError(res, 403, 'Acceso denegado: Requiere rol de administrador');
        }

        const keyId = pathname.substring('/api/v1/admin/api-keys/'.length);
        db.deleteApiKey(keyId);

        db.insertAuditLog({
          action: 'REVOKE_API_KEY',
          userId: auth.user ? auth.user.id : 'usr-admin',
          ip: req.socket.remoteAddress || '127.0.0.1',
          details: `Revocación de API key ${keyId}`
        });

        return sendJson(res, 200, { success: true });
      }

      // -----------------------------------------------------------------------
      // Admin: GET /api/v1/admin/blocked-ips
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/v1/admin/blocked-ips') {
        const userRole = (auth.user && auth.user.role) || auth.role;
        if (userRole !== 'admin') {
          return sendError(res, 403, 'Acceso denegado: Requiere rol de administrador');
        }

        const blocked = db.getBlockedIps();
        return sendJson(res, 200, blocked);
      }

      // -----------------------------------------------------------------------
      // Admin: POST /api/v1/admin/unblock-ip
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/v1/admin/unblock-ip') {
        const userRole = (auth.user && auth.user.role) || auth.role;
        if (userRole !== 'admin') {
          return sendError(res, 403, 'Acceso denegado: Requiere rol de administrador');
        }

        const body = await parseJsonBody(req, config.MAX_BODY_BYTES);
        const ip = (body.ip || '').trim();
        if (!ip) {
          return sendError(res, 400, 'Dirección IP requerida');
        }

        db.unblockIp(ip);

        db.insertAuditLog({
          action: 'UNBLOCK_IP',
          userId: auth.user ? auth.user.id : 'usr-admin',
          ip: req.socket.remoteAddress || '127.0.0.1',
          details: `Desbloqueo manual de IP ${ip}`
        });

        return sendJson(res, 200, { success: true, ip });
      }

      // -----------------------------------------------------------------------
      // POST /api/simulate-attack (DEMO_MODE Gated, Tagged as is_simulated=1)
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/simulate-attack') {
        if (!config.DEMO_MODE) {
          return sendError(res, 404, 'Endpoint no disponible: DEMO_MODE está desactivado en la configuración');
        }

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
            'BLOCKED',
            true
          );
        } else if (vector === 'bruteforce') {
          for (let i = 0; i < 5; i++) {
            db.recordIpAttempt(fakeIp, false, 5, 15);
          }
          logEvent(
            'AUTH_BRUTEFORCE_MITIGATED',
            'CRITICAL',
            fakeIp,
            '/auth/admin',
            'SIG-RATE-001',
            'Ataque de diccionario simulado: 5 intentos en 1.8s. Dirección IP bloqueada temporalmente.',
            'IP_BLOCKED',
            true
          );
        } else if (vector === 'bot_honeypot') {
          logEvent(
            'BOT_ANOMALY',
            'HIGH',
            fakeIp,
            '/portal/contacto',
            'SIG-BOT-001',
            'Rastreador automatizado neutralizado: Campo trampa de verificación poblado con valor sintético.',
            'REJECTED',
            true
          );
        } else if (vector === 'xss') {
          logEvent(
            'INJECTION_THREAT',
            'HIGH',
            fakeIp,
            '/portal/comentarios',
            'SIG-XSS-001',
            'Inyección XSS reflejada detectada: [<script>document.cookie</script>]. Sanitización forzada.',
            'BLOCKED',
            true
          );
        }

        return sendJson(res, 200, { success: true, vector, simulatedIp: fakeIp });
      }

      // -----------------------------------------------------------------------
      // GET /api/sessions (Segregates Simulated Data by Default)
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/sessions') {
        const limitParam = parsedUrl.searchParams.get('limit') || '50';
        const offsetParam = parsedUrl.searchParams.get('offset') || '0';
        const includeSimulated = parsedUrl.searchParams.get('includeSimulated') === 'true';

        const limit = Math.min(Math.max(1, parseInt(limitParam, 10) || 50), 500);
        const offset = Math.max(0, parseInt(offsetParam, 10) || 0);

        const sessions = db.getUserSessions(limit, offset, includeSimulated);
        return sendJson(res, 200, sessions);
      }

      // -----------------------------------------------------------------------
      // GET /api/sessions/activities
      // -----------------------------------------------------------------------
      if (method === 'GET' && pathname === '/api/sessions/activities') {
        const sessionId = parsedUrl.searchParams.get('sessionId');
        if (!sessionId || typeof sessionId !== 'string' || !sessionId.trim()) {
          return sendError(res, 400, 'sessionId requerido y debe ser una cadena válida');
        }
        if (!db.sessionExists(sessionId)) {
          return sendError(res, 404, 'Sesión no encontrada');
        }

        const userId = (auth.user && auth.user.id) || 'usr-analyst';
        db.insertAuditLog({
          action: 'VIEW_SESSION',
          userId,
          ip: req.socket.remoteAddress || '127.0.0.1',
          details: `Inspección de actividades para la sesión ${sessionId}`
        });

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
        if (!sessId) {
          return sendError(res, 500, 'Error al inicializar la sesión');
        }
        return sendJson(res, 200, { success: true, sessionId: sessId });
      }

      // -----------------------------------------------------------------------
      // POST /api/sessions/activity
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/sessions/activity') {
        const data = await parseJsonBody(req, config.MAX_BODY_BYTES);
        if (!data || typeof data.sessionId !== 'string' || !data.sessionId.trim()) {
          return sendError(res, 400, 'sessionId requerido y debe ser una cadena de texto no vacía');
        }

        const riskLevel = (data.riskLevel || 'NORMAL').toUpperCase();
        if (!ALLOWED_RISK_LEVELS.has(riskLevel)) {
          return sendError(res, 400, `Nivel de riesgo inválido. Opciones válidas: ${Array.from(ALLOWED_RISK_LEVELS).join(', ')}`);
        }

        if (data.actionType && typeof data.actionType !== 'string') {
          return sendError(res, 400, 'actionType debe ser una cadena de texto');
        }
        if (data.endpoint && typeof data.endpoint !== 'string') {
          return sendError(res, 400, 'endpoint debe ser una cadena de texto');
        }

        if (!db.sessionExists(data.sessionId)) {
          return sendError(res, 404, 'Sesión no encontrada');
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
        if (!data || typeof data.sessionId !== 'string' || !data.sessionId.trim()) {
          return sendError(res, 400, 'sessionId requerido y debe ser una cadena de texto no vacía');
        }
        const ok = db.closeSession(data.sessionId);
        if (!ok) {
          return sendError(res, 404, 'Sesión no encontrada o ya cerrada');
        }
        return sendJson(res, 200, { success: true });
      }

      // -----------------------------------------------------------------------
      // POST /api/sessions/simulate (DEMO_MODE Gated, Tagged as is_simulated=1)
      // -----------------------------------------------------------------------
      if (method === 'POST' && pathname === '/api/sessions/simulate') {
        if (!config.DEMO_MODE) {
          return sendError(res, 404, 'Endpoint no disponible: DEMO_MODE está desactivado en la configuración');
        }

        const roles = ['USUARIO_OPERADOR', 'ADMINISTRADOR_PRUEBAS', 'ANALISTA_DEMO'];
        const users = ['usuario_demo_01@test.local', 'operador_prueba@test.local', 'admin_demo@test.local'];
        const portals = ['/portal/login', '/dashboard/panel', '/modulo/formularios'];
        const ips = ['198.51.100.105', '198.51.100.45', '198.51.100.22'];

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
        }, true);

        db.recordActivity(sessId, 'CONSULTA_DATOS', chosenPortal, 'Consulta de verificación realizada en el sistema.', 'NORMAL', true);
        db.recordActivity(sessId, 'ACTUALIZACION_REGISTRO', '/api/registros/save', 'Validación de formulario de prueba completada.', 'NORMAL', true);

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
