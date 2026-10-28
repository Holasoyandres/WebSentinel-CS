/**
 * WebSentinel-CS :: Enterprise Security Engine with Persistent SQLite Storage
 * Architecture: Standalone Out-of-Band Security Sentinel
 * Author: Holasoyandres (MIT License)
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');
const storage = require('./database');

const PORT = process.env.PORT || 4000;
const PUBLIC_DIR = path.join(__dirname, 'public');

// State Cache
const ipAttempts = new Map();
const stats = {
  totalScans: 0,
  threatsDetected: 0,
  bruteForceBlocked: 0,
  inspectionsRun: 0,
  startTime: Date.now()
};

function logEvent(type, severity, sourceIp, target, ruleId, details, action = 'LOGGED') {
  const event = {
    id: 'SEC-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substr(2, 4).toUpperCase(),
    timestamp: new Date().toISOString(),
    type,
    severity, // 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    sourceIp: sourceIp || '127.0.0.1',
    target: target || '/api',
    ruleId: ruleId || 'RULE-GENERIC',
    details,
    action
  };

  // Persist to native SQLite
  storage.insertIncident(event);

  if (severity === 'CRITICAL' || severity === 'HIGH') {
    stats.threatsDetected++;
  }
  return event;
}

// Initial engine telemetry
logEvent('CORE_INITIALIZED', 'INFO', '127.0.0.1', 'SYSTEM', 'RULE-CORE-001', 'WebSentinel enterprise daemon operational with native SQLite storage engine.', 'MONITORING');

// Threat Detection Signatures (OWASP & CWE Mapped)
const SIGNATURE_DATABASE = [
  { id: 'SIG-SQLI-001', name: 'SQL Injection: Tautology / Boolean Bypass', regex: /('|\b)(OR|AND)\b.+(=|<|>).+/i, severity: 'CRITICAL', cwe: 'CWE-89' },
  { id: 'SIG-SQLI-002', name: 'SQL Injection: UNION-Based Exfiltration', regex: /\bUNION\b\s+(\bALL\b\s+)?\bSELECT\b/i, severity: 'CRITICAL', cwe: 'CWE-89' },
  { id: 'SIG-SQLI-003', name: 'SQL Injection: Inline Comment / Stacked Query', regex: /(--|\/\*|;\s*(DROP|ALTER|INSERT|UPDATE|DELETE|EXEC)\b)/i, severity: 'CRITICAL', cwe: 'CWE-89' },
  { id: 'SIG-XSS-001',  name: 'Cross-Site Scripting: Explicit Tag Injection', regex: /<script\b[^>]*>([\s\S]*?)<\/script>/i, severity: 'HIGH', cwe: 'CWE-79' },
  { id: 'SIG-XSS-002',  name: 'Cross-Site Scripting: Inline Event Attribute', regex: /on(error|load|click|mouseover|submit|focus)\s*=/i, severity: 'HIGH', cwe: 'CWE-79' },
  { id: 'SIG-XSS-003',  name: 'Cross-Site Scripting: URI Scheme Invocation', regex: /javascript\s*:/i, severity: 'HIGH', cwe: 'CWE-79' },
  { id: 'SIG-PATH-001', name: 'Path Traversal: Directory Climb Sequence', regex: /(\.\.\/|\.\.\\)/i, severity: 'HIGH', cwe: 'CWE-22' },
  { id: 'SIG-PATH-002', name: 'LFI: Sensitive Configuration Probe', regex: /(\/etc\/passwd|win\.ini|boot\.ini|\.env|\.git)/i, severity: 'CRITICAL', cwe: 'CWE-22' }
];

function inspectPayload(inputString, honeypotValue) {
  const matches = [];

  if (honeypotValue && honeypotValue.trim().length > 0) {
    matches.push({
      ruleId: 'SIG-BOT-001',
      name: 'Automated Bot Trapped (Honeypot Non-Zero)',
      severity: 'HIGH',
      cwe: 'CWE-799',
      reason: 'Hidden bot field was populated by client.'
    });
  }

  if (typeof inputString === 'string') {
    for (const sig of SIGNATURE_DATABASE) {
      if (sig.regex.test(inputString)) {
        matches.push({
          ruleId: sig.id,
          name: sig.name,
          severity: sig.severity,
          cwe: sig.cwe,
          reason: `Matched detection signature ${sig.id}`
        });
      }
    }
  }

  return matches;
}

// Sliding Window Rate Limiter
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX_FAILURES = 5;

function evaluateRateLimit(ip, isFailed) {
  const now = Date.now();
  let timestamps = ipAttempts.get(ip) || [];
  timestamps = timestamps.filter(t => (now - t) < RATE_LIMIT_WINDOW_MS);

  if (isFailed) {
    timestamps.push(now);
  }
  ipAttempts.set(ip, timestamps);

  const isBlocked = timestamps.length >= RATE_LIMIT_MAX_FAILURES;
  return {
    isBlocked,
    recentFailures: timestamps.length,
    threshold: RATE_LIMIT_MAX_FAILURES,
    retryAfterSec: isBlocked ? Math.ceil((timestamps[0] + RATE_LIMIT_WINDOW_MS - now) / 1000) : 0
  };
}

// Target URL Security Auditing
async function auditTargetUrl(targetUrl) {
  return new Promise((resolve) => {
    let parsedUrl;
    try {
      parsedUrl = new URL(targetUrl);
    } catch (e) {
      return resolve({ error: 'Formato de URL inválido. Use http:// o https://' });
    }

    const client = parsedUrl.protocol === 'https:' ? https : http;
    const startTime = Date.now();

    const req = client.get(targetUrl, { timeout: 8000 }, (res) => {
      const latencyMs = Date.now() - startTime;
      const headers = res.headers;

      const headerStandards = {
        'content-security-policy': {
          header: 'Content-Security-Policy',
          present: Boolean(headers['content-security-policy']),
          impact: 'Mitigación de XSS, Clickjacking e inyección dinámica',
          severity: 'HIGH'
        },
        'x-frame-options': {
          header: 'X-Frame-Options',
          present: Boolean(headers['x-frame-options']),
          impact: 'Protección contra Clickjacking y anidamiento en frames',
          severity: 'MEDIUM'
        },
        'x-content-type-options': {
          header: 'X-Content-Type-Options',
          present: headers['x-content-type-options'] === 'nosniff',
          impact: 'Restricción de sniffing MIME indebido (nosniff)',
          severity: 'MEDIUM'
        },
        'strict-transport-security': {
          header: 'Strict-Transport-Security',
          present: Boolean(headers['strict-transport-security']),
          impact: 'Garantía obligatoria de transporte HTTPS cifrado (HSTS)',
          severity: parsedUrl.protocol === 'https:' ? 'HIGH' : 'LOW'
        },
        'referrer-policy': {
          header: 'Referrer-Policy',
          present: Boolean(headers['referrer-policy']),
          impact: 'Control de fuga de metadatos en peticiones salientes',
          severity: 'LOW'
        }
      };

      const missing = Object.values(headerStandards).filter(h => !h.present);
      const score = Math.max(10, 100 - (missing.length * 18));

      const result = {
        url: targetUrl,
        statusCode: res.statusCode,
        latencyMs,
        securityScore: score,
        headerChecks: headerStandards,
        missingHeadersCount: missing.length,
        rawHeaders: headers
      };

      storage.saveScanResult(result);
      resolve(result);
    });

    req.on('error', (err) => resolve({ error: `Fallo de conexión: ${err.message}` }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ error: 'Tiempo de espera excedido (> 8000ms)' });
    });
  });
}

// Server Dispatcher
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Sentinel-Key');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // --- API Routes ---

  // GET /api/stats
  if (req.method === 'GET' && pathname === '/api/stats') {
    const summary = storage.getAnalyticsSummary();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      ...stats,
      uptimeSeconds: Math.floor((Date.now() - stats.startTime) / 1000),
      totalPersistedIncidents: summary.totalIncidents,
      criticalCount: summary.criticalCount,
      engineStatus: 'ACTIVE_ARMED',
      storageEngine: 'SQLITE_PERSISTENT'
    }));
  }

  // GET /api/events (Read directly from SQLite)
  if (req.method === 'GET' && pathname === '/api/events') {
    const severity = parsed.query.severity || 'ALL';
    const limit = parseInt(parsed.query.limit || '100', 10);
    const rows = storage.getIncidents(limit, severity);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(rows));
  }

  // GET /api/sql/summary (SQL Analytics Aggregation)
  if (req.method === 'GET' && pathname === '/api/sql/summary') {
    const analytics = storage.getAnalyticsSummary();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(analytics));
  }

  // POST /api/sql/query (Run read-only SQL queries from dashboard)
  if (req.method === 'POST' && pathname === '/api/sql/query') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const query = data.query || 'SELECT * FROM incidents ORDER BY timestamp DESC LIMIT 10';
        const rows = storage.runReadOnlyQuery(query);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, count: rows.length, rows }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: err.message }));
      }
    });
    return;
  }

  // GET /api/export-csv
  if (req.method === 'GET' && pathname === '/api/export-csv') {
    const rows = storage.getIncidents(500, 'ALL');
    let csv = 'ID,TIMESTAMP,SEVERITY,TYPE,RULE_ID,SOURCE_IP,TARGET,ACTION,DETAILS\n';
    for (const ev of rows) {
      const cleanDetails = (ev.details || '').replace(/"/g, '""');
      csv += `"${ev.id}","${ev.timestamp}","${ev.severity}","${ev.type}","${ev.rule_id}","${ev.source_ip}","${ev.target}","${ev.action}","${cleanDetails}"\n`;
    }
    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="websentinel-audit-events.csv"'
    });
    return res.end(csv);
  }

  // POST /api/scan
  if (req.method === 'POST' && pathname === '/api/scan') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body || '{}');
        if (!payload.url) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Parámetro URL requerido' }));
        }

        stats.totalScans++;
        const audit = await auditTargetUrl(payload.url);

        if (!audit.error) {
          const sev = audit.securityScore < 50 ? 'HIGH' : (audit.securityScore < 80 ? 'MEDIUM' : 'INFO');
          logEvent('URL_AUDIT_PROBE', sev, req.socket.remoteAddress, payload.url, 'RULE-AUDIT-01',
            `Auditoría completada. Calificación: ${audit.securityScore}/100. Faltantes: ${audit.missingHeadersCount}. Latencia: ${audit.latencyMs}ms.`, 'AUDITED');
        } else {
          logEvent('URL_AUDIT_FAILURE', 'MEDIUM', req.socket.remoteAddress, payload.url, 'RULE-AUDIT-02', audit.error, 'DROPPED');
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(audit));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // POST /api/analyze-request (Consumed by Laravel Middleware or UI)
  if (req.method === 'POST' && pathname === '/api/analyze-request') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        stats.inspectionsRun++;
        const data = JSON.parse(body || '{}');
        const input = data.input || '';
        const honeypot = data.honeypot || '';
        const clientIp = data.clientIp || req.socket.remoteAddress || '127.0.0.1';
        const target = data.targetEndpoint || '/api/v1/resource';

        const threats = inspectPayload(input, honeypot);

        if (threats.length > 0) {
          for (const t of threats) {
            logEvent('INJECTION_THREAT', t.severity, clientIp, target, t.ruleId,
              `${t.name} (${t.cwe}). Muestra: "${input.substring(0, 48)}"`, 'BLOCKED');
          }
        } else {
          logEvent('PAYLOAD_INSPECTED', 'INFO', clientIp, target, 'RULE-WAF-CLEAN',
            'Comprobación de integridad exitosa. Sin patrones maliciosos conocidos.', 'PASSED');
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          safe: threats.length === 0,
          threatCount: threats.length,
          threats
        }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'JSON malformado' }));
      }
    });
    return;
  }

  // POST /api/record-login
  if (req.method === 'POST' && pathname === '/api/record-login') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const clientIp = data.clientIp || req.socket.remoteAddress || '127.0.0.1';
        const identifier = data.identifier || 'anonymous';
        const isSuccess = Boolean(data.success);

        const rate = evaluateRateLimit(clientIp, !isSuccess);

        if (rate.isBlocked) {
          stats.bruteForceBlocked++;
          logEvent('AUTH_BRUTEFORCE_MITIGATED', 'CRITICAL', clientIp, '/auth/login', 'RULE-RATE-001',
            `Límite de tasa excedido (${rate.recentFailures} fallos/min). IP en cooldown por ${rate.retryAfterSec}s.`, 'IP_BLOCKED');
        } else if (!isSuccess) {
          logEvent('AUTH_FAILURE', rate.recentFailures >= 3 ? 'HIGH' : 'LOW', clientIp, '/auth/login', 'RULE-AUTH-002',
            `Intento de autenticación fallido para identidad "${identifier}". Conteo acumulado: ${rate.recentFailures}/${rate.threshold}.`, 'REJECTED');
        } else {
          logEvent('AUTH_SUCCESS', 'INFO', clientIp, '/auth/login', 'RULE-AUTH-001',
            `Autenticación exitosa confirmada para "${identifier}".`, 'AUTHORIZED');
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: rate.isBlocked ? 'BLOCKED' : (isSuccess ? 'AUTHORIZED' : 'DENIED'),
          rate
        }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Petición inválida' }));
      }
    });
    return;
  }

  // POST /api/simulate-attack
  if (req.method === 'POST' && pathname === '/api/simulate-attack') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      const data = JSON.parse(body || '{}');
      const vector = data.vector || 'sqli';
      const fakeIp = `198.51.100.${Math.floor(Math.random() * 200) + 10}`;

      if (vector === 'sqli') {
        logEvent('INJECTION_THREAT', 'CRITICAL', fakeIp, '/api/records/query', 'SIG-SQLI-001',
          "Ataque simulado: [SELECT * FROM users WHERE id = '' OR 1=1 --]. Interceptado por motor heurístico.", 'BLOCKED');
      } else if (vector === 'bruteforce') {
        for (let i = 0; i < 5; i++) {
          evaluateRateLimit(fakeIp, true);
        }
        stats.bruteForceBlocked++;
        logEvent('AUTH_BRUTEFORCE_MITIGATED', 'CRITICAL', fakeIp, '/auth/admin', 'SIG-RATE-001',
          `Ataque de diccionario simulado: 5 intentos en 1.8s. Dirección IP bloqueada temporalmente.`, 'IP_BLOCKED');
      } else if (vector === 'bot_honeypot') {
        logEvent('BOT_ANOMALY', 'HIGH', fakeIp, '/portal/contacto', 'SIG-BOT-001',
          'Rastreador automatizado neutralizado: Campo trampa de verificación poblado con valor sintético.', 'REJECTED');
      } else if (vector === 'xss') {
        logEvent('INJECTION_THREAT', 'HIGH', fakeIp, '/portal/comentarios', 'SIG-XSS-001',
          'Inyección XSS reflejada detectada: [<script>document.cookie</script>]. Sanitización forzada.', 'BLOCKED');
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, vector, simulatedIp: fakeIp }));
    });
    return;
  }

  // --- Session & User Activity Audit Routes ---

  // GET /api/sessions
  if (req.method === 'GET' && pathname === '/api/sessions') {
    const limit = parseInt(parsed.query.limit || '50', 10);
    const sessions = storage.getUserSessions(limit);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(sessions));
  }

  // GET /api/sessions/activities?sessionId=...
  if (req.method === 'GET' && pathname === '/api/sessions/activities') {
    const sessionId = parsed.query.sessionId;
    if (!sessionId) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'sessionId requerido' }));
    }
    const activities = storage.getSessionActivities(sessionId);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(activities));
  }

  // POST /api/sessions/login
  if (req.method === 'POST' && pathname === '/api/sessions/login') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const sessId = storage.createSession({
          user_identifier: data.user || 'usuario.anonimo',
          role: data.role || 'USUARIO',
          ip_address: data.ip || req.socket.remoteAddress || '127.0.0.1',
          login_portal: data.portal || '/auth/login',
          user_agent: req.headers['user-agent'] || 'WebClient'
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, sessionId: sessId }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // POST /api/sessions/activity
  if (req.method === 'POST' && pathname === '/api/sessions/activity') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        storage.recordActivity(
          data.sessionId,
          data.actionType || 'GENERIC_ACTION',
          data.endpoint || '/api',
          data.description || 'Acción ejecutada',
          data.riskLevel || 'NORMAL'
        );
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // POST /api/sessions/logout
  if (req.method === 'POST' && pathname === '/api/sessions/logout') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const ok = storage.closeSession(data.sessionId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: ok }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // POST /api/sessions/simulate
  if (req.method === 'POST' && pathname === '/api/sessions/simulate') {
    const roles = ['USUARIO_OPERADOR', 'ADMINISTRADOR_PRUEBAS', 'ANALISTA_DEMO'];
    const users = ['usuario_demo_01@test.local', 'operador_prueba@test.local', 'admin_demo@test.local'];
    const portals = ['/portal/login', '/dashboard/panel', '/modulo/formularios'];
    const ips = ['192.168.1.105', '10.0.0.45', '127.0.0.1'];

    const chosenRole = roles[Math.floor(Math.random() * roles.length)];
    const chosenUser = users[Math.floor(Math.random() * users.length)];
    const chosenPortal = portals[Math.floor(Math.random() * portals.length)];
    const chosenIp = ips[Math.floor(Math.random() * ips.length)];

    const sessId = storage.createSession({
      user_identifier: chosenUser,
      role: chosenRole,
      ip_address: chosenIp,
      login_portal: chosenPortal,
      user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/127.0.0.0'
    });

    // Add simulated generic actions
    storage.recordActivity(sessId, 'CONSULTA_DATOS', chosenPortal, `Consulta de verificación realizada en el sistema.`, 'NORMAL');
    storage.recordActivity(sessId, 'ACTUALIZACION_REGISTRO', '/api/registros/save', 'Validación de formulario de prueba completada.', 'NORMAL');

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true, sessionId: sessId, user: chosenUser }));
    return;
  }

  // Static Assets Dispatcher
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
  const ext = path.extname(filePath);
  const mimeTypes = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json',
    '.svg': 'image/svg+xml'
  };

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
    } else {
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain' });
      res.end(content);
    }
  });
});

server.listen(PORT, () => {
  console.log(`[WebSentinel-CS Engine] Daemon active: http://localhost:${PORT}`);
  console.log(`[WebSentinel-CS Storage] Native SQLite database: sentinel.sqlite`);
});
