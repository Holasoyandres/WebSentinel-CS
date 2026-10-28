/**
 * WebSentinel-CS: Standalone Web Security & Anomaly Detection Sentinel
 * Developed by Holasoyandres (Open Source Security Portfolio Project)
 * 
 * Features:
 * - Native HTTP Server (Zero external dependencies)
 * - Security Headers & Sensitive Files Vulnerability Scanner
 * - Brute-Force & Credential Stuffing Anomaly Detection Engine
 * - SQLi, XSS, Path Traversal & Bot Honeypot Input Inspection
 * - Real-time Security Event Logging & Metrics API
 */

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 4000;
const PUBLIC_DIR = path.join(__dirname, 'public');

// --- In-Memory State & Metrics Store ---
const securityEvents = [];
const ipAttempts = new Map(); // IP -> Array of timestamps
const MAX_EVENTS = 100;

const stats = {
  totalScans: 0,
  threatsDetected: 0,
  bruteForceBlocked: 0,
  inspectionsRun: 0,
  startTime: Date.now()
};

// Helper: Log security event
function logEvent(type, severity, sourceIp, target, details) {
  const event = {
    id: Date.now().toString(36) + Math.random().toString(36).substr(2, 5),
    timestamp: new Date().toISOString(),
    type,
    severity, // 'INFO', 'WARNING', 'DANGER', 'CRITICAL'
    sourceIp: sourceIp || '127.0.0.1',
    target: target || 'API/Web',
    details
  };
  securityEvents.unshift(event);
  if (securityEvents.length > MAX_EVENTS) securityEvents.pop();
  if (severity === 'DANGER' || severity === 'CRITICAL') {
    stats.threatsDetected++;
  }
  return event;
}

// Initial system event
logEvent('SYSTEM_START', 'INFO', '127.0.0.1', 'Sentinel Core', 'WebSentinel-CS initialized and listening on port ' + PORT);

// --- Inspection Engines ---

// 1. Signature & Heuristic Pattern Matching
const MALICIOUS_PATTERNS = [
  { name: 'SQL Injection (Boolean/Tautology)', regex: /('|\b)(OR|AND)\b.+(=|<|>).+/i, severity: 'CRITICAL' },
  { name: 'SQL Injection (Union Based)', regex: /\bUNION\b\s+(\bALL\b\s+)?\bSELECT\b/i, severity: 'CRITICAL' },
  { name: 'SQL Injection (Stacked/Comment)', regex: /(--|\/\*|;.*(DROP|ALTER|INSERT|UPDATE|DELETE))/i, severity: 'CRITICAL' },
  { name: 'Cross-Site Scripting (XSS Tag)', regex: /<script\b[^>]*>([\s\S]*?)<\/script>/i, severity: 'DANGER' },
  { name: 'Cross-Site Scripting (Inline Event)', regex: /on(error|load|click|mouseover|submit)\s*=/i, severity: 'DANGER' },
  { name: 'Cross-Site Scripting (JS Protocol)', regex: /javascript\s*:/i, severity: 'DANGER' },
  { name: 'Path Traversal (Directory Climb)', regex: /(\.\.\/|\.\.\\)/i, severity: 'CRITICAL' },
  { name: 'Sensitive File Access (/etc/passwd)', regex: /(\/etc\/passwd|win\.ini|boot\.ini)/i, severity: 'CRITICAL' }
];

function inspectPayload(inputString, honeypotValue) {
  const matches = [];

  // Check honeypot (Bot detection)
  if (honeypotValue && honeypotValue.trim().length > 0) {
    matches.push({
      name: 'Bot Honeypot Trap Triggered',
      severity: 'CRITICAL',
      reason: 'Hidden bot verification field was filled out.'
    });
  }

  // Check injection patterns
  if (typeof inputString === 'string') {
    for (const pattern of MALICIOUS_PATTERNS) {
      if (pattern.regex.test(inputString)) {
        matches.push({
          name: pattern.name,
          severity: pattern.severity,
          reason: `Matched pattern rule: ${pattern.name}`
        });
      }
    }
  }

  return matches;
}

// 2. Sliding-Window Rate Limiting (Brute Force Detection)
const BRUTE_FORCE_WINDOW_MS = 60 * 1000; // 1 minute
const BRUTE_FORCE_MAX_FAILURES = 5;

function checkBruteForce(ip, isFailed) {
  const now = Date.now();
  let timestamps = ipAttempts.get(ip) || [];

  // Retain only timestamps within window
  timestamps = timestamps.filter(t => (now - t) < BRUTE_FORCE_WINDOW_MS);

  if (isFailed) {
    timestamps.push(now);
  }
  ipAttempts.set(ip, timestamps);

  const isBlocked = timestamps.length >= BRUTE_FORCE_MAX_FAILURES;
  return {
    isBlocked,
    recentFailures: timestamps.length,
    threshold: BRUTE_FORCE_MAX_FAILURES,
    retryAfterSec: isBlocked ? Math.ceil((timestamps[0] + BRUTE_FORCE_WINDOW_MS - now) / 1000) : 0
  };
}

// 3. Remote URL Security Scanner
async function auditTargetUrl(targetUrl) {
  return new Promise((resolve) => {
    let parsedUrl;
    try {
      parsedUrl = new URL(targetUrl);
    } catch (e) {
      return resolve({ error: 'Invalid URL format' });
    }

    const client = parsedUrl.protocol === 'https:' ? https : http;
    const startTime = Date.now();

    const req = client.get(targetUrl, { timeout: 8000 }, (res) => {
      const latencyMs = Date.now() - startTime;
      const headers = res.headers;

      // Audit Recommended Security Headers (OWASP)
      const headerChecks = {
        'Content-Security-Policy': {
          present: Boolean(headers['content-security-policy']),
          recommendation: 'Protects against XSS, clickjacking, and code injection.'
        },
        'X-Frame-Options': {
          present: Boolean(headers['x-frame-options']),
          recommendation: 'Prevents clickjacking by controlling framing.'
        },
        'X-Content-Type-Options': {
          present: Boolean(headers['x-content-type-options']),
          recommendation: 'Prevents MIME-sniffing vulnerabilities (nosniff).'
        },
        'Strict-Transport-Security': {
          present: Boolean(headers['strict-transport-security']),
          recommendation: 'Forces secure HTTPS connections (HSTS).'
        },
        'Referrer-Policy': {
          present: Boolean(headers['referrer-policy']),
          recommendation: 'Controls how much referrer information is leaked.'
        }
      };

      const missingHeaders = Object.keys(headerChecks).filter(h => !headerChecks[h].present);
      const score = Math.max(10, 100 - (missingHeaders.length * 18));

      resolve({
        url: targetUrl,
        statusCode: res.statusCode,
        latencyMs,
        securityScore: score,
        headerChecks,
        missingHeadersCount: missingHeaders.length
      });
    });

    req.on('error', (err) => {
      resolve({ error: `Connection failed: ${err.message}` });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ error: 'Request timed out after 8 seconds' });
    });
  });
}

// --- HTTP Request Handler ---
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // Set CORS for local integration
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // --- API Endpoints ---

  // GET /api/stats
  if (req.method === 'GET' && pathname === '/api/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ...stats,
      uptimeSeconds: Math.floor((Date.now() - stats.startTime) / 1000),
      activeEventCount: securityEvents.length
    }));
    return;
  }

  // GET /api/events
  if (req.method === 'GET' && pathname === '/api/events') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(securityEvents));
    return;
  }

  // POST /api/scan
  if (req.method === 'POST' && pathname === '/api/scan') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const data = JSON.parse(body || '{}');
        const target = data.url;
        if (!target) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'URL parameter is required' }));
        }

        stats.totalScans++;
        const auditResult = await auditTargetUrl(target);

        if (!auditResult.error) {
          logEvent(
            'URL_AUDIT_COMPLETE',
            auditResult.securityScore < 60 ? 'WARNING' : 'INFO',
            req.socket.remoteAddress,
            target,
            `Scan finished. Score: ${auditResult.securityScore}%. Missing headers: ${auditResult.missingHeadersCount}. Latency: ${auditResult.latencyMs}ms.`
          );
        } else {
          logEvent('URL_AUDIT_FAILED', 'WARNING', req.socket.remoteAddress, target, auditResult.error);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(auditResult));
      } catch (err) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  // POST /api/analyze-request (Inspect input payloads & honeypots)
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

        const threats = inspectPayload(input, honeypot);

        if (threats.length > 0) {
          logEvent(
            'MALICIOUS_INPUT_DETECTED',
            'CRITICAL',
            clientIp,
            data.targetEndpoint || '/form-submission',
            `Threats found: ${threats.map(t => t.name).join(', ')}. Payload sample: "${input.substring(0, 40)}..."`
          );
        } else {
          logEvent('CLEAN_INPUT_VERIFIED', 'INFO', clientIp, data.targetEndpoint || '/form-submission', 'Input validated cleanly against OWASP signature set.');
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          safe: threats.length === 0,
          threatCount: threats.length,
          threats
        }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON payload' }));
      }
    });
    return;
  }

  // POST /api/record-login (Brute force & authentication monitor)
  if (req.method === 'POST' && pathname === '/api/record-login') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const clientIp = data.clientIp || req.socket.remoteAddress || '127.0.0.1';
        const email = data.email || 'anonymous';
        const isSuccess = Boolean(data.success);

        const rateStatus = checkBruteForce(clientIp, !isSuccess);

        if (rateStatus.isBlocked) {
          stats.bruteForceBlocked++;
          logEvent(
            'BRUTE_FORCE_BLOCKED',
            'CRITICAL',
            clientIp,
            '/login',
            `IP rate limit exceeded (${rateStatus.recentFailures} failures in window). Temporarily blocked for ${rateStatus.retryAfterSec}s.`
          );
        } else if (!isSuccess) {
          logEvent(
            'LOGIN_FAILED',
            rateStatus.recentFailures >= 3 ? 'WARNING' : 'INFO',
            clientIp,
            '/login',
            `Failed authentication attempt for "${email}" (${rateStatus.recentFailures}/${rateStatus.threshold} attempts).`
          );
        } else {
          logEvent('LOGIN_SUCCESS', 'INFO', clientIp, '/login', `Successful login verified for user "${email}".`);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: rateStatus.isBlocked ? 'BLOCKED' : (isSuccess ? 'AUTHORIZED' : 'DENIED'),
          rateStatus
        }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request' }));
      }
    });
    return;
  }

  // POST /api/simulate-attack (Demonstration tool for testing defense rules)
  if (req.method === 'POST' && pathname === '/api/simulate-attack') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      const data = JSON.parse(body || '{}');
      const vector = data.vector || 'sqli';
      const fakeIp = `198.51.100.${Math.floor(Math.random() * 200) + 10}`;

      if (vector === 'sqli') {
        inspectPayload("' OR 1=1 --", '');
        logEvent('SIMULATED_ATTACK', 'CRITICAL', fakeIp, '/api/denuncias/query', 'Simulated SQL Injection: Payload [\' OR 1=1 --] blocked by rule.');
      } else if (vector === 'bruteforce') {
        for (let i = 0; i < 6; i++) {
          checkBruteForce(fakeIp, true);
        }
        stats.bruteForceBlocked++;
        logEvent('SIMULATED_ATTACK', 'CRITICAL', fakeIp, '/login', `Simulated Brute-Force attack: 6 rapid failed attempts. IP blocked.`);
      } else if (vector === 'bot_honeypot') {
        logEvent('SIMULATED_ATTACK', 'DANGER', fakeIp, '/form-pqr', 'Simulated Automated Bot: Hidden honeypot field filled by crawler.');
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, vector, simulatedIp: fakeIp }));
    });
    return;
  }

  // --- Static Files Serving ---
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
  const ext = path.extname(filePath);
  const mimeTypes = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.svg': 'image/svg+xml',
    '.png': 'image/png'
  };

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/html' });
        res.end('<h1>404 Not Found</h1><p>WebSentinel-CS endpoint or file not found.</p>');
      } else {
        res.writeHead(500);
        res.end(`Server Error: ${err.code}`);
      }
    } else {
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain' });
      res.end(content, 'utf-8');
    }
  });
});

server.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🛡️  WebSentinel-CS: Security & Anomaly Detection Sentinel`);
  console.log(`📡  Server active at: http://localhost:${PORT}`);
  console.log(`🌐  Open in browser to access the Cyber Security Dashboard`);
  console.log(`=======================================================`);
});
