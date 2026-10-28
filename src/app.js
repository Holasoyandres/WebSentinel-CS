/**
 * WebSentinel-CS :: Application Factory
 * Composes HTTP server with database, engines and routes
 */

const http = require('node:http');
const path = require('node:path');
const { createRateLimiter } = require('./engine/rate-limit');
const { createApiHandler } = require('./routes/api');
const { createRouter } = require('./http/router');

function createApp({ config, db, publicDir }) {
  const resolvedPublicDir = publicDir || path.join(__dirname, '..', 'public');

  const stats = {
    totalScans: 0,
    threatsDetected: 0,
    bruteForceBlocked: 0,
    inspectionsRun: 0,
    startTime: Date.now()
  };

  const rateLimiter = createRateLimiter({
    windowMs: 60 * 1000,
    maxFailures: 5
  });

  const handleApi = createApiHandler({ db, rateLimiter, stats });
  const router = createRouter({ config, handleApi, publicDir: resolvedPublicDir });

  // Initial system telemetry event
  db.insertIncident({
    id: 'SEC-INIT-' + Date.now().toString(36).toUpperCase(),
    timestamp: new Date().toISOString(),
    type: 'CORE_INITIALIZED',
    severity: 'INFO',
    sourceIp: '127.0.0.1',
    target: 'SYSTEM',
    ruleId: 'RULE-CORE-001',
    action: 'MONITORING',
    details: `WebSentinel enterprise daemon operational on port ${config.PORT} (v${config.VERSION}).`
  });

  const server = http.createServer((req, res) => {
    router(req, res).catch((err) => {
      console.error('[Unhandled Request Error]', err);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: true, message: 'Internal Server Error' }));
      }
    });
  });

  return { server, stats, rateLimiter };
}

module.exports = { createApp };
