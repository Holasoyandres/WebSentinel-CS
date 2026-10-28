/**
 * WebSentinel-CS :: Test Helpers
 * Spawns isolated test servers with isolated disk SQLite for multi-threading support
 */

const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');

const { createDatabase } = require('../src/db');
const { createApp } = require('../src/app');

async function startTestServer(options = {}) {
  const tmpDbPath = path.join(os.tmpdir(), `sentinel-test-${crypto.randomUUID()}.sqlite`);

  const testConfig = {
    VERSION: '1.3.0-TEST',
    ENV: 'test',
    HOST: '127.0.0.1',
    PORT: 0, // Random available port
    DB_PATH: options.config && options.config.DB_PATH ? options.config.DB_PATH : tmpDbPath,
    DEMO_MODE: options.demoMode ?? true,
    CORS_ORIGINS: ['*'],
    SCAN_ALLOWLIST: ['127.0.0.1', 'localhost'],
    RETENTION_DAYS: 30,
    LOG_LEVEL: 'silent',
    MAX_BODY_BYTES: 1048576,
    ...options.config
  };

  const db = createDatabase(testConfig.DB_PATH);

  // Auto-provision default test API key
  const testApiKey = 'ws_test_' + crypto.randomBytes(16).toString('hex');
  const keyHash = crypto.createHash('sha256').update(testApiKey).digest('hex');
  db.raw.prepare(`
    INSERT INTO api_keys (id, name, key_hash, scopes, created_at)
    VALUES (?, ?, ?, ?, datetime('now'))
  `).run('key-default-test', 'Default Test Key', keyHash, 'ingest,read');

  // Auto-provision default admin user
  const adminSalt = crypto.randomBytes(16).toString('hex');
  const adminPassHash = crypto.scryptSync('SmokeAdminPass123!', adminSalt, 64).toString('hex');
  db.raw.prepare(`
    INSERT INTO users (id, username, password_hash, salt, role, created_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
  `).run('usr-admin-default', 'admin', adminPassHash, adminSalt, 'admin');

  const publicDir = options.publicDir || path.join(__dirname, '..', 'public');
  const { server, stats, rateLimiter } = createApp({ config: testConfig, db, publicDir });

  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  const address = server.address();
  const port = address.port;
  const baseUrl = `http://127.0.0.1:${port}`;

  async function request(reqPath, reqOptions = {}) {
    return new Promise((resolve, reject) => {
      const url = new URL(reqPath, baseUrl);
      const method = reqOptions.method || 'GET';
      const headers = { ...reqOptions.headers };
      let bodyData = null;

      // Auto-inject test API key unless explicitly opted out or session cookie is set
      const hasAuthHeader = headers['X-Sentinel-Key'] !== undefined || headers['x-sentinel-key'] !== undefined || headers['Cookie'] || headers['cookie'];
      if (!hasAuthHeader && reqOptions.auth !== false) {
        headers['X-Sentinel-Key'] = testApiKey;
      }

      if (reqOptions.body) {
        bodyData = typeof reqOptions.body === 'string'
          ? reqOptions.body
          : JSON.stringify(reqOptions.body);
        headers['Content-Type'] = headers['Content-Type'] || 'application/json';
        headers['Content-Length'] = Buffer.byteLength(bodyData);
      }

      const req = http.request(url, { method, headers }, (res) => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf-8');
          let json = null;
          try {
            json = JSON.parse(raw);
          } catch (_) {
            // Not JSON
          }
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: raw,
            json
          });
        });
      });

      req.on('error', reject);
      if (bodyData) req.write(bodyData);
      req.end();
    });
  }

  async function close() {
    await new Promise((resolve) => server.close(resolve));
    db.close();
    try {
      if (testConfig.DB_PATH === tmpDbPath && fs.existsSync(tmpDbPath)) {
        fs.unlinkSync(tmpDbPath);
      }
    } catch (_) {}
  }

  return {
    server,
    port,
    baseUrl,
    db,
    stats,
    rateLimiter,
    apiKey: testApiKey,
    request,
    close
  };
}

module.exports = { startTestServer };
