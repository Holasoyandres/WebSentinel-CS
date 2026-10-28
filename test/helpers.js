/**
 * WebSentinel-CS :: Test Helpers
 * Spawns isolated test servers with in-memory SQLite
 */

const http = require('node:http');
const path = require('node:path');
const { createDatabase } = require('../src/db');
const { createApp } = require('../src/app');

async function startTestServer(options = {}) {
  const testConfig = {
    VERSION: '1.3.0-TEST',
    ENV: 'test',
    HOST: '127.0.0.1',
    PORT: 0, // Random available port
    DB_PATH: ':memory:',
    DEMO_MODE: options.demoMode ?? true,
    CORS_ORIGINS: ['*'],
    SCAN_ALLOWLIST: ['127.0.0.1', 'localhost'],
    RETENTION_DAYS: 30,
    LOG_LEVEL: 'silent',
    MAX_BODY_BYTES: 1048576,
    ...options.config
  };

  const db = createDatabase(testConfig.DB_PATH);
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
      const headers = reqOptions.headers || {};
      let bodyData = null;

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
  }

  return {
    server,
    port,
    baseUrl,
    db,
    stats,
    rateLimiter,
    request,
    close
  };
}

module.exports = { startTestServer };
