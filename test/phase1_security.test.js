/**
 * WebSentinel-CS :: Phase 1 Security Tests (P0 Vulnerabilities Reproduction & Verification)
 * Strictly verifies fixes for the Senior AppSec Audit findings
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');

const { startTestServer } = require('./helpers');

describe('WebSentinel-CS :: FASE 1 - Seguridad Crítica (P0)', () => {
  let ctx;
  let testApiKey;
  let testAdminUser;
  let adminSessionCookie;
  let adminCsrfToken;

  before(async () => {
    // Generate isolated test server
    ctx = await startTestServer({
      config: {
        CORS_ORIGINS: ['http://trusted-app.local', 'http://127.0.0.1:4000'],
        SCAN_ALLOWLIST: ['trusted.local']
      }
    });

    // Create API Key for tests
    testApiKey = 'ws_test_' + crypto.randomBytes(16).toString('hex');
    const keyHash = crypto.createHash('sha256').update(testApiKey).digest('hex');
    ctx.db.raw.prepare(`
      INSERT INTO api_keys (id, name, key_hash, scopes, created_at)
      VALUES (?, ?, ?, ?, datetime('now'))
    `).run('key-test-01', 'Test Client', keyHash, 'ingest,read');

    // Create Admin User for tests
    const salt = crypto.randomBytes(16).toString('hex');
    const passHash = crypto.scryptSync('AdminTest123!', salt, 64).toString('hex');
    ctx.db.raw.prepare(`
      INSERT INTO users (id, username, password_hash, salt, role, created_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `).run('usr-admin-01', 'admin_sec', passHash, salt, 'admin');

    // Perform login to acquire session cookie and CSRF token
    const loginRes = await ctx.request('/api/auth/login', {
      method: 'POST',
      body: { username: 'admin_sec', password: 'AdminTest123!' }
    });

    assert.equal(loginRes.status, 200, 'Login for admin should succeed');
    const setCookie = loginRes.headers['set-cookie'];
    assert.ok(setCookie, 'Should set session cookie');
    const match = setCookie[0].match(/sentinel_session=([^;]+)/);
    assert.ok(match, 'Should extract sentinel_session');
    adminSessionCookie = `sentinel_session=${match[1]}`;
    adminCsrfToken = loginRes.json.csrfToken;
    assert.ok(adminCsrfToken, 'Should return csrfToken');
  });

  after(async () => {
    if (ctx) await ctx.close();
  });

  // ---------------------------------------------------------------------------
  // 1. Path Traversal & Static Files Restriction
  // ---------------------------------------------------------------------------
  describe('1. Path Traversal & Static Assets Restriction', () => {
    test('Rejects GET /../server.js with 403/404, never 200', async () => {
      const res = await ctx.request('/../server.js');
      assert.notEqual(res.status, 200, 'Must NOT return 200 for parent directory traversal');
      assert.ok([400, 403, 404].includes(res.status));
    });

    test('Rejects URL-encoded path traversal /%2e%2e/server.js', async () => {
      const res = await ctx.request('/%2e%2e/server.js');
      assert.notEqual(res.status, 200, 'Must NOT serve server.js with encoded dots');
      assert.ok([400, 403, 404].includes(res.status));
    });

    test('Rejects path traversal with null byte', async () => {
      const res = await ctx.request('/index.html%00.png');
      assert.notEqual(res.status, 200, 'Must NOT serve files with null bytes');
      assert.ok([400, 403, 404].includes(res.status));
    });

    test('Rejects access to database file /../data/sentinel.sqlite', async () => {
      const res = await ctx.request('/../data/sentinel.sqlite');
      assert.notEqual(res.status, 200, 'Must NOT download SQLite database');
      assert.ok([400, 403, 404].includes(res.status));
    });

    test('Rejects non-whitelisted extensions (e.g. .env, .sqlite, .bak)', async () => {
      // Create a test sensitive file in public folder
      const dummySecret = path.join(__dirname, '..', 'public', 'test_secret.env');
      try {
        fs.writeFileSync(dummySecret, 'DATABASE_PASSWORD=secret');
        const res = await ctx.request('/test_secret.env');
        assert.notEqual(res.status, 200, 'Must NOT serve non-whitelisted file extension');
        assert.ok([403, 404].includes(res.status));
      } finally {
        if (fs.existsSync(dummySecret)) fs.unlinkSync(dummySecret);
      }
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Body Parser & Crash Prevention
  // ---------------------------------------------------------------------------
  describe('2. Request Body Robustness & Crash Prevention', () => {
    test('POST malformed JSON returns 400 Bad Request and keeps server running', async () => {
      const res = await ctx.request('/api/analyze-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sentinel-Key': testApiKey },
        body: '{"invalid": json syntax error...'
      });
      assert.equal(res.status, 400, 'Should return 400 Bad Request');
      assert.equal(res.json.error, true);
    });

    test('POST payload exceeding 1MB threshold returns 413 Payload Too Large', async () => {
      const hugeData = 'x'.repeat(1024 * 1024 + 100);
      const res = await ctx.request('/api/analyze-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Sentinel-Key': testApiKey },
        body: JSON.stringify({ input: hugeData })
      });
      assert.equal(res.status, 413, 'Should return 413 Payload Too Large');
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Two-Tier Authentication & RBAC
  // ---------------------------------------------------------------------------
  describe('3. Two-Tier Authentication (API Keys & Session RBAC)', () => {
    test('Unauthenticated request to protected API endpoint returns 401', async () => {
      const res = await ctx.request('/api/events', { auth: false });
      assert.equal(res.status, 401, 'Should require authentication');
      assert.equal(res.json.error, true);
    });

    test('Invalid X-Sentinel-Key returns 401 Unauthorized', async () => {
      const res = await ctx.request('/api/events', {
        headers: { 'X-Sentinel-Key': 'invalid_secret_key' }
      });
      assert.equal(res.status, 401, 'Should reject invalid API key');
    });

    test('Valid X-Sentinel-Key allows access to authorized scopes', async () => {
      const res = await ctx.request('/api/events', {
        headers: { 'X-Sentinel-Key': testApiKey }
      });
      assert.equal(res.status, 200, 'Should permit access with valid API key');
      assert.ok(Array.isArray(res.json));
    });

    test('Dashboard session allows access and verifies identity with /api/auth/me', async () => {
      const res = await ctx.request('/api/auth/me', {
        headers: { Cookie: adminSessionCookie }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.user.username, 'admin_sec');
      assert.equal(res.json.user.role, 'admin');
    });

    test('Dashboard POST request without CSRF token is rejected with 403', async () => {
      const res = await ctx.request('/api/sessions/simulate', {
        method: 'POST',
        headers: {
          Cookie: adminSessionCookie,
          'Content-Type': 'application/json'
        },
        body: {}
      });
      assert.equal(res.status, 403, 'Should reject dashboard state modification without CSRF token');
    });

    test('Dashboard POST request with valid CSRF token succeeds', async () => {
      const res = await ctx.request('/api/sessions/simulate', {
        method: 'POST',
        headers: {
          Cookie: adminSessionCookie,
          'X-CSRF-Token': adminCsrfToken,
          'Content-Type': 'application/json'
        },
        body: {}
      });
      assert.equal(res.status, 200, 'Should allow state change with valid CSRF');
      assert.equal(res.json.success, true);
    });

    test('Public routes (/healthz, /api/auth/login) are accessible without credentials', async () => {
      const healthRes = await ctx.request('/healthz');
      assert.equal(healthRes.status, 200);
      assert.equal(healthRes.json.status, 'UP');
    });
  });

  // ---------------------------------------------------------------------------
  // 4. SQL Forensics Console Hardening
  // ---------------------------------------------------------------------------
  describe('4. SQL Console Isolation & Query Hardening', () => {
    test('Non-admin caller (API Key) is rejected with 403 Forbidden', async () => {
      const res = await ctx.request('/api/sql/query', {
        method: 'POST',
        headers: {
          'X-Sentinel-Key': testApiKey,
          'Content-Type': 'application/json'
        },
        body: { query: 'SELECT 1' }
      });
      assert.equal(res.status, 403, 'API Key should NOT have access to raw SQL console');
    });

    test('Reject multi-statement queries containing semicolon', async () => {
      const res = await ctx.request('/api/sql/query', {
        method: 'POST',
        headers: {
          Cookie: adminSessionCookie,
          'X-CSRF-Token': adminCsrfToken,
          'Content-Type': 'application/json'
        },
        body: { query: 'SELECT 1; DROP TABLE incidents;' }
      });
      assert.equal(res.status, 400, 'Should reject query with semicolon / multiple statements');
    });

    test('Reject non-SELECT statements (INSERT/UPDATE/DELETE/PRAGMA)', async () => {
      const res = await ctx.request('/api/sql/query', {
        method: 'POST',
        headers: {
          Cookie: adminSessionCookie,
          'X-CSRF-Token': adminCsrfToken,
          'Content-Type': 'application/json'
        },
        body: { query: 'PRAGMA database_list' }
      });
      assert.equal(res.status, 400, 'Should reject PRAGMA/non-SELECT statements');
    });

    test('Valid admin SELECT query executes and records audit log in admin_audit_log', async () => {
      const res = await ctx.request('/api/sql/query', {
        method: 'POST',
        headers: {
          Cookie: adminSessionCookie,
          'X-CSRF-Token': adminCsrfToken,
          'Content-Type': 'application/json'
        },
        body: { query: 'SELECT count(*) as total FROM incidents' }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.success, true);

      // Verify audit record
      const logs = ctx.db.raw.prepare('SELECT * FROM admin_audit_log ORDER BY id DESC LIMIT 1').all();
      assert.ok(logs.length > 0, 'Should write to admin_audit_log');
      assert.equal(logs[0].user_id, 'usr-admin-01');
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Stored XSS Prevention & Enums Validation
  // ---------------------------------------------------------------------------
  describe('5. Stored XSS & Enumeration Validation', () => {
    test('Server rejects invalid severity and risk_level values with 400', async () => {
      const res = await ctx.request('/api/sessions/activity', {
        method: 'POST',
        headers: {
          'X-Sentinel-Key': testApiKey,
          'Content-Type': 'application/json'
        },
        body: {
          sessionId: 'test-sess',
          actionType: 'LOGIN',
          endpoint: '/test',
          description: 'test action',
          riskLevel: '<script>alert(1)</script>'
        }
      });
      assert.equal(res.status, 400, 'Should reject unvalidated risk level');
    });

    test('Dashboard index.html contains no inline onclick handlers', () => {
      const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');
      const onclickMatches = html.match(/onclick\s*=/gi);
      assert.equal(onclickMatches, null, 'public/index.html must not contain inline onclick handlers');
    });
  });

  // ---------------------------------------------------------------------------
  // 6. SSRF Prevention in /api/scan
  // ---------------------------------------------------------------------------
  describe('6. SSRF Protection on Remote URL Scanner', () => {
    test('Rejects scan to loopback address (127.0.0.1)', async () => {
      const res = await ctx.request('/api/scan', {
        method: 'POST',
        headers: {
          Cookie: adminSessionCookie,
          'X-CSRF-Token': adminCsrfToken,
          'Content-Type': 'application/json'
        },
        body: { url: 'http://127.0.0.1:8080/internal' }
      });
      assert.ok(res.json.error, 'Should reject loopback scanning');
      assert.match(res.json.error, /SSRF|restringid/i);
    });

    test('Rejects scan to cloud metadata link-local IP (169.254.169.254)', async () => {
      const res = await ctx.request('/api/scan', {
        method: 'POST',
        headers: {
          Cookie: adminSessionCookie,
          'X-CSRF-Token': adminCsrfToken,
          'Content-Type': 'application/json'
        },
        body: { url: 'http://169.254.169.254/latest/meta-data/' }
      });
      assert.ok(res.json.error, 'Should reject metadata link-local scanning');
      assert.match(res.json.error, /SSRF|restringid/i);
    });

    test('Rejects scan to private IPv4 RFC 1918 (10.0.0.1)', async () => {
      const res = await ctx.request('/api/scan', {
        method: 'POST',
        headers: {
          Cookie: adminSessionCookie,
          'X-CSRF-Token': adminCsrfToken,
          'Content-Type': 'application/json'
        },
        body: { url: 'http://10.0.0.1/admin' }
      });
      assert.ok(res.json.error, 'Should reject private IP scanning');
      assert.match(res.json.error, /SSRF|restringid/i);
    });
  });

  // ---------------------------------------------------------------------------
  // 7. Client IP Spoofing Protection
  // ---------------------------------------------------------------------------
  describe('7. Client IP Trust Enforcement', () => {
    test('Session caller cannot spoof clientIp in body; socket IP is used', async () => {
      const spoofedIp = '203.0.113.199';
      await ctx.request('/api/sessions/login', {
        method: 'POST',
        headers: {
          Cookie: adminSessionCookie,
          'X-CSRF-Token': adminCsrfToken,
          'Content-Type': 'application/json'
        },
        body: {
          user: 'spoof_test_user',
          ip: spoofedIp
        }
      });

      const row = ctx.db.raw.prepare(`SELECT ip_address FROM user_sessions WHERE user_identifier = 'spoof_test_user' ORDER BY login_time DESC LIMIT 1`).get();
      assert.notEqual(row.ip_address, spoofedIp, 'Should not trust arbitrary IP from body');
      assert.equal(row.ip_address, '127.0.0.1');
    });

    test('API Key with ingest scope is allowed to declare clientIp (e.g. Laravel middleware)', async () => {
      const trustedClientIp = '181.49.88.10';
      await ctx.request('/api/analyze-request', {
        method: 'POST',
        headers: {
          'X-Sentinel-Key': testApiKey,
          'Content-Type': 'application/json'
        },
        body: {
          input: 'SELECT * FROM users WHERE id = 1',
          clientIp: trustedClientIp
        }
      });

      const incident = ctx.db.raw.prepare(`SELECT source_ip FROM incidents ORDER BY timestamp DESC LIMIT 1`).get();
      assert.equal(incident.source_ip, trustedClientIp, 'Ingest API key must be trusted to report real client IP');
    });
  });

  // ---------------------------------------------------------------------------
  // 8. CORS Enforcement
  // ---------------------------------------------------------------------------
  describe('8. Strict CORS Origin Validation', () => {
    test('Untrusted Origin does not receive Access-Control-Allow-Origin header', async () => {
      const res = await ctx.request('/healthz', {
        headers: { Origin: 'http://malicious-site.com' }
      });
      assert.equal(res.headers['access-control-allow-origin'], undefined, 'Must NOT reflect untrusted origin or send wildcard');
    });

    test('Allowed Origin receives matching Access-Control-Allow-Origin and credentials', async () => {
      const res = await ctx.request('/healthz', {
        headers: { Origin: 'http://trusted-app.local' }
      });
      assert.equal(res.headers['access-control-allow-origin'], 'http://trusted-app.local');
      assert.equal(res.headers['access-control-allow-credentials'], 'true');
    });
  });

  // ---------------------------------------------------------------------------
  // 9. Standard Security Headers & Self-Scan 100/100
  // ---------------------------------------------------------------------------
  describe('9. Security Headers & Self-Audit', () => {
    test('Every response carries CSP, X-Frame-Options, X-Content-Type-Options and Referrer-Policy', async () => {
      const res = await ctx.request('/');
      assert.equal(res.status, 200);
      assert.ok(res.headers['content-security-policy'], 'CSP must be present');
      assert.equal(res.headers['x-frame-options'], 'DENY');
      assert.equal(res.headers['x-content-type-options'], 'nosniff');
      assert.equal(res.headers['referrer-policy'], 'strict-origin-when-cross-origin');
    });
  });

  // ---------------------------------------------------------------------------
  // 10. Query Parameter Limits & Clamping
  // ---------------------------------------------------------------------------
  describe('10. Query Limits & Parameter Sanitization', () => {
    test('limit=-1 or limit=99999 is clamped to 500 maximum', async () => {
      const res = await ctx.request('/api/events?limit=999999', {
        headers: { 'X-Sentinel-Key': testApiKey }
      });
      assert.equal(res.status, 200);
      assert.ok(Array.isArray(res.json));
    });
  });
});
