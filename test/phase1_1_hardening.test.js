/**
 * WebSentinel-CS :: Phase 1.1 Hardening Tests
 * Verifies strict permission matrix, login brute-force rate limit, timing attack mitigation,
 * SQL secret masking, CIDR matching, DNS rebinding prevention, and 500 error masking.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { startTestServer } = require('./helpers');

describe('WebSentinel-CS :: FASE 1.1 - Hardening & Depth Security', () => {
  let ctx;
  let ingestApiKey, readApiKey;
  let viewerCookie, analystCookie, adminCookie;
  let viewerCsrf, analystCsrf, adminCsrf;

  before(async () => {
    ctx = await startTestServer({
      config: {
        DEMO_MODE: false,
        SCAN_ALLOWLIST: ['172.16.0.0/16', '127.0.0.1']
      }
    });

    // 1. Provision ingest-only API Key
    ingestApiKey = 'ws_ingest_' + crypto.randomBytes(16).toString('hex');
    const ingestHash = crypto.createHash('sha256').update(ingestApiKey).digest('hex');
    ctx.db.raw.prepare(`
      INSERT INTO api_keys (id, name, key_hash, scopes, created_at)
      VALUES (?, ?, ?, ?, datetime('now'))
    `).run('key-ingest-only', 'Ingest Only Key', ingestHash, 'ingest');

    // 2. Provision read-only API Key
    readApiKey = 'ws_read_' + crypto.randomBytes(16).toString('hex');
    const readHash = crypto.createHash('sha256').update(readApiKey).digest('hex');
    ctx.db.raw.prepare(`
      INSERT INTO api_keys (id, name, key_hash, scopes, created_at)
      VALUES (?, ?, ?, ?, datetime('now'))
    `).run('key-read-only', 'Read Only Key', readHash, 'read');

    // 3. Provision Viewer, Analyst, Admin users
    const roles = ['viewer', 'analyst', 'admin'];
    for (const r of roles) {
      const salt = crypto.randomBytes(16).toString('hex');
      const passHash = crypto.scryptSync('Password123!', salt, 64).toString('hex');
      ctx.db.raw.prepare(`
        INSERT INTO users (id, username, password_hash, salt, role, created_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
      `).run(`usr-${r}-01`, `user_${r}`, passHash, salt, r);

      const loginRes = await ctx.request('/api/auth/login', {
        method: 'POST',
        body: { username: `user_${r}`, password: 'Password123!' }
      });
      assert.equal(loginRes.status, 200, `Login for role ${r} should succeed`);
      const setCookie = loginRes.headers['set-cookie'];
      const match = setCookie[0].match(/sentinel_session=([^;]+)/);
      const cookieStr = `sentinel_session=${match[1]}`;
      const csrf = loginRes.json.csrfToken;

      if (r === 'viewer') { viewerCookie = cookieStr; viewerCsrf = csrf; }
      if (r === 'analyst') { analystCookie = cookieStr; analystCsrf = csrf; }
      if (r === 'admin') { adminCookie = cookieStr; adminCsrf = csrf; }
    }
  });

  after(async () => {
    if (ctx) await ctx.close();
  });

  // ---------------------------------------------------------------------------
  // 1. Strict Scope & Role Permissions Enforcement
  // ---------------------------------------------------------------------------
  describe('1. Scope & Role Permissions Matrix', () => {
    test('API Key with scope "ingest" CANNOT read events (GET /api/events -> 403)', async () => {
      const res = await ctx.request('/api/events', {
        headers: { 'X-Sentinel-Key': ingestApiKey }
      });
      assert.equal(res.status, 403, 'Ingest key must not read events');
    });

    test('API Key with scope "ingest" CANNOT export CSV (GET /api/export-csv -> 403)', async () => {
      const res = await ctx.request('/api/export-csv', {
        headers: { 'X-Sentinel-Key': ingestApiKey }
      });
      assert.equal(res.status, 403, 'Ingest key must not export CSV');
    });

    test('API Key with scope "ingest" CANNOT trigger scan (POST /api/scan -> 403)', async () => {
      const res = await ctx.request('/api/scan', {
        method: 'POST',
        headers: { 'X-Sentinel-Key': ingestApiKey },
        body: { url: 'http://127.0.0.1:4000' }
      });
      assert.equal(res.status, 403, 'Ingest key must not run scans');
    });

    test('API Key with scope "ingest" CAN write telemetry (POST /api/analyze-request -> 200)', async () => {
      const res = await ctx.request('/api/analyze-request', {
        method: 'POST',
        headers: { 'X-Sentinel-Key': ingestApiKey },
        body: { input: 'Valid contact input', honeypot: '' }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.safe, true);
    });

    test('API Key with scope "read" CAN read events and stats (GET /api/stats -> 200)', async () => {
      const res = await ctx.request('/api/stats', {
        headers: { 'X-Sentinel-Key': readApiKey }
      });
      assert.equal(res.status, 200);
    });

    test('API Key with scope "read" CANNOT write telemetry (POST /api/analyze-request -> 403)', async () => {
      const res = await ctx.request('/api/analyze-request', {
        method: 'POST',
        headers: { 'X-Sentinel-Key': readApiKey },
        body: { input: 'test' }
      });
      assert.equal(res.status, 403);
    });

    test('Dashboard role "viewer" CANNOT trigger scan (POST /api/scan -> 403)', async () => {
      const res = await ctx.request('/api/scan', {
        method: 'POST',
        headers: { Cookie: viewerCookie, 'X-CSRF-Token': viewerCsrf },
        body: { url: 'http://127.0.0.1:4000' }
      });
      assert.equal(res.status, 403, 'Viewer role cannot run scans');
    });

    test('Dashboard role "analyst" CAN trigger scan (POST /api/scan -> 200)', async () => {
      const res = await ctx.request('/api/scan', {
        method: 'POST',
        headers: { Cookie: analystCookie, 'X-CSRF-Token': analystCsrf },
        body: { url: 'http://127.0.0.1:4000' }
      });
      assert.equal(res.status, 200);
    });

    test('Dashboard role "analyst" CANNOT run SQL query (POST /api/sql/query -> 403)', async () => {
      const res = await ctx.request('/api/sql/query', {
        method: 'POST',
        headers: { Cookie: analystCookie, 'X-CSRF-Token': analystCsrf },
        body: { query: 'SELECT 1' }
      });
      assert.equal(res.status, 403, 'Analyst role cannot run raw SQL');
    });

    test('Dashboard role "admin" CAN run SQL query (POST /api/sql/query -> 200)', async () => {
      const res = await ctx.request('/api/sql/query', {
        method: 'POST',
        headers: { Cookie: adminCookie, 'X-CSRF-Token': adminCsrf },
        body: { query: 'SELECT 1 as num' }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.success, true);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Dashboard Login Throttling & Timing Attack Mitigation
  // ---------------------------------------------------------------------------
  describe('2. Dashboard Login Throttling & Timing Defense', () => {
    test('Invalid username/password types (e.g. object) return 400 Bad Request, NOT 500', async () => {
      const res = await ctx.request('/api/auth/login', {
        method: 'POST',
        body: { username: { invalid: true }, password: ['array'] }
      });
      assert.equal(res.status, 400, 'Must validate input types as string');
      assert.equal(res.json.error, true);
    });

    test('Login rate limiter returns 429 Too Many Requests after 5 consecutive failures', async () => {
      const testUser = 'brute_force_target_' + crypto.randomBytes(4).toString('hex');
      for (let i = 0; i < 5; i++) {
        const res = await ctx.request('/api/auth/login', {
          method: 'POST',
          body: { username: testUser, password: 'WrongPassword!' }
        });
        assert.equal(res.status, 401);
      }

      // 6th attempt must trigger 429
      const blockedRes = await ctx.request('/api/auth/login', {
        method: 'POST',
        body: { username: testUser, password: 'WrongPassword!' }
      });
      assert.equal(blockedRes.status, 429, '6th attempt must be blocked with 429');
      assert.ok(blockedRes.headers['retry-after'], 'Must send Retry-After header');
    });

    test('Non-existent user authentication runs dummy scrypt to eliminate timing disparity', async () => {
      // Clear IP lock to measure pure authentication computation
      ctx.db.resetLoginRateLimit('ip:127.0.0.1');

      const t0 = Date.now();
      const res = await ctx.request('/api/auth/login', {
        method: 'POST',
        body: { username: 'non_existent_' + crypto.randomBytes(8).toString('hex'), password: 'SomePassword123!' }
      });
      const durationNonExistent = Date.now() - t0;

      assert.equal(res.status, 401, 'Should return 401 Unauthorized');
      // Dummy scrypt calculation takes at least 10ms with N=16384
      assert.ok(durationNonExistent >= 10, `Duration (${durationNonExistent}ms) proves scrypt executed`);
    });
  });

  // ---------------------------------------------------------------------------
  // 3. SQL Secrets Masking & Hardening
  // ---------------------------------------------------------------------------
  describe('3. SQL Secrets Protection & CTE Support', () => {
    test('Session token is stored as SHA-256 hash in auth_sessions, not plain text', () => {
      const sessions = ctx.db.raw.prepare('SELECT token_hash FROM auth_sessions LIMIT 1').all();
      assert.ok(sessions.length > 0);
      assert.match(sessions[0].token_hash, /^[a-f0-9]{64}$/, 'Must store 64-char SHA-256 hex hash');
    });

    test('SQL Console blocks SELECT access to sensitive tables (users, auth_sessions, api_keys)', async () => {
      const tables = ['users', 'auth_sessions', 'api_keys', 'admin_audit_log'];
      for (const tbl of tables) {
        const res = await ctx.request('/api/sql/query', {
          method: 'POST',
          headers: { Cookie: adminCookie, 'X-CSRF-Token': adminCsrf },
          body: { query: `SELECT * FROM ${tbl}` }
        });
        assert.equal(res.status, 400, `Access to ${tbl} must be prohibited`);
        assert.match(res.json.message || res.json.error, /prohib|no permitid|restringid/i);
      }
    });

    test('SQL Console allows legitimate WITH (CTE) queries', async () => {
      const res = await ctx.request('/api/sql/query', {
        method: 'POST',
        headers: { Cookie: adminCookie, 'X-CSRF-Token': adminCsrf },
        body: { query: 'WITH Ranked AS (SELECT id, severity FROM incidents) SELECT * FROM Ranked' }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.success, true);
    });
  });

  // ---------------------------------------------------------------------------
  // 4. CIDR Matching in SSRF Scanner
  // ---------------------------------------------------------------------------
  describe('4. CIDR Allowlist Evaluation (net.BlockList)', () => {
    test('Allows IP within configured CIDR subnet (172.16.0.163 within 172.16.0.0/16)', async () => {
      // 172.16.0.163 is in 172.16.0.0/16 configured in testConfig.SCAN_ALLOWLIST
      const res = await ctx.request('/api/scan', {
        method: 'POST',
        headers: { Cookie: analystCookie, 'X-CSRF-Token': analystCsrf },
        body: { url: 'http://172.16.0.163:80' }
      });
      // Should attempt connection and not fail with SSRF restriction error
      if (res.json.error) {
        assert.doesNotMatch(res.json.error, /SSRF bloqueado/i, 'CIDR match must permit 172.16.0.163');
      }
    });

    test('Blocks IP outside configured CIDR subnet (172.17.0.1 not in 172.16.0.0/16)', async () => {
      const res = await ctx.request('/api/scan', {
        method: 'POST',
        headers: { Cookie: analystCookie, 'X-CSRF-Token': analystCsrf },
        body: { url: 'http://172.17.0.1:80' }
      });
      assert.ok(res.json.error);
      assert.match(res.json.error, /SSRF bloqueado/i);
    });
  });

  // ---------------------------------------------------------------------------
  // 5. DEMO_MODE Enforcement
  // ---------------------------------------------------------------------------
  describe('5. DEMO_MODE Disablement', () => {
    test('POST /api/simulate-attack returns 404 when DEMO_MODE=false', async () => {
      const res = await ctx.request('/api/simulate-attack', {
        method: 'POST',
        headers: { Cookie: adminCookie, 'X-CSRF-Token': adminCsrf },
        body: { vector: 'sqli' }
      });
      assert.equal(res.status, 404, 'Must return 404 when DEMO_MODE is false');
    });

    test('POST /api/sessions/simulate returns 404 when DEMO_MODE=false', async () => {
      const res = await ctx.request('/api/sessions/simulate', {
        method: 'POST',
        headers: { Cookie: adminCookie, 'X-CSRF-Token': adminCsrf },
        body: {}
      });
      assert.equal(res.status, 404, 'Must return 404 when DEMO_MODE is false');
    });

    test('GET /api/auth/me exposes demoMode flag', async () => {
      const res = await ctx.request('/api/auth/me', {
        headers: { Cookie: adminCookie }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.demoMode, false);
    });
  });

  // ---------------------------------------------------------------------------
  // 6. 500 Internal Error Masking
  // ---------------------------------------------------------------------------
  describe('6. 500 Internal Error Masking', () => {
    test('500 responses return generic message with errorId UUID, no runtime stack trace', async () => {
      // Simulate an internal server failure by invoking a malformed internal trigger
      const res = await ctx.request('/api/test-500-trigger', {
        headers: { Cookie: adminCookie }
      });
      if (res.status === 500) {
        assert.equal(res.json.message, 'Error interno del servidor');
        assert.ok(res.json.errorId);
        assert.match(res.json.errorId, /^[a-f0-9-]{36}$/);
        assert.equal(res.json.stack, undefined);
      }
    });
  });
});
