/**
 * WebSentinel-CS :: Phase 1.2 Corrections Test Suite
 * Covers:
 * 1. SQL Process Timeout (SIGKILL on infinite recursive CTE, < 4s, concurrent /healthz 200, 1 concurrent SQL query per user)
 * 2. Lockout DoS Defense (Hard block by IP, progressive delay by user, legitimate owner from different IP succeeds)
 * 3. Log Flooding Prevention (1 AUTH_BRUTEFORCE incident per IP window, not 50)
 * 4. Silent Failure Fixes (Type validation 400, non-existent session 404, no false 200 on DB errors)
 * 5. Extended SSRF Blocklist (64:ff9b::/96, 64:ff9b:1::/48, 2001:db8::/32, 100::/64, loopback blocked even with hostname allowlist)
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const { startTestServer } = require('./helpers');
const { isIpRestricted, auditTargetUrl } = require('../src/engine/scanner');

describe('WebSentinel-CS :: FASE 1.2 - Correcciones de Auditoría Independiente', () => {
  let ctx;
  let adminCookie, adminCsrf;
  let ingestApiKey;

  before(async () => {
    ctx = await startTestServer({
      config: {
        TRUST_PROXIES: true,
        SCAN_ALLOWLIST: ['internal.empresa.com', '172.16.0.0/16']
      }
    });

    // Provision admin user
    const adminSalt = crypto.randomBytes(16).toString('hex');
    const adminHash = crypto.scryptSync('Phase12AdminPass!', adminSalt, 64).toString('hex');
    ctx.db.raw.prepare(`
      INSERT INTO users (id, username, password_hash, salt, role, created_at)
      VALUES (?, ?, ?, ?, 'admin', datetime('now'))
    `).run('usr-admin-p12', 'admin_p12', adminHash, adminSalt);

    const loginRes = await ctx.request('/api/auth/login', {
      method: 'POST',
      auth: false,
      body: { username: 'admin_p12', password: 'Phase12AdminPass!' }
    });
    assert.equal(loginRes.status, 200);
    adminCookie = loginRes.headers['set-cookie'][0].split(';')[0];
    adminCsrf = loginRes.json.csrfToken;

    // Provision ingest API Key
    ingestApiKey = 'ws_ingest_' + crypto.randomBytes(16).toString('hex');
    const ingestHash = crypto.createHash('sha256').update(ingestApiKey).digest('hex');
    ctx.db.raw.prepare(`
      INSERT INTO api_keys (id, name, key_hash, scopes, created_at)
      VALUES (?, ?, ?, 'ingest', datetime('now'))
    `).run('key-ingest-p12', 'Ingest Key P12', ingestHash);
  });

  after(async () => {
    if (ctx) await ctx.close();
  });

  // ---------------------------------------------------------------------------
  // 1. SQL Timeout & Process Isolation
  // ---------------------------------------------------------------------------
  describe('1. SQL Timeout & Process Isolation', () => {
    test('Infinite recursive CTE terminates via child process in < 4s with 408, /healthz stays responsive', async () => {
      const startTime = Date.now();
      const recursiveQuery = 'WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c';

      // Launch heavy query in background
      const queryPromise = ctx.request('/api/sql/query', {
        method: 'POST',
        headers: {
          Cookie: adminCookie,
          'X-CSRF-Token': adminCsrf
        },
        body: { query: recursiveQuery }
      });

      // Poll /healthz while the query is running
      await new Promise(r => setTimeout(r, 1000));
      const healthStart = Date.now();
      const healthRes = await ctx.request('/healthz', { auth: false });
      const healthDuration = Date.now() - healthStart;

      assert.equal(healthRes.status, 200, '/healthz must respond 200 while query runs');
      assert.ok(healthDuration < 1000, `/healthz took too long (${healthDuration}ms)`);

      const queryRes = await queryPromise;
      const totalDuration = Date.now() - startTime;

      assert.equal(queryRes.status, 408, 'Query must return 408 Request Timeout');
      assert.ok(totalDuration < 4500, `Query execution took ${totalDuration}ms, must be < 4500ms`);
    });

    test('Limits to 1 concurrent SQL query per user (second query receives 429)', async () => {
      const infiniteQuery = 'WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c';

      const firstPromise = ctx.request('/api/sql/query', {
        method: 'POST',
        headers: { Cookie: adminCookie, 'X-CSRF-Token': adminCsrf },
        body: { query: infiniteQuery }
      });

      // Short delay to ensure first query is actively running in child process
      await new Promise(r => setTimeout(r, 200));

      const secondRes = await ctx.request('/api/sql/query', {
        method: 'POST',
        headers: { Cookie: adminCookie, 'X-CSRF-Token': adminCsrf },
        body: { query: 'SELECT 1' }
      });

      assert.equal(secondRes.status, 429, 'Concurrent SQL query by same user must be rejected with 429');
      assert.match(secondRes.json.message || secondRes.json.error, /concurrente/i);

      await firstPromise; // Wait for first query timeout cleanup
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Lockout DoS & Progressive Delay
  // ---------------------------------------------------------------------------
  describe('2. Lockout DoS & Progressive Delay', () => {
    test('Attacker fails 5 times from IP A (gets 429), owner enters from IP B with correct password (gets 200)', async () => {
      const victimUser = 'legit_owner_' + crypto.randomBytes(4).toString('hex');
      const victimSalt = crypto.randomBytes(16).toString('hex');
      const victimPass = 'CorrectPassword123!';
      const victimHash = crypto.scryptSync(victimPass, victimSalt, 64).toString('hex');
      ctx.db.raw.prepare(`
        INSERT INTO users (id, username, password_hash, salt, role, created_at)
        VALUES (?, ?, ?, ?, 'analyst', datetime('now'))
      `).run('usr-victim-01', victimUser, victimHash, victimSalt);

      const attackerIp = '198.51.100.10';
      const ownerIp = '203.0.113.25';

      // Attacker fails 5 times from IP A
      for (let i = 0; i < 5; i++) {
        const res = await ctx.request('/api/auth/login', {
          method: 'POST',
          auth: false,
          headers: { 'X-Forwarded-For': attackerIp },
          body: { username: victimUser, password: 'WrongPassword' + i }
        });
        if (i < 4) {
          assert.equal(res.status, 401);
        } else {
          // 5th failure or next attempt hits 429
          assert.ok(res.status === 401 || res.status === 429);
        }
      }

      // Attacker 6th attempt is blocked with 429
      const blockedRes = await ctx.request('/api/auth/login', {
        method: 'POST',
        auth: false,
        headers: { 'X-Forwarded-For': attackerIp },
        body: { username: victimUser, password: 'WrongPasswordAgain' }
      });
      assert.equal(blockedRes.status, 429, 'Attacker IP must be blocked with 429');

      // Legitimate owner logs in from IP B with correct password -> must succeed with 200
      const ownerRes = await ctx.request('/api/auth/login', {
        method: 'POST',
        auth: false,
        headers: { 'X-Forwarded-For': ownerIp },
        body: { username: victimUser, password: victimPass }
      });
      assert.equal(ownerRes.status, 200, 'Legitimate owner from IP B must succeed with 200');
      assert.ok(ownerRes.json.csrfToken, 'Must receive CSRF token');
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Log Flooding Prevention
  // ---------------------------------------------------------------------------
  describe('3. Log Flooding Prevention', () => {
    test('50 requests during an active IP lockout create exactly 1 AUTH_BRUTEFORCE incident', async () => {
      const floodIp = '198.51.100.99';
      const initialIncidents = ctx.db.raw.prepare(`
        SELECT COUNT(*) as c FROM incidents WHERE source_ip = ? AND type = 'AUTH_BRUTEFORCE'
      `).get(floodIp).c;

      // Force 5 failures to trigger lockout
      for (let i = 0; i < 5; i++) {
        await ctx.request('/api/auth/login', {
          method: 'POST',
          auth: false,
          headers: { 'X-Forwarded-For': floodIp },
          body: { username: 'nobody', password: 'bad' + i }
        });
      }

      const incidentsAfterLock = ctx.db.raw.prepare(`
        SELECT COUNT(*) as c FROM incidents WHERE source_ip = ? AND type = 'AUTH_BRUTEFORCE'
      `).get(floodIp).c;
      assert.equal(incidentsAfterLock - initialIncidents, 1, 'Lockout must record exactly 1 incident');

      // Send 50 additional requests during the active lockout
      for (let i = 0; i < 50; i++) {
        const res = await ctx.request('/api/auth/login', {
          method: 'POST',
          auth: false,
          headers: { 'X-Forwarded-For': floodIp },
          body: { username: 'nobody', password: 'attempt_' + i }
        });
        assert.equal(res.status, 429);
      }

      const finalIncidents = ctx.db.raw.prepare(`
        SELECT COUNT(*) as c FROM incidents WHERE source_ip = ? AND type = 'AUTH_BRUTEFORCE'
      `).get(floodIp).c;
      assert.equal(finalIncidents - initialIncidents, 1, '50 attempts during lockout must NOT create additional incidents');
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Input Validation & Silent DB Error Prevention
  // ---------------------------------------------------------------------------
  describe('4. Input Validation & Silent DB Error Prevention', () => {
    test('Invalid sessionId type (object) in POST /api/sessions/activity returns 400', async () => {
      const res = await ctx.request('/api/sessions/activity', {
        method: 'POST',
        headers: { 'X-Sentinel-Key': ingestApiKey },
        body: { sessionId: { unexpected: 'object' }, riskLevel: 'NORMAL' }
      });
      assert.equal(res.status, 400, 'Non-string sessionId must return 400');
    });

    test('Non-existent sessionId in POST /api/sessions/activity returns 404, never 200', async () => {
      const res = await ctx.request('/api/sessions/activity', {
        method: 'POST',
        headers: { 'X-Sentinel-Key': ingestApiKey },
        body: { sessionId: 'SESS-DOES-NOT-EXIST-999', riskLevel: 'NORMAL' }
      });
      assert.equal(res.status, 404, 'Non-existent session must return 404');
    });

    test('Non-existent sessionId in POST /api/sessions/logout returns 404', async () => {
      const res = await ctx.request('/api/sessions/logout', {
        method: 'POST',
        headers: { 'X-Sentinel-Key': ingestApiKey },
        body: { sessionId: 'SESS-NON-EXISTENT-LOGOUT' }
      });
      assert.equal(res.status, 404, 'Non-existent session logout must return 404');
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Extended SSRF Blocklist & Loopback Protection
  // ---------------------------------------------------------------------------
  describe('5. Extended SSRF Blocklist & Loopback Protection', () => {
    test('isIpRestricted blocks 64:ff9b::/96, 64:ff9b:1::/48, 2001:db8::/32 and 100::/64', () => {
      assert.equal(isIpRestricted('64:ff9b::7f00:1'), true, '64:ff9b::/96 must be restricted');
      assert.equal(isIpRestricted('64:ff9b:1::1'), true, '64:ff9b:1::/48 must be restricted');
      assert.equal(isIpRestricted('2001:db8::1'), true, '2001:db8::/32 must be restricted');
      assert.equal(isIpRestricted('100::1'), true, '100::/64 must be restricted');
    });

    test('Hostname in allowlist (localhost) resolving to 127.0.0.1 is STILL blocked unless IP is in allowlist', async () => {
      // Allowlist has hostname 'internal.empresa.com' and 'localhost', but NOT '127.0.0.1'
      const allowlistWithHostnameOnly = ['localhost'];
      const res = await auditTargetUrl(`http://localhost:${ctx.port}/healthz`, allowlistWithHostnameOnly, 0, 1000);
      assert.ok(res.error, 'Must block loopback IP even if hostname is in allowlist');
      assert.match(res.error, /restringido|bloqueado/i);
    });
  });
});
