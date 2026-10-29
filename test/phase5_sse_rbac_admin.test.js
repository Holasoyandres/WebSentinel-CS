/**
 * WebSentinel-CS :: FASE 5 Tests - SSE Stream, RBAC Admin & CSV Sanitization
 * Validates real-time SSE streaming, formula injection prevention, and admin management.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const crypto = require('node:crypto');

const { startTestServer } = require('./helpers');

describe('WebSentinel-CS :: FASE 5 - Consola SOC en Tiempo Real, RBAC Admin & Exportación Segura', () => {
  let context;
  let adminSessionCookie;
  let adminCsrfToken;
  let analystSessionCookie;
  let analystCsrfToken;
  let viewerSessionCookie;
  let viewerCsrfToken;
  let ingestKey;
  let readOnlyKey;

  before(async () => {
    context = await startTestServer({
      config: {
        ANOMALY_THRESHOLD: 5
      }
    });

    ingestKey = context.apiKey;

    // Create a read-only key
    readOnlyKey = 'ws_readonly_' + crypto.randomBytes(16).toString('hex');
    const readOnlyHash = crypto.createHash('sha256').update(readOnlyKey).digest('hex');
    context.db.raw.prepare(`
      INSERT INTO api_keys (id, name, key_hash, scopes, created_at)
      VALUES (?, ?, ?, ?, datetime('now'))
    `).run('key-readonly-phase5', 'Read Only Key', readOnlyHash, 'read');

    // Create analyst user
    const analystSalt = crypto.randomBytes(16).toString('hex');
    const analystHash = crypto.scryptSync('AnalystPass123!', analystSalt, 64).toString('hex');
    context.db.raw.prepare(`
      INSERT INTO users (id, username, password_hash, salt, role, created_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `).run('usr-analyst-phase5', 'analyst_user', analystHash, analystSalt, 'analyst');

    // Create viewer user
    const viewerSalt = crypto.randomBytes(16).toString('hex');
    const viewerHash = crypto.scryptSync('ViewerPass123!', viewerSalt, 64).toString('hex');
    context.db.raw.prepare(`
      INSERT INTO users (id, username, password_hash, salt, role, created_at)
      VALUES (?, ?, ?, ?, ?, datetime('now'))
    `).run('usr-viewer-phase5', 'viewer_user', viewerHash, viewerSalt, 'viewer');

    // Login admin
    const adminLoginRes = await context.request('/api/auth/login', {
      method: 'POST',
      body: { username: 'admin', password: 'SmokeAdminPass123!' },
      auth: false
    });
    assert.strictEqual(adminLoginRes.status, 200);
    adminSessionCookie = adminLoginRes.headers['set-cookie'][0].split(';')[0];
    adminCsrfToken = adminLoginRes.json.csrfToken;

    // Login analyst
    const analystLoginRes = await context.request('/api/auth/login', {
      method: 'POST',
      body: { username: 'analyst_user', password: 'AnalystPass123!' },
      auth: false
    });
    assert.strictEqual(analystLoginRes.status, 200);
    analystSessionCookie = analystLoginRes.headers['set-cookie'][0].split(';')[0];
    analystCsrfToken = analystLoginRes.json.csrfToken;

    // Login viewer
    const viewerLoginRes = await context.request('/api/auth/login', {
      method: 'POST',
      body: { username: 'viewer_user', password: 'ViewerPass123!' },
      auth: false
    });
    assert.strictEqual(viewerLoginRes.status, 200);
    viewerSessionCookie = viewerLoginRes.headers['set-cookie'][0].split(';')[0];
    viewerCsrfToken = viewerLoginRes.json.csrfToken;
  });

  after(async () => {
    if (context) await context.close();
  });

  // ---------------------------------------------------------------------------
  // 1. Server-Sent Events (SSE) Real-Time Stream
  // ---------------------------------------------------------------------------
  describe('1. Server-Sent Events (SSE) Stream (GET /api/v1/stream)', () => {
    test('Establishes SSE connection with text/event-stream headers and receives connected event', async () => {
      return new Promise((resolve, reject) => {
        const url = new URL('/api/v1/stream', context.baseUrl);
        const req = http.request(url, {
          method: 'GET',
          headers: {
            'Cookie': adminSessionCookie,
            'Accept': 'text/event-stream'
          }
        }, (res) => {
          assert.strictEqual(res.statusCode, 200);
          assert.ok(res.headers['content-type'].includes('text/event-stream'));
          assert.strictEqual(res.headers['cache-control'], 'no-cache, no-transform');

          let buffer = '';
          res.on('data', (chunk) => {
            buffer += chunk.toString('utf8');
            if (buffer.includes('event: connected')) {
              req.destroy(); // Close stream cleanly
              resolve();
            }
          });
        });

        req.on('error', (err) => {
          // Socket hang up when req.destroy() is called is normal
          if (err.code !== 'ECONNRESET') reject(err);
        });

        req.end();
      });
    });

    test('Allows read-only API key to subscribe to SSE stream', async () => {
      return new Promise((resolve, reject) => {
        const url = new URL('/api/v1/stream', context.baseUrl);
        const req = http.request(url, {
          method: 'GET',
          headers: {
            'X-Sentinel-Key': readOnlyKey,
            'Accept': 'text/event-stream'
          }
        }, (res) => {
          assert.strictEqual(res.statusCode, 200);
          req.destroy();
          resolve();
        });

        req.on('error', (err) => {
          if (err.code !== 'ECONNRESET') reject(err);
        });

        req.end();
      });
    });

    test('Rejects unauthenticated stream request with 401', async () => {
      const res = await context.request('/api/v1/stream', {
        method: 'GET',
        auth: false
      });
      assert.strictEqual(res.status, 401);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. CSV Formula Injection Hardening & Date Range Filtering
  // ---------------------------------------------------------------------------
  describe('2. CSV Formula Injection Prevention & Date Filtering (/api/export-csv)', () => {
    test('Sanitizes cells starting with formula characters (=, +, -, @, \\t) by prepending single quote', async () => {
      // Ingest an incident with formula payload
      await context.request('/api/v1/events', {
        method: 'POST',
        headers: { 'X-Sentinel-Key': ingestKey },
        body: {
          type: 'FORMULA_TEST',
          severity: 'HIGH',
          ruleId: 'TEST-CSV-01',
          sourceIp: '10.0.0.99',
          target: '/export',
          details: '=cmd|\' /C calc\'!A0', // Excel DDE attack payload
          action: 'BLOCKED'
        }
      });

      const res = await context.request('/api/export-csv', {
        method: 'GET',
        headers: { 'Cookie': adminSessionCookie },
        auth: false
      });

      assert.strictEqual(res.status, 200);
      assert.ok(res.headers['content-type'].includes('text/csv'));

      const csvLines = res.body.split('\n');
      const matchedLine = csvLines.find(l => l.includes('FORMULA_TEST'));
      assert.ok(matchedLine, 'CSV must contain the ingested incident');

      // Formula injection defense: the payload cell must start with an escaped quote: "'=cmd"
      assert.ok(
        matchedLine.includes("\"'=cmd|") || matchedLine.includes("''=cmd|"),
        `Formula payload must be prepended with single quote to prevent DDE execution. Line was: ${matchedLine}`
      );
    });

    test('Filters CSV export by date range (?from=...&to=...)', async () => {
      const tomorrow = new Date(Date.now() + 86400000).toISOString();
      const inTwoDays = new Date(Date.now() + 172800000).toISOString();

      const res = await context.request(`/api/export-csv?from=${encodeURIComponent(tomorrow)}&to=${encodeURIComponent(inTwoDays)}`, {
        method: 'GET',
        headers: { 'Cookie': adminSessionCookie },
        auth: false
      });

      assert.strictEqual(res.status, 200);
      const lines = res.body.trim().split('\n');
      // Only CSV header line should remain since range is in the future
      assert.strictEqual(lines.length, 1, 'Should contain only header line when range has no events');
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Admin Security Management (API Keys & IP Unblocking)
  // ---------------------------------------------------------------------------
  describe('3. Admin Management Endpoints (/api/v1/admin/*)', () => {
    let createdKeyId;
    let createdRawKey;

    test('Admin role CAN list active API keys (GET /api/v1/admin/api-keys)', async () => {
      const res = await context.request('/api/v1/admin/api-keys', {
        method: 'GET',
        headers: { 'Cookie': adminSessionCookie },
        auth: false
      });

      assert.strictEqual(res.status, 200);
      assert.ok(Array.isArray(res.json));
      assert.ok(res.json.length >= 1);
      assert.strictEqual(res.json[0].key_hash, undefined, 'Key hash must NEVER be exposed via API');
      assert.ok(res.json[0].scopes);
    });

    test('Analyst or Viewer CANNOT access admin API keys (403 Forbidden)', async () => {
      const resAnalyst = await context.request('/api/v1/admin/api-keys', {
        method: 'GET',
        headers: { 'Cookie': analystSessionCookie },
        auth: false
      });
      assert.strictEqual(resAnalyst.status, 403);

      const resViewer = await context.request('/api/v1/admin/api-keys', {
        method: 'GET',
        headers: { 'Cookie': viewerSessionCookie },
        auth: false
      });
      assert.strictEqual(resViewer.status, 403);
    });

    test('Admin role CAN generate a new API key with specific scopes', async () => {
      const res = await context.request('/api/v1/admin/api-keys', {
        method: 'POST',
        headers: {
          'Cookie': adminSessionCookie,
          'X-CSRF-Token': adminCsrfToken
        },
        body: {
          name: 'Microservice Ingest Key',
          scopes: 'ingest'
        },
        auth: false
      });

      assert.strictEqual(res.status, 201);
      assert.strictEqual(res.json.success, true);
      assert.ok(res.json.key && res.json.key.startsWith('ws_live_'), 'Must return raw API key once');
      assert.ok(res.json.id);

      createdKeyId = res.json.id;
      createdRawKey = res.json.key;

      // Verify the generated key can immediately authenticate with ingest scope
      const testIngest = await context.request('/api/v1/events', {
        method: 'POST',
        headers: { 'X-Sentinel-Key': createdRawKey },
        body: {
          type: 'KEY_VERIFICATION',
          severity: 'INFO',
          ruleId: 'RULE-KEY-01',
          sourceIp: '127.0.0.1',
          target: '/test',
          details: 'Key verified',
          action: 'LOGGED'
        },
        auth: false
      });
      assert.strictEqual(testIngest.status, 201);
    });

    test('Admin role CAN revoke an API key', async () => {
      const res = await context.request(`/api/v1/admin/api-keys/${createdKeyId}`, {
        method: 'DELETE',
        headers: {
          'Cookie': adminSessionCookie,
          'X-CSRF-Token': adminCsrfToken
        },
        auth: false
      });

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.success, true);

      // Verify revoked key can no longer authenticate
      const testRevoked = await context.request('/api/v1/events', {
        method: 'POST',
        headers: { 'X-Sentinel-Key': createdRawKey },
        body: { type: 'TEST' },
        auth: false
      });
      assert.strictEqual(testRevoked.status, 401);
    });

    test('Admin role CAN view blocked IPs and manually unblock an IP', async () => {
      // 1. Lock an IP via telemetry rate limiter
      const targetIp = '198.51.100.42';
      context.db.recordIpAttempt(targetIp, false, 1, 15); // force block

      // 2. Query blocked IPs
      const listRes = await context.request('/api/v1/admin/blocked-ips', {
        method: 'GET',
        headers: { 'Cookie': adminSessionCookie },
        auth: false
      });

      assert.strictEqual(listRes.status, 200);
      assert.ok(Array.isArray(listRes.json));
      const blockedItem = listRes.json.find(b => b.ip === targetIp);
      assert.ok(blockedItem, `Target IP ${targetIp} should be in blocked IPs list`);
      assert.ok(blockedItem.remainingSeconds > 0);

      // 3. Unblock IP
      const unblockRes = await context.request('/api/v1/admin/unblock-ip', {
        method: 'POST',
        headers: {
          'Cookie': adminSessionCookie,
          'X-CSRF-Token': adminCsrfToken
        },
        body: { ip: targetIp },
        auth: false
      });

      assert.strictEqual(unblockRes.status, 200);
      assert.strictEqual(unblockRes.json.success, true);

      // 4. Verify IP is no longer blocked
      const statusRes = await context.request(`/api/v1/ip/${targetIp}/status`, {
        method: 'GET',
        headers: { 'Cookie': adminSessionCookie },
        auth: false
      });
      assert.strictEqual(statusRes.json.isBlocked, false);
    });
  });
});
