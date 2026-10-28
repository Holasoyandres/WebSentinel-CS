/**
 * WebSentinel-CS :: Smoke Test Suite
 * Native node:test runner for all endpoints and core components
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startTestServer } = require('./helpers');

describe('WebSentinel-CS :: Smoke Tests (FASE 0)', () => {
  let app;

  before(async () => {
    app = await startTestServer();
  });

  after(async () => {
    await app.close();
  });

  describe('1. Static File Assets', () => {
    it('GET / should serve index.html with 200 OK', async () => {
      const res = await app.request('/');
      assert.equal(res.status, 200);
      assert.match(res.headers['content-type'], /text\/html/);
      assert.match(res.body, /WEBSENTINEL/);
    });

    it('GET /styles.css should serve CSS stylesheet with 200 OK', async () => {
      const res = await app.request('/styles.css');
      assert.equal(res.status, 200);
      assert.match(res.headers['content-type'], /text\/css/);
    });

    it('GET /app.js should serve frontend telemetry script with 200 OK', async () => {
      const res = await app.request('/app.js');
      assert.equal(res.status, 200);
      assert.match(res.headers['content-type'], /application\/javascript/);
    });

    it('GET /non-existent-file.xyz should return 404', async () => {
      const res = await app.request('/non-existent-file.xyz');
      assert.equal(res.status, 404);
    });
  });

  describe('2. Telemetry & Core Metrics API', () => {
    it('GET /api/stats should return operational counters and status', async () => {
      const res = await app.request('/api/stats');
      assert.equal(res.status, 200);
      assert.ok(res.json);
      assert.equal(res.json.engineStatus, 'ACTIVE_ARMED');
      assert.equal(res.json.storageEngine, 'SQLITE_PERSISTENT');
      assert.equal(typeof res.json.totalPersistedIncidents, 'number');
    });

    it('GET /api/events should return stored incidents array', async () => {
      const res = await app.request('/api/events');
      assert.equal(res.status, 200);
      assert.ok(Array.isArray(res.json));
      assert.ok(res.json.length >= 1); // Includes CORE_INITIALIZED event
    });

    it('GET /api/export-csv should return structured CSV file', async () => {
      const res = await app.request('/api/export-csv');
      assert.equal(res.status, 200);
      assert.match(res.headers['content-type'], /text\/csv/);
      assert.match(res.body, /^ID,TIMESTAMP,SEVERITY/);
    });
  });

  describe('3. SQL Forensics Engine', () => {
    it('GET /api/sql/summary should return aggregated SQL analytics', async () => {
      const res = await app.request('/api/sql/summary');
      assert.equal(res.status, 200);
      assert.ok(res.json);
      assert.ok('totalIncidents' in res.json);
      assert.ok(Array.isArray(res.json.topIps));
      assert.ok(Array.isArray(res.json.severityDistribution));
    });

    it('POST /api/sql/query should execute read-only SELECT query', async () => {
      const res = await app.request('/api/sql/query', {
        method: 'POST',
        body: { query: 'SELECT severity, count(*) as count FROM incidents GROUP BY severity' }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.success, true);
      assert.ok(Array.isArray(res.json.rows));
    });

    it('POST /api/sql/query should reject non-SELECT statements', async () => {
      const res = await app.request('/api/sql/query', {
        method: 'POST',
        body: { query: 'DROP TABLE incidents;' }
      });
      assert.equal(res.status, 400);
      assert.equal(res.json.success, false);
      assert.match(res.json.error, /Solo se permiten consultas SQL de lectura/);
    });
  });

  describe('4. WAF Payload Inspection', () => {
    it('POST /api/analyze-request should accept clean benign input', async () => {
      const res = await app.request('/api/analyze-request', {
        method: 'POST',
        body: { input: 'Formulario de contacto regular', honeypot: '' }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.safe, true);
      assert.equal(res.json.threatCount, 0);
    });

    it('POST /api/analyze-request should detect SQL Injection (Tautology)', async () => {
      const res = await app.request('/api/analyze-request', {
        method: 'POST',
        body: { input: "' OR 1=1 --", honeypot: '' }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.safe, false);
      assert.ok(res.json.threatCount >= 1);
      assert.equal(res.json.threats[0].severity, 'CRITICAL');
    });

    it('POST /api/analyze-request should detect XSS tag injection', async () => {
      const res = await app.request('/api/analyze-request', {
        method: 'POST',
        body: { input: '<script>alert(1)</script>', honeypot: '' }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.safe, false);
      assert.equal(res.json.threats[0].severity, 'HIGH');
    });

    it('POST /api/analyze-request should trigger bot honeypot detection', async () => {
      const res = await app.request('/api/analyze-request', {
        method: 'POST',
        body: { input: 'texto', honeypot: 'crawler_bot_signature' }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.safe, false);
      assert.equal(res.json.threats[0].ruleId, 'SIG-BOT-001');
    });
  });

  describe('5. Authentication Rate Limiting & Sliding Window', () => {
    it('POST /api/record-login should track successful login', async () => {
      const res = await app.request('/api/record-login', {
        method: 'POST',
        body: { identifier: 'admin@sentinel.local', success: true }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.status, 'AUTHORIZED');
    });

    it('POST /api/record-login should track failed attempts and trigger block on threshold', async () => {
      const testIp = '198.51.100.99';
      for (let i = 0; i < 4; i++) {
        await app.request('/api/record-login', {
          method: 'POST',
          body: { identifier: 'attacker@evil.com', clientIp: testIp, success: false }
        });
      }
      // 5th failure exceeds threshold (maxFailures = 5)
      const resBlocked = await app.request('/api/record-login', {
        method: 'POST',
        body: { identifier: 'attacker@evil.com', clientIp: testIp, success: false }
      });
      assert.equal(resBlocked.status, 200);
      assert.equal(resBlocked.json.status, 'BLOCKED');
      assert.equal(resBlocked.json.rate.isBlocked, true);
    });
  });

  describe('6. Attack Simulator Vector', () => {
    it('POST /api/simulate-attack should simulate SQLi vector cleanly', async () => {
      const res = await app.request('/api/simulate-attack', {
        method: 'POST',
        body: { vector: 'sqli' }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.success, true);
      assert.equal(res.json.vector, 'sqli');
    });

    it('POST /api/simulate-attack should simulate bruteforce vector cleanly', async () => {
      const res = await app.request('/api/simulate-attack', {
        method: 'POST',
        body: { vector: 'bruteforce' }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.success, true);
      assert.equal(res.json.vector, 'bruteforce');
    });
  });

  describe('7. User Sessions & Activity Audit Flow', () => {
    let createdSessionId = null;

    it('POST /api/sessions/login should open a new user session', async () => {
      const res = await app.request('/api/sessions/login', {
        method: 'POST',
        body: { user: 'analista.seguridad', role: 'ANALISTA', portal: '/portal/login' }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.success, true);
      assert.ok(res.json.sessionId);
      createdSessionId = res.json.sessionId;
    });

    it('POST /api/sessions/activity should record user action in session', async () => {
      const res = await app.request('/api/sessions/activity', {
        method: 'POST',
        body: {
          sessionId: createdSessionId,
          actionType: 'EXPORT_REPORT',
          endpoint: '/reports/export',
          description: 'Descargó reporte de incidentes',
          riskLevel: 'ELEVATED'
        }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.success, true);
    });

    it('GET /api/sessions/activities should return list of actions for session', async () => {
      const res = await app.request(`/api/sessions/activities?sessionId=${createdSessionId}`);
      assert.equal(res.status, 200);
      assert.ok(Array.isArray(res.json));
      assert.ok(res.json.length >= 2); // AUTH_LOGIN + EXPORT_REPORT
    });

    it('POST /api/sessions/logout should terminate session', async () => {
      const res = await app.request('/api/sessions/logout', {
        method: 'POST',
        body: { sessionId: createdSessionId }
      });
      assert.equal(res.status, 200);
      assert.equal(res.json.success, true);
    });

    it('GET /api/sessions should list all sessions', async () => {
      const res = await app.request('/api/sessions');
      assert.equal(res.status, 200);
      assert.ok(Array.isArray(res.json));
      const found = res.json.find(s => s.session_id === createdSessionId);
      assert.ok(found);
      assert.equal(found.status, 'CERRADA');
    });
  });

  describe('8. Remote URL Scanner Endpoint', () => {
    it('POST /api/scan should audit self URL and return security score', async () => {
      const res = await app.request('/api/scan', {
        method: 'POST',
        body: { url: app.baseUrl }
      });
      assert.equal(res.status, 200);
      assert.ok(res.json);
      assert.equal(typeof res.json.securityScore, 'number');
      assert.equal(res.json.statusCode, 200);
    });

    it('POST /api/scan should reject empty URL with 400', async () => {
      const res = await app.request('/api/scan', {
        method: 'POST',
        body: {}
      });
      assert.equal(res.status, 400);
    });
  });

  describe('9. Body Parser & Robustness', () => {
    it('POST /api/simulate-attack with malformed JSON should return 400 and NOT crash server', async () => {
      const res = await app.request('/api/simulate-attack', {
        method: 'POST',
        body: '{ malformed json: not valid...'
      });
      assert.equal(res.status, 400);
      assert.equal(res.json.error, true);

      // Verify server is still alive and responsive!
      const ping = await app.request('/api/stats');
      assert.equal(ping.status, 200);
    });
  });
});
