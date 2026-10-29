/**
 * WebSentinel-CS :: FASE 3 Tests - Normalization, WAF Engine & Ingestion (P1)
 * Validates canonicalization pipeline, CRS anomaly scoring, ReDoS protection,
 * and dedicated event ingestion endpoint.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const { startTestServer } = require('./helpers');
const { normalizePayload } = require('../src/engine/normalizer');
const { inspectPayload } = require('../src/engine/signatures');

describe('WebSentinel-CS :: FASE 3 - Pipeline de Normalización, WAF & Ingesta', () => {
  let context;
  let serverUrl;
  let ingestKey;
  let readOnlyKey;

  before(async () => {
    context = await startTestServer({
      config: {
        ANOMALY_THRESHOLD: 5
      }
    });
    serverUrl = context.baseUrl;
    ingestKey = context.apiKey; // default key has ingest,read

    // Create a read-only key (no ingest scope)
    readOnlyKey = 'ws_readonly_' + crypto.randomBytes(16).toString('hex');
    const readOnlyHash = crypto.createHash('sha256').update(readOnlyKey).digest('hex');
    context.db.raw.prepare(`
      INSERT INTO api_keys (id, name, key_hash, scopes, created_at)
      VALUES (?, ?, ?, ?, datetime('now'))
    `).run('key-readonly-test', 'Read Only Test Key', readOnlyHash, 'read');
  });

  after(async () => {
    if (context) await context.close();
  });

  // ---------------------------------------------------------------------------
  // 1. Pipeline de Normalización Unitario
  // ---------------------------------------------------------------------------
  describe('1. Normalization Pipeline (src/engine/normalizer.js)', () => {
    test('Recursive URL decoding up to 3 passes resolves double encoding (%2527 -> %27 -> \')', () => {
      const res = normalizePayload('%2527%20OR%201=1');
      assert.ok(res.normalized.includes("' OR 1=1"), `Expected decoded quote and spaces: got ${res.normalized}`);
    });

    test('Single-pass URL encoding is resolved cleanly (%27%20UNION%20SELECT)', () => {
      const res = normalizePayload('%27%20UNION%20SELECT');
      assert.ok(res.normalized.includes("' UNION SELECT"), `Expected decoded string: got ${res.normalized}`);
    });

    test('Malformed URL encoding does not throw URIError and is handled safely', () => {
      assert.doesNotThrow(() => {
        const res = normalizePayload('text%zz%25%a%');
        assert.ok(typeof res.normalized === 'string');
      });
    });

    test('HTML entities (named, decimal, hex) are decoded', () => {
      const input = '&quot; &apos; &#x27; &#39; &lt;script&gt; &amp;';
      const res = normalizePayload(input);
      assert.ok(res.normalized.includes('" \' \' \' <script> &'), `Got: ${res.normalized}`);
    });

    test('Unicode NFKC normalization and null bytes removal', () => {
      const input = 'admin\u0000\uFF21\uFF44\uFF4D\uFF49\uFF4E'; // null byte + fullwidth "Admin"
      const res = normalizePayload(input);
      assert.strictEqual(res.normalized.includes('\0'), false, 'Null byte must be removed');
      assert.ok(res.normalized.includes('adminAdmin'), `Expected NFKC normalized: got ${res.normalized}`);
    });

    test('Inline SQL comments (/* ... */) are removed and whitespace collapsed', () => {
      const input = 'SELECT/*comment*/1   FROM/*multi\nline\ncomment*/users   WHERE  id = 1';
      const res = normalizePayload(input);
      assert.strictEqual(res.normalized, 'SELECT 1 FROM users WHERE id = 1');
    });

    test('ReDoS safety: inputs exceeding 16 KB are safely truncated', () => {
      const hugeInput = 'A'.repeat(30000);
      const res = normalizePayload(hugeInput);
      assert.strictEqual(res.normalized.length, 16384, 'Should truncate to exactly 16,384 characters');
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Centralized Signatures & False Positive Elimination
  // ---------------------------------------------------------------------------
  describe('2. Centralized Signatures (rules/signatures.json)', () => {
    test('Signatures file exists and is valid JSON with required schema fields', () => {
      const sigPath = path.join(__dirname, '..', 'rules', 'signatures.json');
      assert.ok(fs.existsSync(sigPath), 'rules/signatures.json must exist');
      const sigs = JSON.parse(fs.readFileSync(sigPath, 'utf8'));
      assert.ok(Array.isArray(sigs));
      assert.ok(sigs.length >= 10);

      for (const sig of sigs) {
        assert.ok(sig.id, 'Signature must have id');
        assert.ok(sig.name, 'Signature must have name');
        assert.ok(sig.category, 'Signature must have category');
        assert.ok(sig.regex, 'Signature must have regex');
        assert.ok(sig.severity, 'Signature must have severity');
        assert.ok(sig.cwe, 'Signature must have cwe');
        assert.ok(typeof sig.score === 'number', 'Signature must have numeric score');
      }
    });

    test('False positive fix: SIG-SQLI-003 does NOT trigger on standard double hyphens in prose', () => {
      const text = 'Este es un texto -- con guión normal entre palabras';
      const inspection = inspectPayload(text);
      const matchedSql3 = inspection.triggeredRules.find(r => r.id === 'SIG-SQLI-003');
      assert.strictEqual(matchedSql3, undefined, 'SIG-SQLI-003 must not flag benign double hyphen in prose');
    });

    test('False positive fix: SIG-PATH-002 does NOT trigger on domains like enviaexpress.com', () => {
      const email = 'soporte@enviaexpress.com';
      const inspection = inspectPayload(email);
      const matchedPath = inspection.triggeredRules.find(r => r.id === 'SIG-PATH-002');
      assert.strictEqual(matchedPath, undefined, 'SIG-PATH-002 must not flag enviaexpress.com domain');
    });

    test('Detects modern XSS vectors (<svg/onanimationstart=alert(1)> and data: schemes)', () => {
      const payload1 = '<svg/onanimationstart=alert(1)>';
      const res1 = inspectPayload(payload1);
      assert.strictEqual(res1.safe, false);
      assert.ok(res1.triggeredRules.some(r => r.category === 'xss'));

      const payload2 = '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>';
      const res2 = inspectPayload(payload2);
      assert.strictEqual(res2.safe, false);
      assert.ok(res2.triggeredRules.some(r => r.id === 'SIG-XSS-003'));
    });

    test('Detects blind SQLi time delays (SLEEP, BENCHMARK, PG_SLEEP)', () => {
      const payload = "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--";
      const res = inspectPayload(payload);
      assert.strictEqual(res.safe, false);
      assert.ok(res.triggeredRules.some(r => r.id === 'SIG-SQLI-004'));
    });

    test('Detects Command Injection vectors (pipe chaining, backticks)', () => {
      const payload = "input.txt; cat /etc/passwd";
      const res = inspectPayload(payload);
      assert.strictEqual(res.safe, false);
      assert.ok(res.triggeredRules.some(r => r.category === 'cmd_injection'));
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Anomaly Scoring OWASP CRS Style in POST /api/analyze-request
  // ---------------------------------------------------------------------------
  describe('3. OWASP CRS-Style Anomaly Scoring in /api/analyze-request', () => {
    test('Threshold blocking: score >= 5 yields action BLOCK, status BLOCKED, safe false', async () => {
      const res = await context.request('/api/analyze-request', {
        method: 'POST',
        body: {
          input: "' UNION SELECT null, username, password FROM users --",
          honeypot: ""
        }
      });

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.safe, false);
      assert.strictEqual(res.json.action, 'BLOCK');
      assert.strictEqual(res.json.status, 'BLOCKED');
      assert.ok(res.json.scoreTotal >= 5);
      assert.strictEqual(res.json.threshold, 5);
      assert.ok(Array.isArray(res.json.triggeredRules));
      assert.ok(res.json.triggeredRules.length > 0);
    });

    test('Flagging: 0 < score < threshold yields action FLAG, status SUSPICIOUS, safe false', async () => {
      // Craft input that triggers a rule with score 4 (HIGH, e.g. SIG-SQLI-005 @@version or SIG-PATH-001) without reaching 5
      const res = await context.request('/api/analyze-request', {
        method: 'POST',
        body: {
          input: "view @@version info",
          honeypot: ""
        }
      });

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.safe, false);
      assert.strictEqual(res.json.action, 'FLAG');
      assert.strictEqual(res.json.status, 'SUSPICIOUS');
      assert.strictEqual(res.json.scoreTotal, 4);
      assert.strictEqual(res.json.threshold, 5);
    });

    test('Clean payload: score === 0 yields action ALLOW, status SAFE, safe true', async () => {
      const res = await context.request('/api/analyze-request', {
        method: 'POST',
        body: {
          input: "Consulta estándar de usuario Juan Pérez",
          honeypot: ""
        }
      });

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.safe, true);
      assert.strictEqual(res.json.action, 'ALLOW');
      assert.strictEqual(res.json.status, 'SAFE');
      assert.strictEqual(res.json.scoreTotal, 0);
    });

    test('Evasion attempt with double URL encoding is caught via normalization', async () => {
      const res = await context.request('/api/analyze-request', {
        method: 'POST',
        body: {
          input: "%2527%20OR%201=1",
          honeypot: ""
        }
      });

      assert.strictEqual(res.status, 200);
      assert.strictEqual(res.json.safe, false);
      assert.ok(res.json.scoreTotal >= 5);
      assert.strictEqual(res.json.action, 'BLOCK');
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Dedicated Event Ingestion Endpoint (POST /api/v1/events)
  // ---------------------------------------------------------------------------
  describe('4. Dedicated Event Ingestion Endpoint (POST /api/v1/events)', () => {
    test('API Key with scope ingest can ingest valid telemetry event (201 Created)', async () => {
      const payload = {
        type: 'EXTERNAL_WAF_ALERT',
        severity: 'HIGH',
        ruleId: 'EXT-RULE-942100',
        sourceIp: '190.25.10.4',
        target: '/portal/login.php',
        details: 'SQLi attempt blocked by external Nginx ModSecurity',
        action: 'BLOCKED'
      };

      const res = await context.request('/api/v1/events', {
        method: 'POST',
        body: payload,
        headers: {
          'X-Sentinel-Key': ingestKey
        }
      });

      assert.strictEqual(res.status, 201);
      assert.strictEqual(res.json.success, true);
      assert.ok(res.json.eventId && res.json.eventId.startsWith('SEC-'), 'Should return generated eventId');

      // Verify persistence in DB
      const row = context.db.raw.prepare('SELECT * FROM incidents WHERE id = ?').get(res.json.eventId);
      assert.ok(row);
      assert.strictEqual(row.type, 'EXTERNAL_WAF_ALERT');
      assert.strictEqual(row.source_ip, '190.25.10.4');
      assert.ok(row.hash && row.hash.length === 64, 'Must have SHA-256 hash chaining');
    });

    test('API Key with read-only scope receives 403 Forbidden', async () => {
      const res = await context.request('/api/v1/events', {
        method: 'POST',
        body: {
          type: 'EXTERNAL_ALERT',
          severity: 'LOW',
          ruleId: 'EXT-01',
          sourceIp: '1.2.3.4',
          target: '/home',
          details: 'info',
          action: 'LOGGED'
        },
        headers: {
          'X-Sentinel-Key': readOnlyKey
        }
      });

      assert.strictEqual(res.status, 403);
    });

    test('Unauthenticated request receives 401 Unauthorized', async () => {
      const res = await context.request('/api/v1/events', {
        method: 'POST',
        body: { type: 'TEST' },
        auth: false
      });

      assert.strictEqual(res.status, 401);
    });

    test('Invalid schema (missing required fields or invalid enum) returns 400 Bad Request', async () => {
      const res = await context.request('/api/v1/events', {
        method: 'POST',
        body: {
          type: 'BAD_SEVERITY',
          severity: 'ULTRA_CRITICAL', // invalid enum
          ruleId: 'R-1',
          sourceIp: '1.1.1.1',
          target: '/test',
          details: 'details',
          action: 'BLOCKED'
        },
        headers: {
          'X-Sentinel-Key': ingestKey
        }
      });

      assert.strictEqual(res.status, 400);
      const msg = res.json.message || '';
      assert.ok(msg.includes('severidad') || msg.includes('severity') || msg.includes('inválido'));
    });
  });
});
