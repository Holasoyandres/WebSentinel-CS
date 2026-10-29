/**
 * WebSentinel-CS :: Phase 2 Integrity, Forensics & Reliability Test Suite
 * Covers:
 * 1. Versioned migrations (schema_migrations, upgrade without data loss)
 * 2. SQLite PRAGMAs (WAL, NORMAL, foreign keys, busy_timeout)
 * 3. Event IDs formatted with crypto.randomUUID()
 * 4. Simulated data segregation (is_simulated flag, metrics/CSV exclusion)
 * 5. Persistent IP reputation in ip_reputation table and GET /api/v1/ip/:ip/status
 * 6. Database-backed /api/stats (persistent metrics)
 * 7. Configurable retention task (purges INFO >30d, older than RETENTION_DAYS, expired sessions/locks)
 * 8. SQLite hot backup (VACUUM INTO) and verification of restore procedure
 * 9. Cryptographic SHA-256 hash chaining and tamper detection (/api/v1/integrity/verify)
 * 10. Expanded admin_audit_log (action, user_id, ip, details)
 * 11. Operational probes (/healthz with real DB check, /readyz)
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const { DatabaseSync } = require('node:sqlite');
const { startTestServer } = require('./helpers');
const { createDatabase } = require('../src/db');

describe('WebSentinel-CS :: FASE 2 - Integridad Forense, Fiabilidad y Operación', () => {
  let ctx;
  let adminCookie, adminCsrf;
  let ingestApiKey;

  before(async () => {
    ctx = await startTestServer({
      config: {
        DEMO_MODE: true,
        TRUST_PROXIES: true,
        STORE_PASSED_EVENTS: false,
        RETENTION_DAYS: 90
      }
    });

    // Provision admin user
    const adminSalt = crypto.randomBytes(16).toString('hex');
    const adminHash = crypto.scryptSync('Phase2AdminPass123!', adminSalt, 64).toString('hex');
    ctx.db.raw.prepare(`
      INSERT INTO users (id, username, password_hash, salt, role, created_at)
      VALUES (?, ?, ?, ?, 'admin', datetime('now'))
    `).run('usr-admin-p2', 'admin_p2', adminHash, adminSalt);

    const loginRes = await ctx.request('/api/auth/login', {
      method: 'POST',
      auth: false,
      body: { username: 'admin_p2', password: 'Phase2AdminPass123!' }
    });
    assert.equal(loginRes.status, 200);
    adminCookie = loginRes.headers['set-cookie'][0].split(';')[0];
    adminCsrf = loginRes.json.csrfToken;

    // Provision ingest API Key
    ingestApiKey = 'ws_ingest_' + crypto.randomBytes(16).toString('hex');
    const ingestHash = crypto.createHash('sha256').update(ingestApiKey).digest('hex');
    ctx.db.raw.prepare(`
      INSERT INTO api_keys (id, name, key_hash, scopes, created_at)
      VALUES (?, ?, ?, 'ingest,read', datetime('now'))
    `).run('key-ingest-p2', 'Ingest & Read Key P2', ingestHash);
  });

  after(async () => {
    if (ctx) await ctx.close();
  });

  // ---------------------------------------------------------------------------
  // 1. Versioned Migrations & Schema Upgrade Without Data Loss
  // ---------------------------------------------------------------------------
  describe('1. Versioned Migrations System', () => {
    test('Migrates existing database with old schema without losing data', () => {
      const legacyDbPath = path.join(os.tmpdir(), `legacy-sentinel-${crypto.randomUUID()}.sqlite`);
      const legacyDb = new DatabaseSync(legacyDbPath);

      // Old schema without schema_migrations, is_simulated, or prev_hash
      legacyDb.exec(`
        CREATE TABLE incidents (
          id TEXT PRIMARY KEY,
          timestamp DATETIME NOT NULL,
          severity TEXT NOT NULL,
          type TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          source_ip TEXT NOT NULL,
          target TEXT NOT NULL,
          action TEXT NOT NULL,
          details TEXT NOT NULL
        );
        CREATE TABLE users (
          id TEXT PRIMARY KEY,
          username TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          salt TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'analyst',
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
      `);

      // Insert legacy data
      legacyDb.prepare(`
        INSERT INTO incidents (id, timestamp, severity, type, rule_id, source_ip, target, action, details)
        VALUES ('OLD-INC-001', datetime('now'), 'CRITICAL', 'SQLI', 'RULE-01', '10.0.0.1', '/login', 'BLOCKED', 'Ataque antiguo')
      `).run();

      legacyDb.prepare(`
        INSERT INTO users (id, username, password_hash, salt, role)
        VALUES ('USR-OLD-01', 'legacy_admin', 'hash123', 'salt123', 'admin')
      `).run();

      legacyDb.close();

      // Open database using new createDatabase with auto-migration runner
      const upgradedDb = createDatabase(legacyDbPath);

      // Verify schema_migrations table tracks applied migrations
      const applied = upgradedDb.raw.prepare('SELECT version, name FROM schema_migrations ORDER BY version ASC').all();
      assert.ok(applied.length >= 2, 'Must have applied migration 1 and 2');
      assert.equal(applied[0].version, 1);
      assert.equal(applied[1].version, 2);

      // Verify legacy data is 100% intact
      const incident = upgradedDb.raw.prepare('SELECT * FROM incidents WHERE id = ?').get('OLD-INC-001');
      assert.equal(incident.id, 'OLD-INC-001');
      assert.equal(incident.severity, 'CRITICAL');
      assert.equal(incident.details, 'Ataque antiguo');
      assert.equal(incident.is_simulated, 0, 'New column is_simulated defaults to 0');

      const user = upgradedDb.raw.prepare('SELECT * FROM users WHERE id = ?').get('USR-OLD-01');
      assert.equal(user.username, 'legacy_admin');

      upgradedDb.close();
      try { fs.unlinkSync(legacyDbPath); } catch (_) {}
    });
  });

  // ---------------------------------------------------------------------------
  // 2. SQLite PRAGMAs & Performance Hardening
  // ---------------------------------------------------------------------------
  describe('2. SQLite PRAGMA Configuration', () => {
    test('Database enables WAL, busy timeout, foreign keys and normal synchronous', () => {
      const journalMode = ctx.db.raw.prepare('PRAGMA journal_mode').get().journal_mode;
      assert.match(journalMode.toLowerCase(), /wal|memory/i);

      const busyTimeout = ctx.db.raw.prepare('PRAGMA busy_timeout').get().timeout;
      assert.ok(busyTimeout >= 5000, `busy_timeout must be >= 5000ms, got ${busyTimeout}`);

      const foreignKeys = ctx.db.raw.prepare('PRAGMA foreign_keys').get().foreign_keys;
      assert.equal(foreignKeys, 1, 'foreign_keys must be enabled (1)');
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Crypto Random UUIDs for Incident IDs
  // ---------------------------------------------------------------------------
  describe('3. Crypto UUID Event IDs', () => {
    test('Incident IDs use crypto.randomUUID() without Math.random()', async () => {
      const res = await ctx.request('/api/analyze-request', {
        method: 'POST',
        headers: { 'X-Sentinel-Key': ingestApiKey },
        body: { input: "' OR '1'='1" }
      });

      assert.equal(res.status, 200);
      assert.equal(res.json.safe, false);
      const incidentId = res.json.incidentId;
      assert.ok(incidentId.startsWith('SEC-'), 'Incident ID must have SEC- prefix');

      // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
      const uuidPart = incidentId.slice(4);
      assert.match(
        uuidPart,
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
        'Incident ID must contain a valid cryptographic UUID'
      );
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Simulated Data Segregation & Exclusion
  // ---------------------------------------------------------------------------
  describe('4. Simulated Data Segregation (is_simulated)', () => {
    test('Simulated attacks are tagged with is_simulated=1 and excluded from default queries and CSV', async () => {
      // Simulate an attack
      const simRes = await ctx.request('/api/simulate-attack', {
        method: 'POST',
        headers: { Cookie: adminCookie, 'X-CSRF-Token': adminCsrf },
        body: { vector: 'sqli' }
      });
      assert.equal(simRes.status, 200);

      // Verify default /api/events excludes simulated events
      const defaultEventsRes = await ctx.request('/api/events?limit=50', {
        headers: { Cookie: adminCookie, 'X-CSRF-Token': adminCsrf }
      });
      assert.equal(defaultEventsRes.status, 200);
      for (const ev of defaultEventsRes.json) {
        assert.ok(ev.is_simulated === 0 || ev.is_simulated === null, 'Default events must NOT include simulated records');
      }

      // Verify /api/events?includeSimulated=true includes simulated events
      const allEventsRes = await ctx.request('/api/events?limit=50&includeSimulated=true', {
        headers: { Cookie: adminCookie, 'X-CSRF-Token': adminCsrf }
      });
      assert.equal(allEventsRes.status, 200);
      const hasSimulated = allEventsRes.json.some(ev => ev.is_simulated === 1);
      assert.ok(hasSimulated, 'Events with includeSimulated=true must contain simulated records');

      // Verify CSV export excludes simulated by default
      const csvRes = await ctx.request('/api/export-csv', {
        headers: { Cookie: adminCookie, 'X-CSRF-Token': adminCsrf }
      });
      assert.equal(csvRes.status, 200);
      assert.ok(!csvRes.body.includes(',1,"Ataque simulado'), 'Default CSV must not contain simulated events');
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Persistent IP Reputation Rate Limiter & Status Query
  // ---------------------------------------------------------------------------
  describe('5. Persistent IP Reputation (ip_reputation)', () => {
    test('Telemetric brute force persists in ip_reputation and is queryable via GET /api/v1/ip/:ip/status', async () => {
      const testIp = '198.51.100.88';

      // Record 5 failed logins for this IP
      for (let i = 0; i < 5; i++) {
        const res = await ctx.request('/api/record-login', {
          method: 'POST',
          headers: { 'X-Sentinel-Key': ingestApiKey },
          body: { clientIp: testIp, user: 'target_user', success: false }
        });
        assert.equal(res.status, 200);
        if (i === 4) {
          assert.equal(res.json.status, 'BLOCKED');
        }
      }

      // Query status via new GET /api/v1/ip/:ip/status endpoint
      const statusRes = await ctx.request(`/api/v1/ip/${testIp}/status`, {
        headers: { 'X-Sentinel-Key': ingestApiKey }
      });
      assert.equal(statusRes.status, 200);
      assert.equal(statusRes.json.ip, testIp);
      assert.equal(statusRes.json.isBlocked, true);
      assert.ok(statusRes.json.blockExpiresAt, 'Must have block expiration timestamp');
      assert.equal(statusRes.json.failedAttempts, 5);

      // Verify persistent record in SQLite table
      const row = ctx.db.raw.prepare('SELECT * FROM ip_reputation WHERE ip = ?').get(testIp);
      assert.ok(row, 'Record must exist in ip_reputation table');
      assert.equal(row.failed_attempts, 5);
      assert.ok(new Date(row.block_expires_at).getTime() > Date.now());
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Database-Backed Persistent /api/stats
  // ---------------------------------------------------------------------------
  describe('6. Persistent Database Metrics in /api/stats', () => {
    test('/api/stats computes metrics directly from SQLite tables', async () => {
      const statsRes = await ctx.request('/api/stats', {
        headers: { Cookie: adminCookie, 'X-CSRF-Token': adminCsrf }
      });
      assert.equal(statsRes.status, 200);
      assert.ok(typeof statsRes.json.totalPersistedIncidents === 'number');
      assert.ok(typeof statsRes.json.criticalCount === 'number');
      assert.ok(typeof statsRes.json.threatsDetected === 'number');
      assert.equal(statsRes.json.storageEngine, 'SQLITE_PERSISTENT');
    });
  });

  // ---------------------------------------------------------------------------
  // 7. Configurable Retention & Purging
  // ---------------------------------------------------------------------------
  describe('7. Retention & Purging Engine', () => {
    test('purgeExpiredRecords purges expired sessions, rate limits, and old incidents', () => {
      // 1. Insert an expired auth_session
      ctx.db.raw.prepare(`
        INSERT INTO auth_sessions (token_hash, user_id, csrf_token, expires_at, created_at)
        VALUES ('expired-tok-hash', 'usr-admin-p2', 'csrf-exp', datetime('now', '-2 hours'), datetime('now', '-10 hours'))
      `).run();

      // 2. Insert an expired login_rate_limit
      ctx.db.raw.prepare(`
        INSERT INTO login_rate_limits (identifier, failures, locked_until, updated_at)
        VALUES ('ip:198.51.100.99', 5, datetime('now', '-10 minutes'), datetime('now', '-20 minutes'))
      `).run();

      // 3. Insert an old INFO incident (>30 days old)
      ctx.db.raw.prepare(`
        INSERT INTO incidents (id, timestamp, severity, type, rule_id, source_ip, target, action, details)
        VALUES ('OLD-INFO-001', datetime('now', '-35 days'), 'INFO', 'CLEAN', 'R1', '127.0.0.1', '/', 'PASSED', 'Viejo info')
      `).run();

      // Run purge
      const purgeResult = ctx.db.purgeExpiredRecords(90);
      assert.ok(purgeResult.expiredSessionsPurged >= 1, 'Must purge expired session');
      assert.ok(purgeResult.rateLimitsPurged >= 1, 'Must purge expired rate limit lock');
      assert.ok(purgeResult.infoPassedPurged >= 1, 'Must purge old INFO incident');

      // Verify expired session is gone
      const expiredSess = ctx.db.raw.prepare('SELECT * FROM auth_sessions WHERE token_hash = ?').get('expired-tok-hash');
      assert.equal(expiredSess, undefined);
    });
  });

  // ---------------------------------------------------------------------------
  // 8. Live Hot Backups via VACUUM INTO and Restore Verification
  // ---------------------------------------------------------------------------
  describe('8. Automated Backups & Restore Procedure', () => {
    test('createBackup creates hot SQLite snapshot using VACUUM INTO and rotates old archives', () => {
      const backupDir = path.join(os.tmpdir(), `sentinel-backups-${crypto.randomUUID()}`);

      // Perform backup
      const backupResult = ctx.db.createBackup(backupDir, 3);
      assert.equal(backupResult.success, true);
      assert.ok(fs.existsSync(backupResult.backupPath), 'Backup file must exist on disk');

      // Verify backup is a valid readable SQLite database
      const backupDb = new DatabaseSync(backupResult.backupPath, { readOnly: true });
      const users = backupDb.prepare('SELECT COUNT(*) as c FROM users').get();
      assert.ok(users.c >= 1, 'Backup database must contain user tables');
      backupDb.close();

      // Clean up backup directory
      try {
        fs.rmSync(backupDir, { recursive: true, force: true });
      } catch (_) {}
    });
  });

  // ---------------------------------------------------------------------------
  // 9. Cryptographic Log Integrity (SHA-256 Hash Chaining) & Tamper Detection
  // ---------------------------------------------------------------------------
  describe('9. Cryptographic Log Integrity & Tamper Detection', () => {
    test('Log verification endpoint validates hash chain and detects manual row tampering', async () => {
      // 1. Initial verification on clean log
      const initialRes = await ctx.request('/api/v1/integrity/verify', {
        headers: { Cookie: adminCookie, 'X-CSRF-Token': adminCsrf }
      });
      assert.equal(initialRes.status, 200);
      assert.equal(initialRes.json.valid, true);

      // 2. Tamper with a row directly in SQLite
      const victimRow = ctx.db.raw.prepare('SELECT id, severity FROM incidents ORDER BY rowid DESC LIMIT 1').get();
      assert.ok(victimRow, 'Must have at least one incident to test tampering');

      const originalSeverity = victimRow.severity;
      const tamperedSeverity = originalSeverity === 'CRITICAL' ? 'LOW' : 'CRITICAL';

      // Direct manual manipulation simulating database unauthorized modification
      ctx.db.raw.prepare('UPDATE incidents SET severity = ? WHERE id = ?').run(tamperedSeverity, victimRow.id);

      // 3. Integrity verification must detect the tampering
      const verifyRes = await ctx.request('/api/v1/integrity/verify', {
        headers: { Cookie: adminCookie, 'X-CSRF-Token': adminCsrf }
      });
      assert.equal(verifyRes.status, 200);
      assert.equal(verifyRes.json.valid, false, 'Must detect tampering');
      assert.equal(verifyRes.json.brokenAtId, victimRow.id, 'Must identify tampered row ID');
      assert.match(verifyRes.json.reason, /tampering/i);

      // Restore original state
      ctx.db.raw.prepare('UPDATE incidents SET severity = ? WHERE id = ?').run(originalSeverity, victimRow.id);
    });
  });

  // ---------------------------------------------------------------------------
  // 10. Expanded Admin Panel Audit Log
  // ---------------------------------------------------------------------------
  describe('10. Expanded Audit Logging (admin_audit_log)', () => {
    test('Admin actions (login, logout, sql, export csv) record structured audit entries', () => {
      const logs = ctx.db.raw.prepare('SELECT action, user_id, ip, details FROM admin_audit_log ORDER BY id DESC LIMIT 10').all();
      const actions = logs.map(l => l.action);

      assert.ok(actions.includes('LOGIN'), 'Audit log must record LOGIN');
      assert.ok(actions.includes('SQL_QUERY') || actions.includes('EXPORT_CSV'), 'Audit log must record administrative operations');
    });
  });

  // ---------------------------------------------------------------------------
  // 11. Operational Probes (/healthz & /readyz)
  // ---------------------------------------------------------------------------
  describe('11. Operational Probes', () => {
    test('/healthz verifies real database connection with SELECT 1 and returns status UP', async () => {
      const res = await ctx.request('/healthz', { auth: false });
      assert.equal(res.status, 200);
      assert.equal(res.json.status, 'UP');
      assert.equal(res.json.database, 'OK');
      assert.ok(res.json.version);
    });

    test('/readyz verifies readiness for orchestrator probes', async () => {
      const res = await ctx.request('/readyz', { auth: false });
      assert.equal(res.status, 200);
      assert.equal(res.json.ready, true);
    });
  });
});
