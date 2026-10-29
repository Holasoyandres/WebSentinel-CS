/**
 * WebSentinel-CS :: Database Engine
 * Native SQLite storage using Node.js DatabaseSync
 * Features: WAL mode, foreign keys, versioned migrations, statement cache,
 * cryptographic hash chaining, persistent IP reputation, and automated hot backups.
 */

const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { runMigrations } = require('./migrator');

function createDatabase(dbPath) {
  if (dbPath !== ':memory:') {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const db = new DatabaseSync(dbPath);

  // WAL, busy timeout, foreign keys and synchronous hardening
  try {
    db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      PRAGMA foreign_keys = ON;
      PRAGMA busy_timeout = 5000;
    `);
  } catch (_) {
    // In-memory databases or restricted environments may ignore some PRAGMAs
  }

  // Execute versioned migrations to ensure zero data loss on schema updates
  runMigrations(db);

  // Prepared statement cache for high performance
  const statementCache = new Map();
  function getPrepared(sql) {
    let stmt = statementCache.get(sql);
    if (!stmt) {
      stmt = db.prepare(sql);
      statementCache.set(sql, stmt);
    }
    return stmt;
  }

  return {
    raw: db,

    // -------------------------------------------------------------------------
    // Incident Telemetry & Cryptographic Hash Chaining
    // -------------------------------------------------------------------------
    insertIncident(event) {
      const isSimulated = event.isSimulated ? 1 : 0;

      // 1. Fetch previous incident hash to maintain cryptographic chain
      let prevHash = '0'.repeat(64); // Genesis hash
      try {
        const lastRow = db.prepare('SELECT hash FROM incidents ORDER BY rowid DESC LIMIT 1').get();
        if (lastRow && lastRow.hash) {
          prevHash = lastRow.hash;
        }
      } catch (_) {}

      // 2. Canonical serialization for immutable SHA-256 fingerprinting
      const canonicalData = [
        prevHash,
        event.id,
        event.timestamp,
        event.severity,
        event.type,
        event.sourceIp,
        event.target
      ].join('|');
      const hash = crypto.createHash('sha256').update(canonicalData).digest('hex');

      const stmt = getPrepared(`
        INSERT INTO incidents (id, timestamp, severity, type, rule_id, source_ip, target, action, details, is_simulated, prev_hash, hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        event.id,
        event.timestamp,
        event.severity,
        event.type,
        event.ruleId || 'RULE-GENERIC',
        event.sourceIp,
        event.target,
        event.action,
        event.details,
        isSimulated,
        prevHash,
        hash
      );
    },

    getIncidents(limit = 100, severity = 'ALL', offset = 0, includeSimulated = false) {
      const parsedLimit = Math.max(1, Math.min(500, parseInt(limit, 10) || 100));
      const parsedOffset = Math.max(0, parseInt(offset, 10) || 0);
      const simClause = includeSimulated ? '' : 'AND (is_simulated IS NULL OR is_simulated = 0)';

      if (severity === 'ALL') {
        const sql = `SELECT * FROM incidents WHERE 1=1 ${simClause} ORDER BY timestamp DESC LIMIT ? OFFSET ?`;
        return db.prepare(sql).all(parsedLimit, parsedOffset);
      } else {
        const sql = `SELECT * FROM incidents WHERE severity = ? ${simClause} ORDER BY timestamp DESC LIMIT ? OFFSET ?`;
        return db.prepare(sql).all(severity, parsedLimit, parsedOffset);
      }
    },

    verifyIncidentLogIntegrity() {
      const rows = db.prepare('SELECT id, timestamp, severity, type, source_ip, target, prev_hash, hash FROM incidents ORDER BY rowid ASC').all();
      let expectedPrevHash = '0'.repeat(64);

      for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        if (row.prev_hash !== expectedPrevHash) {
          return {
            valid: false,
            brokenAtId: row.id,
            reason: `Discrepancia en enlace de cadena prev_hash en registro ${row.id}`,
            expectedPrevHash,
            actualPrevHash: row.prev_hash
          };
        }

        const canonicalData = [
          row.prev_hash,
          row.id,
          row.timestamp,
          row.severity,
          row.type,
          row.source_ip,
          row.target
        ].join('|');
        const calculatedHash = crypto.createHash('sha256').update(canonicalData).digest('hex');

        if (row.hash !== calculatedHash) {
          return {
            valid: false,
            brokenAtId: row.id,
            reason: `Firma criptográfica inválida (tampering detectado) en registro ${row.id}`,
            expectedHash: calculatedHash,
            actualHash: row.hash
          };
        }

        expectedPrevHash = row.hash;
      }

      return {
        valid: true,
        verifiedCount: rows.length
      };
    },

    // -------------------------------------------------------------------------
    // Persistent IP Reputation & Telemetry Limiting
    // -------------------------------------------------------------------------
    getIpReputation(ip) {
      const row = getPrepared(`SELECT * FROM ip_reputation WHERE ip = ?`).get(ip);
      if (!row) {
        return { ip, isBlocked: false, blockExpiresAt: null, failedAttempts: 0, reputationScore: 100 };
      }
      const isBlocked = row.block_expires_at ? new Date(row.block_expires_at).getTime() > Date.now() : false;
      return {
        ip: row.ip,
        isBlocked,
        blockExpiresAt: row.block_expires_at,
        failedAttempts: row.failed_attempts || 0,
        reputationScore: row.reputation_score ?? 100
      };
    },

    recordIpAttempt(ip, isSuccess, threshold = 5, lockMinutes = 15) {
      const current = getPrepared(`SELECT * FROM ip_reputation WHERE ip = ?`).get(ip);

      if (isSuccess) {
        getPrepared(`
          INSERT INTO ip_reputation (ip, failed_attempts, block_expires_at, last_seen, updated_at)
          VALUES (?, 0, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
          ON CONFLICT(ip) DO UPDATE SET
            failed_attempts = 0,
            block_expires_at = NULL,
            last_seen = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        `).run(ip);
        return { isBlocked: false, failedAttempts: 0, blockExpiresAt: null };
      }

      const failures = (current ? current.failed_attempts : 0) + 1;
      let blockExpiresAt = current ? current.block_expires_at : null;
      let isBlocked = false;

      if (failures >= threshold) {
        isBlocked = true;
        blockExpiresAt = new Date(Date.now() + lockMinutes * 60 * 1000).toISOString();
      }

      getPrepared(`
        INSERT INTO ip_reputation (ip, failed_attempts, block_expires_at, first_seen, last_seen, updated_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT(ip) DO UPDATE SET
          failed_attempts = ?,
          block_expires_at = ?,
          last_seen = CURRENT_TIMESTAMP,
          updated_at = CURRENT_TIMESTAMP
      `).run(ip, failures, blockExpiresAt, failures, blockExpiresAt);

      return { isBlocked, failedAttempts: failures, blockExpiresAt };
    },

    // -------------------------------------------------------------------------
    // Endpoint Scans & Analytics Summary
    // -------------------------------------------------------------------------
    saveScanResult(scan) {
      const stmt = getPrepared(`
        INSERT INTO endpoint_scans (target_url, status_code, security_score, missing_headers_count, latency_ms)
        VALUES (?, ?, ?, ?, ?)
      `);
      stmt.run(
        scan.url,
        scan.statusCode || 0,
        scan.securityScore || 0,
        scan.missingHeadersCount || 0,
        scan.latencyMs || 0
      );
    },

    incrementDailyInspection(isThreat = false) {
      const today = new Date().toISOString().slice(0, 10);
      getPrepared(`
        INSERT INTO daily_metrics (date, inspections_count, threats_count, updated_at)
        VALUES (?, 1, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(date) DO UPDATE SET
          inspections_count = inspections_count + 1,
          threats_count = threats_count + ?,
          updated_at = CURRENT_TIMESTAMP
      `).run(today, isThreat ? 1 : 0, isThreat ? 1 : 0);
    },

    getAnalyticsSummary(includeSimulated = false) {
      const simFilter = includeSimulated ? '' : 'WHERE (is_simulated IS NULL OR is_simulated = 0)';
      const simFilterAnd = includeSimulated ? '' : 'AND (is_simulated IS NULL OR is_simulated = 0)';

      const totalIncidents = db.prepare(`SELECT COUNT(*) as c FROM incidents ${simFilter}`).get().c;
      const criticalCount = db.prepare(`SELECT COUNT(*) as c FROM incidents WHERE severity = 'CRITICAL' ${simFilterAnd}`).get().c;
      const highCount = db.prepare(`SELECT COUNT(*) as c FROM incidents WHERE severity = 'HIGH' ${simFilterAnd}`).get().c;
      const threatsDetected = db.prepare(`SELECT COUNT(*) as c FROM incidents WHERE severity IN ('CRITICAL', 'HIGH') ${simFilterAnd}`).get().c;
      const bruteForceBlocked = db.prepare(`SELECT COUNT(*) as c FROM incidents WHERE type LIKE '%BRUTEFORCE%' ${simFilterAnd}`).get().c;

      let totalScans = 0;
      try {
        totalScans = db.prepare(`SELECT COUNT(*) as c FROM endpoint_scans`).get().c;
      } catch (_) {}

      let inspectionsRun = 0;
      try {
        const dm = db.prepare(`SELECT COALESCE(SUM(inspections_count), 0) as c FROM daily_metrics`).get();
        inspectionsRun = dm ? dm.c : 0;
      } catch (_) {}

      let topIps = [];
      try {
        topIps = db.prepare(`SELECT source_ip, COUNT(*) as count FROM incidents ${simFilter} GROUP BY source_ip ORDER BY count DESC LIMIT 5`).all();
      } catch (_) {}

      let severityDistribution = [];
      try {
        severityDistribution = db.prepare(`SELECT severity, COUNT(*) as count FROM incidents ${simFilter} GROUP BY severity`).all();
      } catch (_) {}

      return {
        totalIncidents,
        criticalCount,
        highCount,
        threatsDetected,
        bruteForceBlocked,
        totalScans,
        inspectionsRun,
        topIps,
        severityDistribution
      };
    },

    // -------------------------------------------------------------------------
    // User Sessions & Activities Audit Flow
    // -------------------------------------------------------------------------
    sessionExists(sessionId) {
      if (!sessionId || typeof sessionId !== 'string') return false;
      try {
        const row = getPrepared(`SELECT session_id FROM user_sessions WHERE session_id = ?`).get(sessionId);
        return Boolean(row);
      } catch (_) {
        return false;
      }
    },

    createSession(data, isSimulated = false) {
      const sessionId = 'SESS-' + crypto.randomUUID().toUpperCase();
      const loginTime = new Date().toISOString();
      const stmt = getPrepared(`
        INSERT INTO user_sessions (session_id, user_identifier, role, ip_address, login_portal, user_agent, status, login_time, logout_time, duration_minutes, is_simulated)
        VALUES (?, ?, ?, ?, ?, ?, 'ACTIVA', ?, NULL, 0, ?)
      `);
      stmt.run(
        sessionId,
        data.user_identifier || 'usuario.anonimo',
        data.role || 'USUARIO',
        data.ip_address || '127.0.0.1',
        data.login_portal || '/auth/login',
        data.user_agent || 'Standard Web Client',
        loginTime,
        isSimulated ? 1 : 0
      );

      this.recordActivity(sessionId, 'AUTH_LOGIN', data.login_portal || '/auth/login', 'Inicio de sesión verificado.', 'NORMAL', isSimulated);
      return sessionId;
    },

    recordActivity(sessionId, actionType, endpoint, description, riskLevel = 'NORMAL', isSimulated = false) {
      const stmt = getPrepared(`
        INSERT INTO session_activities (session_id, timestamp, action_type, endpoint, description, risk_level, is_simulated)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        sessionId,
        new Date().toISOString(),
        actionType,
        endpoint,
        description,
        riskLevel,
        isSimulated ? 1 : 0
      );
    },

    closeSession(sessionId) {
      if (!sessionId || typeof sessionId !== 'string') return false;
      const sess = getPrepared(`SELECT login_time FROM user_sessions WHERE session_id = ?`).get(sessionId);
      if (!sess) return false;

      const logoutTime = new Date().toISOString();
      let durationMinutes = 1;
      if (sess.login_time) {
        const diffMs = new Date(logoutTime) - new Date(sess.login_time);
        durationMinutes = Math.max(1, Math.round(diffMs / 60000));
      }

      const stmt = getPrepared(`
        UPDATE user_sessions 
        SET status = 'CERRADA', logout_time = ?, duration_minutes = ?
        WHERE session_id = ?
      `);
      stmt.run(logoutTime, durationMinutes, sessionId);

      try {
        this.recordActivity(sessionId, 'AUTH_LOGOUT', '/auth/logout', 'Cierre voluntario de sesión.', 'NORMAL');
      } catch (_) {}
      return true;
    },

    getSessionActivities(sessionId) {
      const stmt = getPrepared(`
        SELECT * FROM session_activities
        WHERE session_id = ?
        ORDER BY timestamp ASC
      `);
      return stmt.all(sessionId);
    },

    getUserSessions(limit = 50, offset = 0, includeSimulated = false) {
      const simClause = includeSimulated ? '' : 'WHERE (is_simulated IS NULL OR is_simulated = 0)';
      const stmt = db.prepare(`
        SELECT * FROM user_sessions
        ${simClause}
        ORDER BY login_time DESC
        LIMIT ? OFFSET ?
      `);
      return stmt.all(limit, offset);
    },

    // -------------------------------------------------------------------------
    // API Keys Management
    // -------------------------------------------------------------------------
    findApiKeyByHash(keyHash) {
      return getPrepared(`SELECT * FROM api_keys WHERE key_hash = ?`).get(keyHash);
    },

    touchApiKey(keyId) {
      try {
        getPrepared(`UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`).run(keyId);
      } catch (_) {}
    },

    // -------------------------------------------------------------------------
    // Dashboard Users & Authentication RBAC
    // -------------------------------------------------------------------------
    findUserByUsername(username) {
      return getPrepared(`SELECT * FROM users WHERE username = ?`).get(username);
    },

    findUserById(userId) {
      return getPrepared(`SELECT id, username, role FROM users WHERE id = ?`).get(userId);
    },

    createAuthSession(userId, durationHours = 8) {
      const rawToken = crypto.randomBytes(32).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
      const csrfToken = crypto.randomBytes(24).toString('hex');
      const expiresAt = new Date(Date.now() + durationHours * 3600 * 1000).toISOString();

      getPrepared(`
        INSERT INTO auth_sessions (token_hash, user_id, csrf_token, expires_at, created_at)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
      `).run(tokenHash, userId, csrfToken, expiresAt);

      return { rawToken, csrfToken, expiresAt };
    },

    getAuthSession(rawToken) {
      if (!rawToken || typeof rawToken !== 'string') return null;
      const tokenHash = crypto.createHash('sha256').update(rawToken.trim()).digest('hex');
      const row = getPrepared(`
        SELECT s.token_hash, s.user_id, s.csrf_token, s.expires_at, u.username, u.role
        FROM auth_sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token_hash = ? AND s.expires_at > CURRENT_TIMESTAMP
      `).get(tokenHash);

      return row || null;
    },

    revokeAuthSession(rawToken) {
      if (!rawToken || typeof rawToken !== 'string') return;
      const tokenHash = crypto.createHash('sha256').update(rawToken.trim()).digest('hex');
      getPrepared(`DELETE FROM auth_sessions WHERE token_hash = ?`).run(tokenHash);
    },

    // -------------------------------------------------------------------------
    // Login Rate Limiting (Dashboard)
    // -------------------------------------------------------------------------
    checkLoginRateLimit(identifier) {
      try {
        const row = getPrepared(`SELECT * FROM login_rate_limits WHERE identifier = ?`).get(identifier);
        if (row && row.locked_until) {
          const lockTime = new Date(row.locked_until).getTime();
          const now = Date.now();
          if (lockTime > now) {
            const retryAfterSec = Math.max(1, Math.ceil((lockTime - now) / 1000));
            return { isLocked: true, retryAfterSec, failures: row.failures, alerted: Boolean(row.alerted) };
          }
        }
        return { isLocked: false, retryAfterSec: 0, failures: row ? row.failures : 0, alerted: Boolean(row ? row.alerted : 0) };
      } catch (err) {
        console.error('[DB Error] checkLoginRateLimit:', err.message);
        return { isLocked: false, retryAfterSec: 0, failures: 0, alerted: false };
      }
    },

    incrementBlockedAttempts(identifier) {
      try {
        getPrepared(`
          UPDATE login_rate_limits
          SET failures = failures + 1, updated_at = CURRENT_TIMESTAMP
          WHERE identifier = ?
        `).run(identifier);
      } catch (_) {}
    },

    getUserLoginFailures(identifier) {
      try {
        const row = getPrepared(`SELECT failures FROM login_rate_limits WHERE identifier = ?`).get(identifier);
        return row ? (row.failures || 0) : 0;
      } catch (_) {
        return 0;
      }
    },

    recordLoginFailure(identifier, maxFailures = 5, lockMinutes = 15) {
      try {
        const row = getPrepared(`SELECT * FROM login_rate_limits WHERE identifier = ?`).get(identifier);
        const currentFailures = (row ? row.failures : 0) + 1;
        let lockedUntil = null;
        let isLocked = false;
        let retryAfterSec = 0;
        let shouldAlert = false;
        let alerted = row ? (row.alerted || 0) : 0;

        const isIp = identifier.startsWith('ip:');
        if (isIp && currentFailures >= maxFailures) {
          isLocked = true;
          retryAfterSec = lockMinutes * 60;
          lockedUntil = new Date(Date.now() + lockMinutes * 60 * 1000).toISOString();
          if (!alerted) {
            shouldAlert = true;
            alerted = 1;
          }
        }

        getPrepared(`
          INSERT INTO login_rate_limits (identifier, failures, locked_until, alerted, updated_at)
          VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
          ON CONFLICT(identifier) DO UPDATE SET
            failures = ?,
            locked_until = ?,
            alerted = ?,
            updated_at = CURRENT_TIMESTAMP
        `).run(identifier, currentFailures, lockedUntil, alerted, currentFailures, lockedUntil, alerted);

        return { isLocked, failures: currentFailures, retryAfterSec, shouldAlert };
      } catch (err) {
        console.error('[DB Error] recordLoginFailure:', err.message);
        return { isLocked: false, failures: 1, retryAfterSec: 0, shouldAlert: false };
      }
    },

    resetLoginRateLimit(identifier) {
      try {
        getPrepared(`DELETE FROM login_rate_limits WHERE identifier = ?`).run(identifier);
      } catch (_) {}
    },

    // -------------------------------------------------------------------------
    // Audit Logging & Forensics Console
    // -------------------------------------------------------------------------
    insertAuditLog({ action = 'SQL_QUERY', userId, ip = '127.0.0.1', details = '', query = '', durationMs = 0, rowsReturned = 0 }) {
      try {
        getPrepared(`
          INSERT INTO admin_audit_log (action, user_id, ip, details, query, duration_ms, rows_returned, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        `).run(action, userId, ip, details, query, durationMs, rowsReturned);
      } catch (err) {
        console.error('[DB Error] insertAuditLog:', err.message);
      }
    },

    runReadOnlyQuery(sql) {
      const cleanSql = sql.trim();
      if (!/^\s*(SELECT|WITH)\b/i.test(cleanSql)) {
        throw new Error('Solo se permiten consultas SQL de lectura (SELECT o WITH)');
      }
      const stmt = db.prepare(cleanSql);
      return stmt.all();
    },

    // -------------------------------------------------------------------------
    // Retention & Expiration Purger
    // -------------------------------------------------------------------------
    purgeExpiredRecords(retentionDays = 90) {
      const results = {};

      // 1. Purge INFO & PASSED older than 30 days
      const r1 = db.prepare(`DELETE FROM incidents WHERE severity IN ('INFO', 'PASSED') AND timestamp < datetime('now', '-30 days')`).run();
      results.infoPassedPurged = r1.changes;

      // 2. Purge incidents older than RETENTION_DAYS
      const r2 = db.prepare(`DELETE FROM incidents WHERE timestamp < datetime('now', '-' || ? || ' days')`).run(retentionDays);
      results.incidentsPurged = r2.changes;

      // 3. Purge expired auth sessions
      const r3 = db.prepare(`DELETE FROM auth_sessions WHERE expires_at < datetime('now')`).run();
      results.expiredSessionsPurged = r3.changes;

      // 4. Purge expired login rate limits
      const r4 = db.prepare(`DELETE FROM login_rate_limits WHERE locked_until IS NOT NULL AND locked_until < datetime('now')`).run();
      results.rateLimitsPurged = r4.changes;

      // 5. Purge expired IP reputation blocks
      const r5 = db.prepare(`DELETE FROM ip_reputation WHERE block_expires_at IS NOT NULL AND block_expires_at < datetime('now')`).run();
      results.reputationBlocksPurged = r5.changes;

      return results;
    },

    // -------------------------------------------------------------------------
    // Live Hot Backups via VACUUM INTO
    // -------------------------------------------------------------------------
    createBackup(backupDir, backupKeep = 7) {
      if (!fs.existsSync(backupDir)) {
        fs.mkdirSync(backupDir, { recursive: true });
      }

      const now = new Date();
      const pad = n => String(n).padStart(2, '0');
      const timestampStr = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
      const filename = `sentinel-${timestampStr}.sqlite`;
      const backupPath = path.join(backupDir, filename);

      // Execute native SQLite VACUUM INTO
      db.prepare(`VACUUM INTO ?`).run(backupPath);

      // Rotate existing backups
      const files = fs.readdirSync(backupDir)
        .filter(f => f.startsWith('sentinel-') && f.endsWith('.sqlite'))
        .sort();

      while (files.length > backupKeep) {
        const oldest = files.shift();
        try {
          fs.unlinkSync(path.join(backupDir, oldest));
        } catch (_) {}
      }

      return {
        success: true,
        filename,
        backupPath,
        retainedBackups: files.length
      };
    },

    // -------------------------------------------------------------------------
    // Transaction Wrapper
    // -------------------------------------------------------------------------
    transaction(fn) {
      db.exec('BEGIN IMMEDIATE;');
      try {
        const result = fn(db);
        db.exec('COMMIT;');
        return result;
      } catch (err) {
        try { db.exec('ROLLBACK;'); } catch (_) {}
        throw err;
      }
    },

    close() {
      statementCache.clear();
      try {
        db.close();
      } catch (_) {}
    }
  };
}

module.exports = {
  createDatabase
};
