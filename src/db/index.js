/**
 * WebSentinel-CS :: Database Engine
 * Native SQLite storage using Node.js DatabaseSync
 */

const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');

function createDatabase(dbPath) {
  if (dbPath !== ':memory:') {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const db = new DatabaseSync(dbPath);

  // Initialize SQLite Schema
  db.exec(`
    CREATE TABLE IF NOT EXISTS incidents (
      id TEXT PRIMARY KEY,
      timestamp DATETIME NOT NULL,
      severity TEXT NOT NULL,
      type TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      source_ip TEXT NOT NULL,
      target TEXT NOT NULL,
      action TEXT NOT NULL,
      details TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS ip_reputation (
      ip TEXT PRIMARY KEY,
      failed_attempts INTEGER DEFAULT 0,
      is_blocked INTEGER DEFAULT 0,
      block_expires_at DATETIME,
      first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS endpoint_scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_url TEXT NOT NULL,
      status_code INTEGER,
      security_score INTEGER,
      missing_headers_count INTEGER,
      latency_ms INTEGER,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS user_sessions (
      session_id TEXT PRIMARY KEY,
      user_identifier TEXT NOT NULL,
      role TEXT DEFAULT 'USUARIO',
      ip_address TEXT NOT NULL,
      login_portal TEXT NOT NULL,
      user_agent TEXT,
      status TEXT DEFAULT 'ACTIVA',
      login_time DATETIME NOT NULL,
      logout_time DATETIME,
      duration_minutes INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS session_activities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      timestamp DATETIME NOT NULL,
      action_type TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      description TEXT NOT NULL,
      risk_level TEXT DEFAULT 'NORMAL',
      FOREIGN KEY (session_id) REFERENCES user_sessions(session_id)
    );

    CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_identifier);
    CREATE INDEX IF NOT EXISTS idx_activities_session ON session_activities(session_id);
  `);

  return {
    raw: db,

    insertIncident(event) {
      try {
        const stmt = db.prepare(`
          INSERT INTO incidents (id, timestamp, severity, type, rule_id, source_ip, target, action, details)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
          event.details
        );
      } catch (err) {
        console.error('[DB Error] Failed to insert incident:', err.message);
      }
    },

    getIncidents(limit = 100, severity = 'ALL') {
      try {
        const parsedLimit = Math.max(1, Math.min(500, parseInt(limit, 10) || 100));
        if (severity === 'ALL') {
          const stmt = db.prepare(`SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?`);
          return stmt.all(parsedLimit);
        } else {
          const stmt = db.prepare(`SELECT * FROM incidents WHERE severity = ? ORDER BY timestamp DESC LIMIT ?`);
          return stmt.all(severity, parsedLimit);
        }
      } catch (err) {
        console.error('[DB Error] Failed to query incidents:', err.message);
        return [];
      }
    },

    saveScanResult(scan) {
      try {
        const stmt = db.prepare(`
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
      } catch (err) {
        console.error('[DB Error] Failed to save scan:', err.message);
      }
    },

    createSession(data) {
      try {
        const sessionId = 'SESS-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substr(2, 4).toUpperCase();
        const loginTime = new Date().toISOString();
        const stmt = db.prepare(`
          INSERT INTO user_sessions (session_id, user_identifier, role, ip_address, login_portal, user_agent, status, login_time, logout_time, duration_minutes)
          VALUES (?, ?, ?, ?, ?, ?, 'ACTIVA', ?, NULL, 0)
        `);
        stmt.run(
          sessionId,
          data.user_identifier || 'usuario.anonimo',
          data.role || 'USUARIO',
          data.ip_address || '127.0.0.1',
          data.login_portal || '/auth/login',
          data.user_agent || 'Standard Web Client',
          loginTime
        );

        this.recordActivity(sessionId, 'AUTH_LOGIN', data.login_portal || '/auth/login', 'Inicio de sesión verificado.', 'NORMAL');
        return sessionId;
      } catch (err) {
        console.error('[DB Error] Failed to create session:', err.message);
        return null;
      }
    },

    recordActivity(sessionId, actionType, endpoint, description, riskLevel = 'NORMAL') {
      try {
        const stmt = db.prepare(`
          INSERT INTO session_activities (session_id, timestamp, action_type, endpoint, description, risk_level)
          VALUES (?, ?, ?, ?, ?, ?)
        `);
        stmt.run(
          sessionId,
          new Date().toISOString(),
          actionType,
          endpoint,
          description,
          riskLevel
        );
      } catch (err) {
        console.error('[DB Error] Failed to record activity:', err.message);
      }
    },

    closeSession(sessionId) {
      try {
        const sess = db.prepare(`SELECT login_time FROM user_sessions WHERE session_id = ?`).get(sessionId);
        const logoutTime = new Date().toISOString();
        let durationMinutes = 1;
        if (sess && sess.login_time) {
          const diffMs = new Date(logoutTime) - new Date(sess.login_time);
          durationMinutes = Math.max(1, Math.round(diffMs / 60000));
        }

        const stmt = db.prepare(`
          UPDATE user_sessions 
          SET status = 'CERRADA', logout_time = ?, duration_minutes = ?
          WHERE session_id = ?
        `);
        stmt.run(logoutTime, durationMinutes, sessionId);

        this.recordActivity(sessionId, 'AUTH_LOGOUT', '/auth/logout', 'Cierre voluntario de sesión.', 'NORMAL');
        return true;
      } catch (err) {
        console.error('[DB Error] Failed to close session:', err.message);
        return false;
      }
    },

    getUserSessions(limit = 50) {
      try {
        const parsedLimit = Math.max(1, Math.min(500, parseInt(limit, 10) || 50));
        const sessions = db.prepare(`
          SELECT s.*, 
            (SELECT COUNT(*) FROM session_activities WHERE session_id = s.session_id) as total_activities
          FROM user_sessions s
          ORDER BY s.login_time DESC
          LIMIT ?
        `).all(parsedLimit);

        return sessions;
      } catch (err) {
        console.error('[DB Error] Failed to get sessions:', err.message);
        return [];
      }
    },

    getSessionActivities(sessionId) {
      try {
        const stmt = db.prepare(`
          SELECT * FROM session_activities 
          WHERE session_id = ? 
          ORDER BY timestamp ASC
        `);
        return stmt.all(sessionId);
      } catch (err) {
        console.error('[DB Error] Failed to get session activities:', err.message);
        return [];
      }
    },

    getAnalyticsSummary() {
      try {
        const totalIncidents = db.prepare(`SELECT COUNT(*) as count FROM incidents`).get().count;
        const criticalCount = db.prepare(`SELECT COUNT(*) as count FROM incidents WHERE severity IN ('CRITICAL', 'HIGH')`).get().count;
        const activeSessions = db.prepare(`SELECT COUNT(*) as count FROM user_sessions WHERE status = 'ACTIVA'`).get().count;
        const totalActivities = db.prepare(`SELECT COUNT(*) as count FROM session_activities`).get().count;
        
        const topIps = db.prepare(`
          SELECT source_ip, COUNT(*) as hits 
          FROM incidents 
          GROUP BY source_ip 
          ORDER BY hits DESC 
          LIMIT 5
        `).all();

        const severityDistribution = db.prepare(`
          SELECT severity, COUNT(*) as count 
          FROM incidents 
          GROUP BY severity
        `).all();

        return {
          totalIncidents,
          criticalCount,
          activeSessions,
          totalActivities,
          topIps,
          severityDistribution
        };
      } catch (err) {
        console.error('[DB Error] Analytics failed:', err.message);
        return { totalIncidents: 0, criticalCount: 0, activeSessions: 0, totalActivities: 0, topIps: [], severityDistribution: [] };
      }
    },

    runReadOnlyQuery(sql) {
      const cleanSql = sql.trim();
      if (!/^\s*SELECT\b/i.test(cleanSql) && !/^\s*WITH\b/i.test(cleanSql)) {
        throw new Error('Solo se permiten consultas SQL de lectura (SELECT)');
      }
      const stmt = db.prepare(cleanSql);
      return stmt.all();
    },

    close() {
      try {
        db.close();
      } catch (err) {
        // ignore if already closed
      }
    }
  };
}

module.exports = { createDatabase };
