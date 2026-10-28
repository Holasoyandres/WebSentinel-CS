/**
 * WebSentinel-CS :: Native SQLite Storage & Forensics Engine
 * Powered by Node.js 24 Native DatabaseSync (Zero external npm packages)
 */

const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'sentinel.sqlite');
const db = new DatabaseSync(DB_PATH);

// Initialize Enterprise SQL Schema
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

// Seed Initial Enterprise Sessions if table is empty
function seedSampleSessionsIfEmpty() {
  const count = db.prepare(`SELECT count(*) as total FROM user_sessions`).get().total;
  if (count === 0) {
    const now = Date.now();
    const samples = [
      {
        session_id: 'SESS-USR-8921',
        user_identifier: 'carlos.mendoza@eaav.local',
        role: 'AUDITOR_SISTEMAS',
        ip_address: '172.16.0.45',
        login_portal: '/admin/seguridad',
        user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0',
        status: 'ACTIVA',
        login_time: new Date(now - 45 * 60 * 1000).toISOString(),
        logout_time: null,
        duration_minutes: 45,
        activities: [
          { action_type: 'AUTH_LOGIN', endpoint: '/admin/login', desc: 'Inicio de sesión exitoso con credenciales corporativas y MFA.', risk: 'NORMAL', timeOffset: 45 },
          { action_type: 'VIEW_AUDIT_LOGS', endpoint: '/admin/logs', desc: 'Consultó el registro de auditoría de trámites radicados en el mes.', risk: 'NORMAL', timeOffset: 40 },
          { action_type: 'EXPORT_REPORT', endpoint: '/admin/reports/export?format=xlsx', desc: 'Descargó exportación confidencial de solicitudes ciudadanas.', risk: 'ELEVATED', timeOffset: 25 },
          { action_type: 'CONFIG_CHECK', endpoint: '/admin/config/firewall', desc: 'Verificó estado de las políticas de firewall perimetral.', risk: 'NORMAL', timeOffset: 10 }
        ]
      },
      {
        session_id: 'SESS-USR-8919',
        user_identifier: 'mariana.lopez@atencion.local',
        role: 'OFICIAL_RADICACION',
        ip_address: '172.16.0.112',
        login_portal: '/portal/tramites-suit',
        user_agent: 'Mozilla/5.0 (X11; Linux x86_64) Firefox/129.0',
        status: 'CERRADA',
        login_time: new Date(now - 140 * 60 * 1000).toISOString(),
        logout_time: new Date(now - 55 * 60 * 1000).toISOString(),
        duration_minutes: 85,
        activities: [
          { action_type: 'AUTH_LOGIN', endpoint: '/portal/login', desc: 'Autenticación en ventanilla única de atención.', risk: 'NORMAL', timeOffset: 140 },
          { action_type: 'CREATE_RECORD', endpoint: '/api/tramites/radicar', desc: 'Radicó trámite SUIT #48291 (Solicitud de conexión red principal).', risk: 'NORMAL', timeOffset: 120 },
          { action_type: 'ATTACH_DOCUMENT', endpoint: '/api/tramites/documentos/upload', desc: 'Adjuntó certificado de estratificación catastral (PDF 1.4 MB).', risk: 'NORMAL', timeOffset: 105 },
          { action_type: 'UPDATE_STATUS', endpoint: '/api/tramites/48291/estado', desc: 'Cambió estado del trámite a "EN_REVISION_TECNICA".', risk: 'NORMAL', timeOffset: 70 },
          { action_type: 'AUTH_LOGOUT', endpoint: '/portal/logout', desc: 'Cierre voluntario de sesión por fin de turno.', risk: 'NORMAL', timeOffset: 55 }
        ]
      },
      {
        session_id: 'SESS-USR-8914',
        user_identifier: 'soporte.externo_contratista',
        role: 'CONSULTOR_BD',
        ip_address: '190.85.12.98',
        login_portal: '/denuncias/admin',
        user_agent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15',
        status: 'CERRADA',
        login_time: new Date(now - 280 * 60 * 1000).toISOString(),
        logout_time: new Date(now - 210 * 60 * 1000).toISOString(),
        duration_minutes: 70,
        activities: [
          { action_type: 'AUTH_LOGIN', endpoint: '/denuncias/admin.html', desc: 'Acceso administrativo remoto mediante VPN corporativa.', risk: 'NORMAL', timeOffset: 280 },
          { action_type: 'QUERY_RECORDS', endpoint: '/api/denuncias/list?limit=50', desc: 'Consultó bandeja de denuncias ciudadanas de corrupción.', risk: 'NORMAL', timeOffset: 260 },
          { action_type: 'SUSPICIOUS_QUERY', endpoint: '/api/denuncias/export_all.php', desc: 'Intentó ejecutar endpoint no autorizado de volcado masivo. Bloqueado.', risk: 'CRITICAL', timeOffset: 230 },
          { action_type: 'AUTH_LOGOUT', endpoint: '/admin/logout', desc: 'Sesión terminada tras advertencia de política de seguridad.', risk: 'HIGH', timeOffset: 210 }
        ]
      }
    ];

    const insertSess = db.prepare(`
      INSERT INTO user_sessions (session_id, user_identifier, role, ip_address, login_portal, user_agent, status, login_time, logout_time, duration_minutes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertAct = db.prepare(`
      INSERT INTO session_activities (session_id, timestamp, action_type, endpoint, description, risk_level)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    for (const s of samples) {
      insertSess.run(
        s.session_id,
        s.user_identifier,
        s.role,
        s.ip_address,
        s.login_portal,
        s.user_agent,
        s.status,
        s.login_time,
        s.logout_time,
        s.duration_minutes
      );

      for (const a of s.activities) {
        insertAct.run(
          s.session_id,
          new Date(now - a.timeOffset * 60 * 1000).toISOString(),
          a.action_type,
          a.endpoint,
          a.desc,
          a.risk
        );
      }
    }
  }
}

seedSampleSessionsIfEmpty();

module.exports = {
  db,

  // Insert Incident
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

  // Retrieve Incidents
  getIncidents(limit = 100, severity = 'ALL') {
    try {
      if (severity === 'ALL') {
        const stmt = db.prepare(`SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?`);
        return stmt.all(limit);
      } else {
        const stmt = db.prepare(`SELECT * FROM incidents WHERE severity = ? ORDER BY timestamp DESC LIMIT ?`);
        return stmt.all(severity, limit);
      }
    } catch (err) {
      console.error('[DB Error] Failed to query incidents:', err.message);
      return [];
    }
  },

  // Save Scan Result
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

  // User Session Management
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

      // Record first action: Login
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
      const sessions = db.prepare(`
        SELECT s.*, 
          (SELECT COUNT(*) FROM session_activities WHERE session_id = s.session_id) as total_activities
        FROM user_sessions s
        ORDER BY s.login_time DESC
        LIMIT ?
      `).all(limit);

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

  // Aggregated SQL Analytics
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

  // Read-only SQL Query Runner for Forensic Analyst
  runReadOnlyQuery(sql) {
    const cleanSql = sql.trim();
    if (!/^\s*SELECT\b/i.test(cleanSql) && !/^\s*WITH\b/i.test(cleanSql)) {
      throw new Error('Solo se permiten consultas SQL de lectura (SELECT)');
    }
    const stmt = db.prepare(cleanSql);
    return stmt.all();
  }
};
