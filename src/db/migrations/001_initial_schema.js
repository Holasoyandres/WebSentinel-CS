/**
 * WebSentinel-CS :: Migration 001 - Initial Schema
 */

module.exports = {
  version: 1,
  name: '001_initial_schema',
  up(db) {
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
        details TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS endpoint_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_url TEXT NOT NULL,
        scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        status_code INTEGER,
        security_score INTEGER,
        missing_headers_count INTEGER,
        latency_ms INTEGER
      );

      CREATE TABLE IF NOT EXISTS user_sessions (
        session_id TEXT PRIMARY KEY,
        user_identifier TEXT NOT NULL,
        role TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        login_portal TEXT NOT NULL,
        user_agent TEXT NOT NULL,
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

      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        key_hash TEXT NOT NULL UNIQUE,
        scopes TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used_at DATETIME
      );

      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'analyst',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS auth_sessions (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        csrf_token TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS login_rate_limits (
        identifier TEXT PRIMARY KEY,
        failures INTEGER DEFAULT 0,
        locked_until DATETIME,
        alerted INTEGER DEFAULT 0,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS admin_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        query TEXT NOT NULL,
        duration_ms INTEGER NOT NULL,
        rows_returned INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
      CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_identifier);
      CREATE INDEX IF NOT EXISTS idx_activities_session ON session_activities(session_id);
      CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
      CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id);
    `);
  }
};
