/**
 * WebSentinel-CS :: Migration 002 - Phase 2 Forensics, Integrity & Persistence
 */

function safeAddColumn(db, table, columnDef) {
  try {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${columnDef};`);
  } catch (err) {
    // Column already exists or table cannot be altered - safe to ignore
  }
}

module.exports = {
  version: 2,
  name: '002_phase2_integrity',
  up(db) {
    // 1. Incidents Forensics & Cryptographic Hash Chaining
    safeAddColumn(db, 'incidents', 'is_simulated INTEGER DEFAULT 0');
    safeAddColumn(db, 'incidents', 'prev_hash TEXT');
    safeAddColumn(db, 'incidents', 'hash TEXT');

    // 2. User Sessions & Activities Simulation Segregation
    safeAddColumn(db, 'user_sessions', 'is_simulated INTEGER DEFAULT 0');
    safeAddColumn(db, 'session_activities', 'is_simulated INTEGER DEFAULT 0');

    // 3. Persistent IP Reputation Rate Limiter
    db.exec(`
      CREATE TABLE IF NOT EXISTS ip_reputation (
        ip TEXT PRIMARY KEY,
        failed_attempts INTEGER DEFAULT 0,
        block_expires_at DATETIME,
        reputation_score INTEGER DEFAULT 100,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_ip_reputation_blocked ON ip_reputation(block_expires_at);
    `);

    // 4. Aggregated Daily Metrics (for persistent stats & high-throughput mode)
    db.exec(`
      CREATE TABLE IF NOT EXISTS daily_metrics (
        date TEXT PRIMARY KEY,
        inspections_count INTEGER DEFAULT 0,
        threats_count INTEGER DEFAULT 0,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 5. Expanded Admin Panel Audit Log
    safeAddColumn(db, 'admin_audit_log', "action TEXT DEFAULT 'SQL_QUERY'");
    safeAddColumn(db, 'admin_audit_log', "ip TEXT DEFAULT '127.0.0.1'");
    safeAddColumn(db, 'admin_audit_log', 'details TEXT');

    // 6. Performance Indexes
    db.exec(`
      CREATE INDEX IF NOT EXISTS idx_incidents_simulated ON incidents(is_simulated);
      CREATE INDEX IF NOT EXISTS idx_sessions_simulated ON user_sessions(is_simulated);
    `);
  }
};
