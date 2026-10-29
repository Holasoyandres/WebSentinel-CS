/**
 * WebSentinel-CS :: Migration 003 - Schema Alignment for Sessions & Rate Limiting
 */

function safeAddColumn(db, table, columnDef) {
  try {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${columnDef};`);
  } catch (err) {
    // Column already exists or table cannot be altered - safe to ignore
  }
}

module.exports = {
  version: 3,
  name: '003_align_schema',
  up(db) {
    // 1. Ensure login_rate_limits has alerted column
    safeAddColumn(db, 'login_rate_limits', 'alerted INTEGER DEFAULT 0');

    // 2. Ensure auth_sessions table uses token_hash as primary key
    const sessionCols = db.prepare("PRAGMA table_info(auth_sessions)").all();
    const hasTokenHash = sessionCols.some(c => c.name === 'token_hash');

    if (!hasTokenHash) {
      db.exec(`
        DROP TABLE IF EXISTS auth_sessions;
        CREATE TABLE auth_sessions (
          token_hash TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          csrf_token TEXT NOT NULL,
          expires_at DATETIME NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id);
      `);
    }
  }
};
