/**
 * WebSentinel-CS :: Isolated SQL Child Process
 * Executes analytical queries in an isolated operating system process
 * Allows reliable SIGKILL termination upon timeout without event-loop hangs
 */

const { DatabaseSync } = require('node:sqlite');

const SENSITIVE_TABLES = new Set([
  'users',
  'auth_sessions',
  'api_keys',
  'admin_audit_log',
  'login_rate_limits'
]);

process.on('message', (msg) => {
  try {
    const { dbPath, query } = msg;
    const db = new DatabaseSync(dbPath, { readOnly: true });

    // Native kernel-level table access authorizer
    db.setAuthorizer((action, arg1) => {
      if (arg1 && SENSITIVE_TABLES.has(String(arg1).toLowerCase())) {
        return 1; // SQLITE_DENY
      }
      return 0; // SQLITE_OK
    });

    db.exec('PRAGMA query_only = ON;');

    const stmt = db.prepare(query);
    const rows = stmt.all();
    db.close();

    if (process.send) {
      process.send({ success: true, rows });
    }
    process.exit(0);
  } catch (err) {
    if (process.send) {
      process.send({ success: false, error: err.message });
    }
    process.exit(1);
  }
});
