/**
 * WebSentinel-CS :: Isolated SQL Worker Thread
 * Runs administrative queries in strictly read-only mode with setAuthorizer table protections
 */

const { parentPort, workerData } = require('node:worker_threads');
const { DatabaseSync } = require('node:sqlite');

const SENSITIVE_TABLES = new Set([
  'users',
  'auth_sessions',
  'api_keys',
  'admin_audit_log',
  'login_rate_limits'
]);

try {
  const { dbPath, query } = workerData;
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

  parentPort.postMessage({ success: true, rows });
} catch (err) {
  parentPort.postMessage({ success: false, error: err.message });
}
