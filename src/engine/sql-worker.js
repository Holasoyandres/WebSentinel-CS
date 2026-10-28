/**
 * WebSentinel-CS :: Isolated SQL Worker Thread
 * Runs administrative queries with query_only restriction outside the event loop
 */

const { parentPort, workerData } = require('node:worker_threads');
const { DatabaseSync } = require('node:sqlite');

try {
  const { dbPath, query } = workerData;
  const db = new DatabaseSync(dbPath);
  try {
    db.exec('PRAGMA query_only = ON;');
  } catch (_) {}

  const stmt = db.prepare(query);
  const rows = stmt.all();
  db.close();

  parentPort.postMessage({ success: true, rows });
} catch (err) {
  parentPort.postMessage({ success: false, error: err.message });
}
