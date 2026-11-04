/**
 * WebSentinel-CS :: Migration 004 - Integrity Checkpoints for Log Purging
 */

module.exports = {
  version: 4,
  name: '004_integrity_checkpoints',
  up(db) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS integrity_checkpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        checkpoint_hash TEXT NOT NULL,
        purged_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);
  }
};
