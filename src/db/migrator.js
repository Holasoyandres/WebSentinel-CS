/**
 * WebSentinel-CS :: Database Migrator
 * Runs versioned database migrations with automatic rollback and state tracking
 */

const fs = require('node:fs');
const path = require('node:path');

function runMigrations(db) {
  // Ensure schema_migrations exists
  db.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const appliedRows = db.prepare(`SELECT version FROM schema_migrations`).all();
  const appliedVersions = new Set(appliedRows.map(r => r.version));

  const migrationsDir = path.join(__dirname, 'migrations');
  if (!fs.existsSync(migrationsDir)) {
    return;
  }

  const files = fs.readdirSync(migrationsDir)
    .filter(f => f.endsWith('.js'))
    .sort();

  for (const file of files) {
    const migrationPath = path.join(migrationsDir, file);
    const migration = require(migrationPath);

    if (migration.version && !appliedVersions.has(migration.version)) {
      try {
        db.exec('BEGIN IMMEDIATE;');
        migration.up(db);
        db.prepare(`
          INSERT INTO schema_migrations (version, name, applied_at)
          VALUES (?, ?, datetime('now'))
        `).run(migration.version, migration.name || file);
        db.exec('COMMIT;');
      } catch (err) {
        try { db.exec('ROLLBACK;'); } catch (_) {}
        throw new Error(`[Migration Error] Failed applying ${file}: ${err.message}`);
      }
    }
  }
}

module.exports = {
  runMigrations
};
