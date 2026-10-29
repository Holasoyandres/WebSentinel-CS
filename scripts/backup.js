#!/usr/bin/env node
/**
 * WebSentinel-CS :: Database Hot Backup Utility
 * Generates point-in-time snapshot using native SQLite VACUUM INTO and rotates old archives
 * Usage: npm run backup
 */

const config = require('../src/config');
const { createDatabase } = require('../src/db');

console.log('[WebSentinel Backup] Inicializando snapshot caliente de SQLite...');
const db = createDatabase(config.DB_PATH);

try {
  const result = db.createBackup(config.BACKUP_DIR, config.BACKUP_KEEP);
  console.log(`
===================================================================
WebSentinel-CS :: Respaldo Creado Exitosamente
===================================================================
Archivo:     ${result.filename}
Ruta:        ${result.backupPath}
Retenidos:   ${result.retainedBackups} copias (Rotación activa: ${config.BACKUP_KEEP})
===================================================================
  `);
  process.exit(0);
} catch (err) {
  console.error('[WebSentinel Backup Error]:', err.message);
  process.exit(1);
} finally {
  db.close();
}
