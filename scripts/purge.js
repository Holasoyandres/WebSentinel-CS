#!/usr/bin/env node
/**
 * WebSentinel-CS :: Retention & Expiration Purger
 * Purges expired sessions, rate limits, reputation blocks, and telemetry older than RETENTION_DAYS
 * Usage: npm run purge
 */

const config = require('../src/config');
const { createDatabase } = require('../src/db');

console.log(`[WebSentinel Purge] Ejecutando purga con RETENTION_DAYS=${config.RETENTION_DAYS}...`);
const db = createDatabase(config.DB_PATH);

try {
  const result = db.purgeExpiredRecords(config.RETENTION_DAYS);
  console.log(`
===================================================================
WebSentinel-CS :: Mantenimiento y Purga Completada
===================================================================
Eventos INFO/PASSED (>30d):      ${result.infoPassedPurged} purgados
Incidentes antiguos (>retención): ${result.incidentsPurged} purgados
Sesiones expiradas:              ${result.expiredSessionsPurged} purgadas
Bloqueos de login expirados:     ${result.rateLimitsPurged} purgados
Bloqueos de reputación IP:       ${result.reputationBlocksPurged} purgados
===================================================================
  `);
  process.exit(0);
} catch (err) {
  console.error('[WebSentinel Purge Error]:', err.message);
  process.exit(1);
} finally {
  db.close();
}
