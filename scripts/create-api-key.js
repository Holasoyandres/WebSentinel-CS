#!/usr/bin/env node
/**
 * WebSentinel-CS :: Provision API Key CLI
 * Generates high-entropy API key for integrations (Laravel Middleware, Daemons)
 * Usage: node scripts/create-api-key.js [name] [scopes]
 */

const crypto = require('node:crypto');
const path = require('node:path');
const config = require('../src/config');
const { createDatabase } = require('../src/db');

const name = process.argv[2] || 'Laravel-Integration';
const scopes = process.argv[3] || 'ingest,read';

const db = createDatabase(config.DB_PATH);

const rawSecret = 'ws_' + crypto.randomBytes(24).toString('hex');
const keyHash = crypto.createHash('sha256').update(rawSecret).digest('hex');
const keyId = 'key-' + crypto.randomBytes(6).toString('hex');

try {
  db.raw.prepare(`
    INSERT INTO api_keys (id, name, key_hash, scopes, created_at)
    VALUES (?, ?, ?, ?, datetime('now'))
  `).run(keyId, name, keyHash, scopes);

  console.log(`
===================================================================
WebSentinel-CS :: Clave API Creada Exitosamente
===================================================================
ID Identificador: ${keyId}
Nombre Asignado:  ${name}
Permisos (Scopes):${scopes}

API Key Secreta:  ${rawSecret}
===================================================================
ATENCIÓN: Guarde esta clave en su archivo .env (X-Sentinel-Key).
Por seguridad, el daemon solo almacena su huella criptográfica SHA-256
y la clave no podrá ser recuperada después.
===================================================================
`);
} catch (err) {
  console.error('[Error al crear API Key]:', err.message);
  process.exit(1);
} finally {
  db.close();
}
