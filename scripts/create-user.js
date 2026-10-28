#!/usr/bin/env node
/**
 * WebSentinel-CS :: Provision Dashboard User CLI
 * Creates administrative or analyst accounts using native scrypt hashing
 * Usage: node scripts/create-user.js <username> <password> [role]
 */

const crypto = require('node:crypto');
const config = require('../src/config');
const { createDatabase } = require('../src/db');

const username = process.argv[2];
const password = process.argv[3];
const role = (process.argv[4] || 'analyst').toLowerCase();

if (!username || !password) {
  console.error('Uso: node scripts/create-user.js <username> <password> [admin|analyst]');
  process.exit(1);
}

if (!['admin', 'analyst'].includes(role)) {
  console.error('Rol inválido. Debe ser "admin" o "analyst".');
  process.exit(1);
}

const db = createDatabase(config.DB_PATH);

const salt = crypto.randomBytes(16).toString('hex');
const passwordHash = crypto.scryptSync(password, salt, 64).toString('hex');
const userId = 'usr-' + crypto.randomBytes(6).toString('hex');

try {
  db.raw.prepare(`
    INSERT INTO users (id, username, password_hash, salt, role, created_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
  `).run(userId, username, passwordHash, salt, role);

  console.log(`
===================================================================
WebSentinel-CS :: Usuario de Panel Registrado Exitosamente
===================================================================
ID Usuario: ${userId}
Usuario:    ${username}
Rol:        ${role}
Cifrado:    scrypt (N=16384, r=8, p=1, length=64)
===================================================================
`);
} catch (err) {
  if (err.message.includes('UNIQUE constraint failed')) {
    console.error(`Error: El usuario "${username}" ya existe en el sistema.`);
  } else {
    console.error('[Error al crear usuario]:', err.message);
  }
  process.exit(1);
} finally {
  db.close();
}
