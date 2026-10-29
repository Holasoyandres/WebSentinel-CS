/**
 * WebSentinel-CS :: Configuration Module
 * Single Source of Truth for environment and application settings
 */

const path = require('node:path');

const env = process.env;

const config = {
  VERSION: '1.3.0',
  ENV: env.NODE_ENV || 'production',
  HOST: env.HOST || '127.0.0.1',
  PORT: parseInt(env.PORT || '4000', 10),
  DB_PATH: env.DB_PATH || path.join(__dirname, '..', 'data', 'sentinel.sqlite'),
  DEMO_MODE: env.DEMO_MODE === 'true',
  TRUST_PROXIES: env.TRUST_PROXIES === 'true',
  CORS_ORIGINS: env.CORS_ORIGINS
    ? env.CORS_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
    : ['http://127.0.0.1:4000', 'http://localhost:4000'],
  SCAN_ALLOWLIST: env.SCAN_ALLOWLIST
    ? env.SCAN_ALLOWLIST.split(',').map(s => s.trim()).filter(Boolean)
    : [], // Default is empty: private networks or local scanning must be explicitly declared in .env
  RETENTION_DAYS: parseInt(env.RETENTION_DAYS || '90', 10),
  STORE_PASSED_EVENTS: env.STORE_PASSED_EVENTS === 'true', // Default false: pass events aggregate daily, not stored row by row
  BACKUP_KEEP: parseInt(env.BACKUP_KEEP || '7', 10),
  BACKUP_DIR: env.BACKUP_DIR || path.join(__dirname, '..', 'data', 'backups'),
  ANOMALY_THRESHOLD: parseInt(env.ANOMALY_THRESHOLD || '5', 10),
  LOG_LEVEL: env.LOG_LEVEL || 'info',
  MAX_BODY_BYTES: parseInt(env.MAX_BODY_BYTES || '1048576', 10) // 1 MB
};

module.exports = config;
