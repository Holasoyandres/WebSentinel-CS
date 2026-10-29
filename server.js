/**
 * WebSentinel-CS :: Entry Point
 * Architecture: Standalone Out-of-Band Security Sentinel (FASE 2)
 * Features: Structured logging, WAL database, and 10s graceful shutdown draining
 */

const config = require('./src/config');
const { createLogger } = require('./src/logger');
const { createDatabase } = require('./src/db');
const { createApp } = require('./src/app');

const logger = createLogger(config.LOG_LEVEL);
const db = createDatabase(config.DB_PATH);
const { server } = createApp({ config, db });

server.listen(config.PORT, config.HOST, () => {
  logger.info('WebSentinel-CS Daemon activo', {
    version: config.VERSION,
    host: config.HOST,
    port: config.PORT,
    dbPath: config.DB_PATH,
    env: config.ENV
  });
});

let isShuttingDown = false;

function handleShutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;

  logger.info(`Señal ${signal} recibida: iniciando apagado ordenado...`, { timeoutMs: 10000 });

  // Stop accepting new connections
  server.close(() => {
    try {
      db.close();
      logger.info('Servidor HTTP y base de datos SQLite cerrados limpiamente');
      process.exit(0);
    } catch (err) {
      logger.error('Error al cerrar base de datos:', { error: err.message });
      process.exit(1);
    }
  });

  // Force shutdown if active requests do not drain within 10 seconds
  const forceTimer = setTimeout(() => {
    logger.warn('Tiempo de espera de drenado (10s) agotado. Forzando terminación');
    try { db.close(); } catch (_) {}
    process.exit(1);
  }, 10000);

  if (forceTimer.unref) forceTimer.unref();
}

process.on('SIGINT', () => handleShutdown('SIGINT'));
process.on('SIGTERM', () => handleShutdown('SIGTERM'));

process.on('uncaughtException', (err) => {
  logger.error('Excepción no capturada en tiempo de ejecución', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error('Rechazo no controlado de promesa', { reason: String(reason) });
  process.exit(1);
});
