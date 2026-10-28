/**
 * WebSentinel-CS :: Entry Point
 * Architecture: Standalone Out-of-Band Security Sentinel
 * Author: Holasoyandres (MIT License)
 */

const config = require('./src/config');
const { createDatabase } = require('./src/db');
const { createApp } = require('./src/app');

const db = createDatabase(config.DB_PATH);
const { server } = createApp({ config, db });

server.listen(config.PORT, config.HOST, () => {
  console.log(`[WebSentinel-CS Engine] Daemon active: http://${config.HOST}:${config.PORT} (v${config.VERSION})`);
  console.log(`[WebSentinel-CS Storage] SQLite Database: ${config.DB_PATH}`);
});

function handleShutdown() {
  console.log('\n[WebSentinel-CS] Shutting down daemon cleanly...');
  server.close(() => {
    db.close();
    console.log('[WebSentinel-CS] Server and database closed.');
    process.exit(0);
  });
}

process.on('SIGINT', handleShutdown);
process.on('SIGTERM', handleShutdown);
