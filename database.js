/**
 * WebSentinel-CS :: Legacy compatibility adapter for ./src/db
 */

const config = require('./src/config');
const { createDatabase } = require('./src/db');

module.exports = createDatabase(config.DB_PATH);
