/**
 * WebSentinel-CS :: PM2 Production Process Manager Configuration
 */

module.exports = {
  apps: [
    {
      name: 'websentinel-cs',
      script: './server.js',
      instances: 1, // Standalone SQLite sentinel runs as single authority instance
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '500M',
      kill_timeout: 10000,
      env: {
        NODE_ENV: 'production',
        HOST: '127.0.0.1',
        PORT: 4000,
        TRUST_PROXIES: 'true',
        LOG_LEVEL: 'info'
      }
    }
  ]
};
