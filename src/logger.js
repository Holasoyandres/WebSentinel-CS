/**
 * WebSentinel-CS :: Structured JSON Logger
 * Formats operational messages as single-line JSON streams to stdout/stderr
 */

const LEVELS = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 100
};

function createLogger(levelName = 'info') {
  const currentThreshold = LEVELS[String(levelName).toLowerCase()] || LEVELS.info;

  function writeLog(level, msg, meta = {}) {
    if (LEVELS[level] < currentThreshold) return;

    const entry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message: typeof msg === 'string' ? msg : (msg && msg.message) || String(msg),
      ...meta
    };

    const out = JSON.stringify(entry) + '\n';
    if (level === 'error') {
      process.stderr.write(out);
    } else {
      process.stdout.write(out);
    }
  }

  return {
    debug: (msg, meta) => writeLog('debug', msg, meta),
    info: (msg, meta) => writeLog('info', msg, meta),
    warn: (msg, meta) => writeLog('warn', msg, meta),
    error: (msg, meta) => writeLog('error', msg, meta)
  };
}

module.exports = {
  createLogger
};
