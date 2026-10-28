/**
 * WebSentinel-CS :: Sliding-Window Rate Limiter Engine
 */

function createRateLimiter(options = {}) {
  const windowMs = options.windowMs || 60 * 1000; // 1 minute
  const maxFailures = options.maxFailures || 5;
  const ipAttempts = new Map();

  return {
    evaluate(ip, isFailed) {
      const now = Date.now();
      let timestamps = ipAttempts.get(ip) || [];
      timestamps = timestamps.filter(t => (now - t) < windowMs);

      if (isFailed) {
        timestamps.push(now);
      }
      ipAttempts.set(ip, timestamps);

      const isBlocked = timestamps.length >= maxFailures;
      return {
        isBlocked,
        recentFailures: timestamps.length,
        threshold: maxFailures,
        retryAfterSec: isBlocked ? Math.ceil((timestamps[0] + windowMs - now) / 1000) : 0
      };
    },

    clear(ip) {
      if (ip) {
        ipAttempts.delete(ip);
      } else {
        ipAttempts.clear();
      }
    }
  };
}

module.exports = { createRateLimiter };
