/**
 * WebSentinel-CS :: Authentication & Access Control (P0)
 * Native crypto two-tier authentication: API Keys (SHA-256) & User Sessions (scrypt + CSRF)
 */

const crypto = require('node:crypto');

const PUBLIC_API_PATHS = new Set([
  '/healthz',
  '/api/auth/login'
]);

function hashApiKey(rawKey) {
  return crypto.createHash('sha256').update(rawKey).digest('hex');
}

function verifyScryptPassword(password, salt, storedHash) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  const parts = cookieHeader.split(';');
  for (const part of parts) {
    const [key, val] = part.trim().split('=');
    if (key && val) {
      cookies[key] = decodeURIComponent(val);
    }
  }
  return cookies;
}

function authenticateRequest(req, db, pathname) {
  // 1. Allow strictly public routes
  if (PUBLIC_API_PATHS.has(pathname)) {
    return { authenticated: true, isPublic: true };
  }

  // 2. Check X-Sentinel-Key (Integration API Key)
  const sentinelKey = req.headers['x-sentinel-key'];
  if (sentinelKey && typeof sentinelKey === 'string') {
    const inputHash = hashApiKey(sentinelKey.trim());
    const apiKey = db.findApiKeyByHash(inputHash);
    if (apiKey) {
      const storedBuf = Buffer.from(apiKey.key_hash, 'hex');
      const inputBuf = Buffer.from(inputHash, 'hex');
      if (storedBuf.length === inputBuf.length && crypto.timingSafeEqual(storedBuf, inputBuf)) {
        db.touchApiKey(apiKey.id);
        const scopes = (apiKey.scopes || '').split(',').map(s => s.trim().toLowerCase());
        return {
          authenticated: true,
          type: 'api_key',
          keyId: apiKey.id,
          name: apiKey.name,
          scopes,
          role: 'service'
        };
      }
    }
    return {
      authenticated: false,
      statusCode: 401,
      message: 'X-Sentinel-Key inválida o revocada'
    };
  }

  // 3. Check Session Cookie (Interactive Web Dashboard)
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = cookies['sentinel_session'];
  if (sessionId) {
    const session = db.getAuthSession(sessionId);
    if (session) {
      // CSRF check on state-changing methods
      if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
        // Exception: login endpoint
        if (pathname !== '/api/auth/login') {
          const csrfHeader = req.headers['x-csrf-token'];
          if (!csrfHeader) {
            return {
              authenticated: false,
              statusCode: 403,
              message: 'Token CSRF ausente en petición de modificación'
            };
          }
          const csrfInputBuf = Buffer.from(csrfHeader);
          const csrfStoredBuf = Buffer.from(session.csrf_token);
          if (csrfInputBuf.length !== csrfStoredBuf.length || !crypto.timingSafeEqual(csrfInputBuf, csrfStoredBuf)) {
            return {
              authenticated: false,
              statusCode: 403,
              message: 'Token CSRF inválido o no coincidente'
            };
          }
        }
      }

      return {
        authenticated: true,
        type: 'session',
        user: {
          id: session.user_id,
          username: session.username,
          role: session.role
        },
        session
      };
    }
  }

  // 4. Default: No valid credentials supplied
  return {
    authenticated: false,
    statusCode: 401,
    message: 'Autenticación requerida: Proporcione X-Sentinel-Key o sesión de analista válida'
  };
}

module.exports = {
  PUBLIC_API_PATHS,
  hashApiKey,
  verifyScryptPassword,
  parseCookies,
  authenticateRequest
};
