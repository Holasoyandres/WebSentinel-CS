/**
 * WebSentinel-CS :: HTTP Response Utilities
 * Centralized response handlers with OWASP recommended security headers, strict CORS, and 500 error masking
 */

const crypto = require('node:crypto');

function setSecurityHeaders(res) {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self' data:; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'interest-cohort=(), camera=(), microphone=(), geolocation=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}

function setCorsHeaders(res, origin, allowedOrigins = []) {
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Sentinel-Key, X-CSRF-Token');
}

function sendJson(res, statusCode, data, extraHeaders = {}) {
  setSecurityHeaders(res);
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    ...extraHeaders
  });
  res.end(body);
}

function sendError(res, statusCode, message, extra = {}) {
  let clientMessage = message;
  let errorId;

  if (statusCode >= 500) {
    errorId = crypto.randomUUID();
    console.error(`[WebSentinel-CS Internal Error ${errorId}]:`, message);
    clientMessage = 'Error interno del servidor';
  }

  sendJson(res, statusCode, {
    success: false,
    error: true,
    message: clientMessage,
    statusCode,
    ...(errorId ? { errorId } : {}),
    ...extra
  });
}

function sendCsv(res, filename, csvString) {
  setSecurityHeaders(res);
  const buf = Buffer.from(csvString, 'utf-8');
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="${filename}"`,
    'Content-Length': buf.length
  });
  res.end(buf);
}

module.exports = {
  setSecurityHeaders,
  setCorsHeaders,
  sendJson,
  sendError,
  sendCsv
};
