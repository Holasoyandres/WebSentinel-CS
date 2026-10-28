/**
 * WebSentinel-CS :: HTTP Response Utilities
 * Centralized response handlers with security headers
 */

function setCorsHeaders(res, origin, allowedOrigins = []) {
  if (allowedOrigins.includes('*') || (origin && allowedOrigins.includes(origin))) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  } else if (allowedOrigins.length > 0) {
    res.setHeader('Access-Control-Allow-Origin', allowedOrigins[0]);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Sentinel-Key');
}

function sendJson(res, statusCode, data, extraHeaders = {}) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    ...extraHeaders
  });
  res.end(body);
}

function sendError(res, statusCode, message, extra = {}) {
  sendJson(res, statusCode, {
    error: true,
    message,
    statusCode,
    ...extra
  });
}

function sendCsv(res, filename, csvString) {
  const buf = Buffer.from(csvString, 'utf-8');
  res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="${filename}"`,
    'Content-Length': buf.length
  });
  res.end(buf);
}

module.exports = {
  setCorsHeaders,
  sendJson,
  sendError,
  sendCsv
};
