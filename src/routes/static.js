/**
 * WebSentinel-CS :: Static Assets Dispatcher
 * Serves dashboard assets with strict path verification, null-byte rejection, and extension allowlist
 */

const fs = require('node:fs');
const path = require('node:path');
const { setSecurityHeaders } = require('../http/respond');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
  '.ico': 'image/x-icon'
};

const ALLOWED_EXTENSIONS = new Set(Object.keys(MIME_TYPES));

function serveStatic(req, res, publicDir, pathname) {
  setSecurityHeaders(res);

  // 1. Decode URI component safely
  let decodedPath;
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch (err) {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('400 Bad Request: Formato de URI inválido');
  }

  // 2. Reject null bytes
  if (decodedPath.includes('\0')) {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('400 Bad Request: Bytes nulos no permitidos');
  }

  // 3. Reject directory traversal segments
  if (decodedPath.includes('..')) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('403 Forbidden: Segmentos de escape de directorio detectados');
  }

  const safeRelativePath = decodedPath === '/' ? 'index.html' : decodedPath.replace(/^[/\\]+/, '');
  const resolvedPath = path.resolve(publicDir, safeRelativePath);
  const normalizedPublic = path.resolve(publicDir);

  // 4. Boundary verification: Must reside strictly inside public directory
  const isWithinPublic = resolvedPath.startsWith(normalizedPublic + path.sep) || resolvedPath === path.join(normalizedPublic, 'index.html');
  if (!isWithinPublic) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('403 Forbidden: Acceso no permitido fuera del directorio público');
  }

  // 5. Strict Extension Allowlist
  const ext = path.extname(resolvedPath).toLowerCase();
  if (!ALLOWED_EXTENSIONS.has(ext)) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('404 Not Found: Archivo no encontrado');
  }

  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(resolvedPath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('404 Not Found: Archivo no encontrado');
      }
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('500 Internal Server Error');
    }

    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': content.length
    });
    res.end(content);
  });
}

module.exports = { serveStatic };
