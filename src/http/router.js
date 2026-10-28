/**
 * WebSentinel-CS :: HTTP Router
 * Parses WHATWG URL, manages CORS, dispatches API and Static requests
 */

const { setCorsHeaders } = require('./respond');
const { serveStatic } = require('../routes/static');

function createRouter({ config, handleApi, publicDir }) {
  return async function router(req, res) {
    const host = req.headers.host || `${config.HOST}:${config.PORT}`;
    const parsedUrl = new URL(req.url, `http://${host}`);
    const pathname = parsedUrl.pathname;
    const origin = req.headers.origin;

    setCorsHeaders(res, origin, config.CORS_ORIGINS);

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      return res.end();
    }

    if (pathname.startsWith('/api/')) {
      return handleApi(req, res, parsedUrl);
    }

    // Default: Static File Delivery
    return serveStatic(req, res, publicDir, pathname);
  };
}

module.exports = { createRouter };
