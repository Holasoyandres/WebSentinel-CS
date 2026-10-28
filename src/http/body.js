/**
 * WebSentinel-CS :: HTTP Request Body Parser
 * Enforces size limits, Content-Type validation, and safe JSON parsing to prevent DoS crashes
 */

function parseJsonBody(req, maxBytes = 1048576) {
  return new Promise((resolve, reject) => {
    // If GET or HEAD, return empty object
    if (req.method === 'GET' || req.method === 'HEAD') {
      return resolve({});
    }

    const contentType = req.headers['content-type'] || '';
    let bytesReceived = 0;
    let hasExceeded = false;
    const chunks = [];

    req.on('data', (chunk) => {
      if (hasExceeded) return;
      bytesReceived += chunk.length;
      if (bytesReceived > maxBytes) {
        hasExceeded = true;
        req.resume(); // Drain and discard remaining incoming stream safely
        const err = new Error('Carga útil excede el límite permitido de 1 MB (413)');
        err.statusCode = 413;
        return reject(err);
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (hasExceeded) return;
      if (chunks.length === 0) {
        return resolve({});
      }

      // Check Content-Type if body is non-empty
      if (contentType && !contentType.toLowerCase().includes('application/json')) {
        const err = new Error('Content-Type inválido. Se requiere application/json');
        err.statusCode = 400;
        return reject(err);
      }

      const raw = Buffer.concat(chunks).toString('utf-8').trim();
      if (!raw) {
        return resolve({});
      }

      try {
        const parsed = JSON.parse(raw);
        resolve(parsed);
      } catch (e) {
        const err = new Error('JSON malformado en el cuerpo de la petición (400)');
        err.statusCode = 400;
        reject(err);
      }
    });

    req.on('error', (err) => {
      if (!hasExceeded) reject(err);
    });
  });
}

module.exports = { parseJsonBody };
