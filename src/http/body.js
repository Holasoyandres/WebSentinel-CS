/**
 * WebSentinel-CS :: HTTP Request Body Parser
 * Enforces size limits and safe JSON parsing to prevent DoS crashes
 */

function parseJsonBody(req, maxBytes = 1048576) {
  return new Promise((resolve, reject) => {
    let bytesReceived = 0;
    const chunks = [];

    req.on('data', (chunk) => {
      bytesReceived += chunk.length;
      if (bytesReceived > maxBytes) {
        req.destroy();
        const err = new Error('Carga útil excede el límite permitido (413)');
        err.statusCode = 413;
        return reject(err);
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      if (chunks.length === 0) {
        return resolve({});
      }
      const raw = Buffer.concat(chunks).toString('utf-8');
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
      reject(err);
    });
  });
}

module.exports = { parseJsonBody };
