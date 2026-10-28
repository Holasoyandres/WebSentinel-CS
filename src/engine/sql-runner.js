/**
 * WebSentinel-CS :: SQL Hardening & Execution Engine
 * Validates single SELECT, wraps with limit, executes in worker thread with 3s timeout
 */

const { Worker } = require('node:worker_threads');
const path = require('node:path');

const FORBIDDEN_SQL_KEYWORDS = [
  'ATTACH', 'DETACH', 'PRAGMA', 'INSERT', 'UPDATE', 'DELETE',
  'DROP', 'ALTER', 'CREATE', 'VACUUM', 'REINDEX', 'REPLACE'
];

function sanitizeAndValidateQuery(rawQuery) {
  if (!rawQuery || typeof rawQuery !== 'string') {
    throw new Error('La consulta SQL debe ser una cadena no vacía');
  }

  // Strip single-line and multi-line comments
  let clean = rawQuery
    .replace(/--.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .trim();

  // Allow one optional trailing semicolon and strip it
  if (clean.endsWith(';')) {
    clean = clean.slice(0, -1).trim();
  }

  // Reject multiple statements
  if (clean.includes(';')) {
    throw new Error('Solo se permite una única consulta SQL (sin punto y coma adicional)');
  }

  // Must begin with SELECT
  if (!/^\s*SELECT\b/i.test(clean)) {
    throw new Error('Solo se permiten consultas de lectura que inicien con SELECT');
  }

  // Check forbidden keywords as separate words
  for (const kw of FORBIDDEN_SQL_KEYWORDS) {
    const re = new RegExp(`\\b${kw}\\b`, 'i');
    if (re.test(clean)) {
      throw new Error(`Palabra clave no permitida en la consola: ${kw}`);
    }
  }

  return clean;
}

function executeQueryWithWorker(dbPath, cleanQuery, dbFallback = null, timeoutMs = 3000) {
  const wrapped = `SELECT * FROM (${cleanQuery}) LIMIT 1000`;

  // If in-memory, worker thread would open a different empty DB, so execute via fallback with query_only
  if (dbPath === ':memory:' && dbFallback) {
    return new Promise((resolve) => {
      try {
        const rows = dbFallback.runReadOnlyQuery(wrapped);
        resolve({ success: true, rows });
      } catch (err) {
        resolve({ success: false, error: err.message });
      }
    });
  }

  return new Promise((resolve) => {
    const worker = new Worker(path.join(__dirname, 'sql-worker.js'), {
      workerData: { dbPath, query: wrapped }
    });

    let finished = false;

    const timer = setTimeout(() => {
      if (!finished) {
        finished = true;
        worker.terminate().finally(() => {
          resolve({
            success: false,
            timeout: true,
            error: `Tiempo límite de ejecución de consulta excedido (${timeoutMs / 1000}s)`
          });
        });
      }
    }, timeoutMs);

    worker.on('message', (msg) => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        resolve(msg);
      }
    });

    worker.on('error', (err) => {
      if (!finished) {
        finished = true;
        clearTimeout(timer);
        resolve({ success: false, error: err.message });
      }
    });

    worker.on('exit', (code) => {
      if (!finished && code !== 0) {
        finished = true;
        clearTimeout(timer);
        resolve({ success: false, error: `El proceso de consulta terminó inesperadamente con código ${code}` });
      }
    });
  });
}

module.exports = {
  sanitizeAndValidateQuery,
  executeQueryWithWorker
};
