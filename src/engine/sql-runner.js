/**
 * WebSentinel-CS :: SQL Hardening & Execution Engine
 * Validates single SELECT or WITH (CTE), blocks credential tables, executes in isolated child process
 */

const { fork } = require('node:child_process');
const path = require('node:path');

const FORBIDDEN_SQL_KEYWORDS = [
  'ATTACH', 'DETACH', 'PRAGMA', 'INSERT', 'UPDATE', 'DELETE',
  'DROP', 'ALTER', 'CREATE', 'VACUUM', 'REINDEX', 'REPLACE'
];

const SENSITIVE_TABLES = [
  'users', 'auth_sessions', 'api_keys', 'admin_audit_log', 'login_rate_limits'
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

  // Must begin with SELECT or WITH
  if (!/^\s*(SELECT|WITH)\b/i.test(clean)) {
    throw new Error('Solo se permiten consultas de lectura que inicien con SELECT o WITH');
  }

  // Check forbidden keywords as separate words
  for (const kw of FORBIDDEN_SQL_KEYWORDS) {
    const re = new RegExp(`\\b${kw}\\b`, 'i');
    if (re.test(clean)) {
      throw new Error(`Palabra clave no permitida en la consola: ${kw}`);
    }
  }

  // Defense-in-depth: check sensitive credential tables
  for (const tbl of SENSITIVE_TABLES) {
    const re = new RegExp(`\\b${tbl}\\b`, 'i');
    if (re.test(clean)) {
      throw new Error(`Acceso denegado: La tabla '${tbl}' contiene secretos internos y está restringida`);
    }
  }

  return clean;
}

function wrapQueryWithLimit(cleanQuery) {
  if (/^\s*WITH\b/i.test(cleanQuery)) {
    if (!/\bLIMIT\s+\d+/i.test(cleanQuery)) {
      return `${cleanQuery} LIMIT 1000`;
    }
    return cleanQuery;
  }
  return `SELECT * FROM (${cleanQuery}) LIMIT 1000`;
}

function executeQueryWithWorker(dbPath, cleanQuery, dbFallback = null, timeoutMs = 3000) {
  const wrapped = wrapQueryWithLimit(cleanQuery);

  // In-memory fallback if needed
  if (dbPath === ':memory:' && dbFallback) {
    return new Promise((resolve) => {
      try {
        if (dbFallback.raw && typeof dbFallback.raw.setAuthorizer === 'function') {
          dbFallback.raw.setAuthorizer((action, arg1) => {
            if (arg1 && SENSITIVE_TABLES.includes(String(arg1).toLowerCase())) {
              return 1; // SQLITE_DENY
            }
            return 0; // SQLITE_OK
          });
        }
        const rows = dbFallback.runReadOnlyQuery(wrapped);
        resolve({ success: true, rows });
      } catch (err) {
        resolve({ success: false, error: err.message });
      }
    });
  }

  return new Promise((resolve) => {
    let finished = false;
    let timer = null;

    const child = fork(path.join(__dirname, 'sql-process.js'), [], {
      stdio: ['ignore', 'ignore', 'ignore', 'ipc']
    });

    const cleanup = () => {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
    };

    const killChild = () => {
      try {
        child.kill('SIGKILL');
      } catch (_) {}
    };

    timer = setTimeout(() => {
      if (!finished) {
        finished = true;
        cleanup();
        killChild();
        resolve({
          success: false,
          timeout: true,
          error: `Tiempo límite de ejecución de consulta excedido (${timeoutMs / 1000}s)`
        });
      }
    }, timeoutMs);

    child.on('message', (msg) => {
      if (!finished) {
        finished = true;
        cleanup();
        killChild();
        resolve(msg);
      }
    });

    child.on('error', (err) => {
      if (!finished) {
        finished = true;
        cleanup();
        killChild();
        resolve({ success: false, error: err.message });
      }
    });

    child.on('exit', (code, signal) => {
      if (!finished) {
        finished = true;
        cleanup();
        if (signal === 'SIGKILL' || signal === 'SIGTERM') {
          resolve({
            success: false,
            timeout: true,
            error: `Tiempo límite de ejecución de consulta excedido (${timeoutMs / 1000}s)`
          });
        } else {
          resolve({
            success: false,
            error: `El proceso de consulta terminó con código ${code ?? signal}`
          });
        }
      }
    });

    child.send({ dbPath, query: wrapped });
  });
}

module.exports = {
  sanitizeAndValidateQuery,
  wrapQueryWithLimit,
  executeQueryWithWorker
};
