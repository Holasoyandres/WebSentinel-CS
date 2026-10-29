/**
 * WebSentinel-CS :: Permissions & Access Control Matrix (FASE 1.1)
 * Enforces strict role-based and scope-based authorization for all API routes
 */

const SCOPE_PERMISSIONS = {
  ingest: new Set([
    'POST:/api/analyze-request',
    'POST:/api/v1/events',
    'POST:/api/record-login',
    'POST:/api/sessions/login',
    'POST:/api/sessions/activity',
    'POST:/api/sessions/logout',
    'GET:/api/v1/ip/:ip/status'
  ]),
  read: new Set([
    'GET:/api/stats',
    'GET:/api/events',
    'GET:/api/sql/summary',
    'GET:/api/sessions',
    'GET:/api/sessions/activities',
    'GET:/api/v1/ip/:ip/status'
  ])
};

const ROLE_PERMISSIONS = {
  viewer: new Set([
    'GET:/api/stats',
    'GET:/api/events',
    'GET:/api/sql/summary',
    'GET:/api/sessions',
    'GET:/api/sessions/activities',
    'GET:/api/auth/me',
    'GET:/api/v1/ip/:ip/status',
    'POST:/api/auth/logout'
  ]),
  analyst: new Set([
    'GET:/api/stats',
    'GET:/api/events',
    'GET:/api/sql/summary',
    'GET:/api/sessions',
    'GET:/api/sessions/activities',
    'GET:/api/auth/me',
    'GET:/api/v1/ip/:ip/status',
    'POST:/api/auth/logout',
    'POST:/api/scan',
    'GET:/api/export-csv',
    'POST:/api/analyze-request',
    'POST:/api/v1/events',
    'POST:/api/simulate-attack',
    'POST:/api/sessions/simulate'
  ]),
  admin: new Set([
    '*' // Full administrative access including /api/sql/query and /api/v1/integrity/verify
  ])
};

function normalizePath(pathname) {
  if (pathname.startsWith('/api/v1/ip/') && pathname.endsWith('/status')) {
    return '/api/v1/ip/:ip/status';
  }
  return pathname;
}

function verifyAuthorization(auth, pathname, method) {
  const normalizedPath = normalizePath(pathname);
  const routeKey = `${method.toUpperCase()}:${normalizedPath}`;

  // 1. Integrations (API Keys)
  if (auth.type === 'api_key') {
    const scopes = auth.scopes || [];
    let isAllowed = false;

    for (const scope of scopes) {
      const allowedRoutes = SCOPE_PERMISSIONS[scope.toLowerCase()];
      if (allowedRoutes && allowedRoutes.has(routeKey)) {
        isAllowed = true;
        break;
      }
    }

    if (!isAllowed) {
      return {
        allowed: false,
        statusCode: 403,
        message: `Acceso denegado: La API Key no posee el scope requerido para ${routeKey}`
      };
    }

    return { allowed: true };
  }

  // 2. Dashboard User Sessions
  if (auth.type === 'session') {
    const role = (auth.user && auth.user.role) || 'viewer';

    if (role === 'admin') {
      return { allowed: true };
    }

    const roleAllowed = ROLE_PERMISSIONS[role.toLowerCase()];
    if (roleAllowed && (roleAllowed.has(routeKey) || roleAllowed.has('*'))) {
      return { allowed: true };
    }

    return {
      allowed: false,
      statusCode: 403,
      message: `Acceso denegado: El rol '${role}' no tiene autorización para acceder a ${routeKey}`
    };
  }

  return {
    allowed: false,
    statusCode: 401,
    message: 'Autenticación requerida'
  };
}

module.exports = {
  SCOPE_PERMISSIONS,
  ROLE_PERMISSIONS,
  verifyAuthorization
};
