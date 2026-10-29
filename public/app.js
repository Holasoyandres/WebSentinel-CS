/**
 * WebSentinel-CS :: Enterprise Frontend Telemetry & SOC Engine (FASE 5)
 * Real-time SSE streaming, RBAC controls, incident forensics modal,
 * live search, pagination, and administrative key management.
 * Author: Holasoyandres
 */

// Global State
let activeFilter = 'ALL';
let telemetryEvents = [];
let currentSelectedSessionId = null;
let currentCsrfToken = '';
let currentUser = null;
let sseConnection = null;
let sseReconnectTimer = null;
let sseBackoffMs = 1000;
let timezoneMode = 'local'; // 'local' | 'utc'

// Pagination & Search State
let currentPage = 1;
const pageSize = 25;
let searchQuery = '';
let dateFromFilter = '';
let dateToFilter = '';

document.addEventListener('DOMContentLoaded', async () => {
  initClock();
  setupGlobalListeners();

  // 1. Initial Authentication & RBAC discovery
  await initAuthAndCsrf();

  // 2. Initial Data Load
  fetchSystemStats();
  fetchSecurityFeed();
  fetchSessionsFeed();

  // 3. Connect Real-Time SSE Stream (Replaces 3s polling)
  connectRealtimeStream();

  // Sessions list periodic refresh (fallback)
  setInterval(fetchSessionsFeed, 10000);
});

// -----------------------------------------------------------------------------
// Authentication, CSRF & RBAC Experience
// -----------------------------------------------------------------------------
async function initAuthAndCsrf() {
  try {
    const res = await fetch('/api/auth/me');
    if (res.ok) {
      const data = await res.json();
      if (data.user) {
        currentUser = data.user;
        if (data.session && data.session.csrf_token) {
          currentCsrfToken = data.session.csrf_token;
        }
        applyRbacUi(currentUser);
        hideLoginModal();
      } else {
        showLoginModal();
      }

      if (data.demoMode === false) {
        document.querySelectorAll('#panelSimulations, [data-attack-sim]').forEach(el => {
          el.classList.add('hidden');
        });
        const btnSimSession = document.getElementById('btnSimulateSession');
        if (btnSimSession) btnSimSession.style.display = 'none';
      }
    } else {
      showLoginModal();
    }
  } catch (_) {
    showLoginModal();
  }
}

function applyRbacUi(user) {
  const badge = document.getElementById('userHeaderBadge');
  const avatar = document.getElementById('userAvatar');
  const username = document.getElementById('headerUsername');
  const roleTag = document.getElementById('headerUserRole');
  const tabAdmin = document.getElementById('tabAdmin');
  const panelSql = document.getElementById('panelSqlConsole');
  const btnScan = document.getElementById('btnScanUrl');

  if (!user) {
    if (badge) badge.classList.add('hidden');
    return;
  }

  if (badge) badge.classList.remove('hidden');
  if (avatar) avatar.textContent = (user.username || 'A')[0].toUpperCase();
  if (username) username.textContent = user.username;
  if (roleTag) {
    roleTag.textContent = user.role.toUpperCase();
    roleTag.className = `user-role-tag user-role-${user.role.toLowerCase()}`;
  }

  // RBAC Adaptive Visibility
  const role = user.role ? user.role.toLowerCase() : 'viewer';

  if (role === 'viewer') {
    if (panelSql) panelSql.classList.add('hidden');
    if (btnScan) { btnScan.disabled = true; btnScan.title = 'Requiere rol analyst o admin'; }
    if (tabAdmin) tabAdmin.classList.add('hidden');
  } else if (role === 'analyst') {
    if (panelSql) panelSql.classList.add('hidden');
    if (btnScan) { btnScan.disabled = false; btnScan.title = 'Auditar endpoint'; }
    if (tabAdmin) tabAdmin.classList.add('hidden');
  } else if (role === 'admin') {
    if (panelSql) panelSql.classList.remove('hidden');
    if (btnScan) { btnScan.disabled = false; btnScan.title = 'Auditar endpoint'; }
    if (tabAdmin) tabAdmin.classList.remove('hidden');
  }
}

function showLoginModal(errMsg = '') {
  const modal = document.getElementById('loginModal');
  const errBox = document.getElementById('loginErrorMessage');
  if (modal) modal.classList.remove('hidden');
  if (errBox) {
    if (errMsg) {
      errBox.textContent = errMsg;
      errBox.classList.remove('hidden');
    } else {
      errBox.classList.add('hidden');
    }
  }
}

function hideLoginModal() {
  const modal = document.getElementById('loginModal');
  if (modal) modal.classList.add('hidden');
}

async function handleLogout() {
  try {
    await fetch('/api/auth/logout', {
      method: 'POST',
      headers: { 'X-CSRF-Token': currentCsrfToken }
    });
  } catch (_) {}
  currentUser = null;
  currentCsrfToken = '';
  applyRbacUi(null);
  showLoginModal();
}

// -----------------------------------------------------------------------------
// Real-Time Server-Sent Events (SSE) Stream
// -----------------------------------------------------------------------------
function connectRealtimeStream() {
  if (sseConnection) {
    try { sseConnection.close(); } catch (_) {}
  }

  const sseBadge = document.getElementById('sseBadge');
  const sseLabel = document.getElementById('sseStatusLabel');

  function setBadgeState(state, text) {
    if (!sseBadge || !sseLabel) return;
    sseBadge.className = `badge-sse ${state}`;
    sseLabel.textContent = text;
  }

  setBadgeState('reconnecting', 'CONECTANDO SSE...');

  sseConnection = new EventSource('/api/v1/stream');

  sseConnection.addEventListener('connected', () => {
    setBadgeState('connected', 'EN VIVO (SSE CONECTADO)');
    sseBackoffMs = 1000; // Reset backoff on success
  });

  sseConnection.addEventListener('incident', (e) => {
    try {
      const newIncident = JSON.parse(e.data);
      handleIncomingIncident(newIncident);
    } catch (err) {
      console.error('Error parsing incident SSE:', err);
    }
  });

  sseConnection.addEventListener('stats', (e) => {
    try {
      const stats = JSON.parse(e.data);
      updateKpis(stats);
    } catch (_) {}
  });

  sseConnection.onerror = () => {
    setBadgeState('reconnecting', 'RECONECTANDO...');
    try { sseConnection.close(); } catch (_) {}
    sseConnection = null;

    // Exponential Backoff Reconnection
    if (!sseReconnectTimer) {
      sseReconnectTimer = setTimeout(() => {
        sseReconnectTimer = null;
        sseBackoffMs = Math.min(sseBackoffMs * 1.5, 30000);
        connectRealtimeStream();
      }, sseBackoffMs);
    }
  };
}

function handleIncomingIncident(event) {
  // Add to top of buffer
  telemetryEvents.unshift(event);
  if (telemetryEvents.length > 500) telemetryEvents.pop();

  renderSocTable();

  // Optimistically increment KPI counter if threat
  if (event.severity === 'CRITICAL' || event.severity === 'HIGH') {
    const kpi = document.getElementById('kpiThreats');
    if (kpi) {
      const cur = parseInt(kpi.textContent.replace(/,/g, ''), 10) || 0;
      kpi.textContent = (cur + 1).toLocaleString();
    }
  }
}

// -----------------------------------------------------------------------------
// SOC Telemetry Feed, Search & Server-Side Pagination
// -----------------------------------------------------------------------------
async function fetchSecurityFeed() {
  try {
    const params = new URLSearchParams();
    if (activeFilter !== 'ALL') params.set('severity', activeFilter);
    if (searchQuery) params.set('search', searchQuery);
    if (dateFromFilter) params.set('from', dateFromFilter);
    if (dateToFilter) params.set('to', dateToFilter);

    params.set('limit', '500'); // Buffer up to 500 records
    params.set('offset', '0');

    const res = await fetch(`/api/events?${params.toString()}`);
    if (res.status === 401) {
      showLoginModal('Sesión expirada. Por favor identifíquese.');
      return;
    }
    if (!res.ok) return;

    telemetryEvents = await res.json();
    currentPage = 1;
    renderSocTable();
  } catch (err) {
    console.error('Telemetry fetch error:', err);
  }
}

function getFilteredEvents() {
  let list = telemetryEvents;

  // 1. Severity filter
  if (activeFilter !== 'ALL') {
    list = list.filter(e => e.severity === activeFilter);
  }

  // 2. Search query filter
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    list = list.filter(e =>
      (e.source_ip && e.source_ip.toLowerCase().includes(q)) ||
      (e.rule_id && e.rule_id.toLowerCase().includes(q)) ||
      (e.target && e.target.toLowerCase().includes(q)) ||
      (e.details && e.details.toLowerCase().includes(q))
    );
  }

  // 3. Date range filters
  if (dateFromFilter) {
    list = list.filter(e => e.timestamp >= dateFromFilter);
  }
  if (dateToFilter) {
    list = list.filter(e => e.timestamp <= dateToFilter + 'T23:59:59.999Z');
  }

  return list;
}

function renderSocTable() {
  const tbody = document.getElementById('socTableBody');
  const countLabel = document.getElementById('eventsCountLabel');
  const pageIndicator = document.getElementById('pageIndicator');
  const btnPrev = document.getElementById('btnPrevPage');
  const btnNext = document.getElementById('btnNextPage');
  if (!tbody || !countLabel) return;

  const filtered = getFilteredEvents();
  const totalCount = filtered.length;
  const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));

  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;

  const startIndex = (currentPage - 1) * pageSize;
  const pagedEvents = filtered.slice(startIndex, startIndex + pageSize);

  countLabel.textContent = `Mostrando ${pagedEvents.length} de ${totalCount} eventos`;
  if (pageIndicator) pageIndicator.textContent = `Página ${currentPage} de ${totalPages}`;
  if (btnPrev) btnPrev.disabled = currentPage <= 1;
  if (btnNext) btnNext.disabled = currentPage >= totalPages;

  if (pagedEvents.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">
          Sin incidentes registrados con los filtros aplicados.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = pagedEvents.map(ev => {
    const dateObj = new Date(ev.timestamp);
    const utcFormatted = dateObj.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
    const localFormatted = dateObj.toLocaleTimeString() + ' (' + dateObj.toLocaleDateString() + ')';
    const displayTime = timezoneMode === 'local' ? localFormatted : utcFormatted;

    const actionClass = ev.action === 'BLOCKED' ? 'action-blocked' : (ev.action === 'IP_BLOCKED' ? 'action-ip-blocked' : 'action-passed');
    const validSev = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(ev.severity) ? ev.severity : 'INFO';

    return `
      <tr data-action="view-incident-detail" data-incident-id="${escapeHtml(ev.id)}">
        <td style="color: var(--text-muted); font-size: 11px;" title="UTC: ${utcFormatted}&#10;Local: ${localFormatted}">${displayTime}</td>
        <td>
          <span class="badge-sev badge-${validSev}">${validSev}</span>
          ${ev.is_simulated ? '<span class="badge-sev" style="background: rgba(147, 51, 234, 0.15); color: #c084fc; border: 1px solid rgba(192, 132, 252, 0.3); margin-left: 4px; font-size: 10px;">SIMULADO</span>' : ''}
        </td>
        <td>
          <span class="rule-tag">${escapeHtml(ev.rule_id || 'RULE-GENERIC')}</span>
        </td>
        <td style="font-family: var(--font-mono); color: var(--color-info);">${escapeHtml(ev.source_ip)}</td>
        <td style="color: var(--text-secondary);">${escapeHtml(ev.target)}</td>
        <td style="max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(ev.details || '')}">
          ${escapeHtml(ev.details || '-')}
        </td>
        <td>
          <span class="action-tag ${actionClass}">${escapeHtml(ev.action)}</span>
        </td>
      </tr>
    `;
  }).join('');
}

// -----------------------------------------------------------------------------
// Incident Technical Forensics Detail Modal
// -----------------------------------------------------------------------------
function showIncidentDetail(incidentId) {
  const ev = telemetryEvents.find(e => e.id === incidentId);
  if (!ev) return;

  const modal = document.getElementById('incidentDetailModal');
  const dId = document.getElementById('detIncidentId');
  const dSev = document.getElementById('detSeverityAction');
  const dRule = document.getElementById('detRuleId');
  const dIp = document.getElementById('detSourceIp');
  const dTarget = document.getElementById('detTarget');
  const dTime = document.getElementById('detTimestamp');
  const dDetails = document.getElementById('detDetails');
  const dHash = document.getElementById('detHash');
  const dPrevHash = document.getElementById('detPrevHash');

  const d = new Date(ev.timestamp);
  const localStr = d.toLocaleString();
  const utcStr = d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

  if (dId) dId.textContent = ev.id;
  if (dSev) dSev.textContent = `${ev.severity} / ${ev.action}`;
  if (dRule) dRule.textContent = ev.rule_id || 'RULE-GENERIC';
  if (dIp) dIp.textContent = ev.source_ip;
  if (dTarget) dTarget.textContent = ev.target;
  if (dTime) dTime.textContent = `${localStr} (Local)  |  ${utcStr}`;
  if (dDetails) dDetails.value = ev.details || '';
  if (dHash) dHash.textContent = ev.hash || 'Hash Genesis / En proceso';
  if (dPrevHash) dPrevHash.textContent = ev.prev_hash || 'Genesis block (0000...)';

  if (modal) modal.classList.remove('hidden');
}

// -----------------------------------------------------------------------------
// Admin Management (API Keys & IP Unblocking)
// -----------------------------------------------------------------------------
async function loadAdminData() {
  if (!currentUser || currentUser.role !== 'admin') return;
  loadApiKeys();
  loadBlockedIps();
}

async function loadApiKeys() {
  const tbody = document.getElementById('apiKeysTableBody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/v1/admin/api-keys');
    if (!res.ok) return;
    const keys = await res.json();

    if (keys.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">No hay API Keys registradas</td></tr>';
      return;
    }

    tbody.innerHTML = keys.map(k => `
      <tr>
        <td style="font-weight: 600;">${escapeHtml(k.name)}</td>
        <td><span class="rule-tag">${escapeHtml(k.scopes)}</span></td>
        <td style="font-size: 11px; color: var(--text-muted);">${escapeHtml(k.created_at || '-')}</td>
        <td style="font-size: 11px; color: var(--text-muted);">${escapeHtml(k.last_used_at || 'Nunca')}</td>
        <td>
          <button class="btn btn-outline btn-sm" style="color: var(--color-critical); border-color: var(--color-critical-border);" data-action="revoke-api-key" data-key-id="${escapeHtml(k.id)}">Revocar</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    console.error('Error loading API keys:', err);
  }
}

async function loadBlockedIps() {
  const tbody = document.getElementById('blockedIpsTableBody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/v1/admin/blocked-ips');
    if (!res.ok) return;
    const blocked = await res.json();

    if (blocked.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--color-muted); padding: 20px;">Sin direcciones IP bloqueadas actualmente</td></tr>';
      return;
    }

    tbody.innerHTML = blocked.map(b => {
      const mins = Math.ceil(b.remainingSeconds / 60);
      return `
        <tr>
          <td style="font-family: var(--font-mono); color: var(--color-critical); font-weight: 600;">${escapeHtml(b.ip)}</td>
          <td><span class="badge-sev badge-CRITICAL">${b.failedAttempts} fallos</span></td>
          <td style="font-size: 11px; color: var(--text-muted);">${escapeHtml(b.blockExpiresAt)}</td>
          <td style="font-family: var(--font-mono); font-size: 11px;">${mins} min</td>
          <td>
            <button class="btn btn-outline btn-sm" style="color: var(--color-success); border-color: var(--color-success-border);" data-action="unblock-ip" data-ip="${escapeHtml(b.ip)}">Desbloquear</button>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Error loading blocked IPs:', err);
  }
}

// -----------------------------------------------------------------------------
// Global Event Delegation & Wireup
// -----------------------------------------------------------------------------
function setupGlobalListeners() {
  // Navigation tabs
  document.addEventListener('click', (e) => {
    const viewBtn = e.target.closest('[data-view]');
    if (viewBtn) {
      switchView(viewBtn.dataset.view);
      return;
    }

    // Filter Buttons
    const filterBtn = e.target.closest('[data-filter]');
    if (filterBtn) {
      activeFilter = filterBtn.dataset.filter;
      document.querySelectorAll('.btn-filter').forEach(b => b.classList.toggle('active', b === filterBtn));
      currentPage = 1;
      fetchSecurityFeed();
      return;
    }

    // Attack simulation buttons
    const attackBtn = e.target.closest('[data-attack-sim]');
    if (attackBtn) {
      runAttackSim(attackBtn.dataset.attackSim);
      return;
    }

    // SQL presets
    const sqlPresetBtn = e.target.closest('[data-sql-preset]');
    if (sqlPresetBtn) {
      const input = document.getElementById('sqlQueryInput');
      if (input) input.value = sqlPresetBtn.dataset.sqlPreset;
      return;
    }

    // Session activity inspection
    const inspectBtn = e.target.closest('[data-action="inspect-session"]');
    if (inspectBtn) {
      loadSessionActivities(
        inspectBtn.dataset.sessionId,
        inspectBtn.dataset.user,
        inspectBtn.dataset.ip,
        inspectBtn.dataset.portal
      );
      return;
    }

    // Incident Detail Modal Click
    const row = e.target.closest('[data-action="view-incident-detail"]');
    if (row) {
      showIncidentDetail(row.dataset.incidentId);
      return;
    }

    // Revoke API Key
    const revokeBtn = e.target.closest('[data-action="revoke-api-key"]');
    if (revokeBtn) {
      const keyId = revokeBtn.dataset.keyId;
      if (confirm('¿Confirmas la revocación definitiva de esta API Key?')) {
        fetch(`/api/v1/admin/api-keys/${keyId}`, {
          method: 'DELETE',
          headers: { 'X-CSRF-Token': currentCsrfToken }
        }).then(res => {
          if (res.ok) loadApiKeys();
        });
      }
      return;
    }

    // Unblock IP
    const unblockBtn = e.target.closest('[data-action="unblock-ip"]');
    if (unblockBtn) {
      const ip = unblockBtn.dataset.ip;
      if (confirm(`¿Desbloquear la IP ${ip} inmediatamente?`)) {
        fetch('/api/v1/admin/unblock-ip', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': currentCsrfToken
          },
          body: JSON.stringify({ ip })
        }).then(res => {
          if (res.ok) loadBlockedIps();
        });
      }
      return;
    }
  });

  // Direct element handlers
  const btnLogout = document.getElementById('btnLogout');
  if (btnLogout) btnLogout.addEventListener('click', handleLogout);

  const btnScan = document.getElementById('btnScanUrl');
  if (btnScan) btnScan.addEventListener('click', executeUrlAudit);

  const btnInspect = document.getElementById('btnInspectPayload');
  if (btnInspect) btnInspect.addEventListener('click', executePayloadInspection);

  const btnSql = document.getElementById('btnRunSql');
  if (btnSql) btnSql.addEventListener('click', executeSqlQuery);

  const btnExport = document.getElementById('btnExportCsv');
  if (btnExport) btnExport.addEventListener('click', () => {
    const params = new URLSearchParams();
    if (activeFilter !== 'ALL') params.set('severity', activeFilter);
    if (searchQuery) params.set('search', searchQuery);
    if (dateFromFilter) params.set('from', dateFromFilter);
    if (dateToFilter) params.set('to', dateToFilter);
    window.location.href = `/api/export-csv?${params.toString()}`;
  });

  const btnRefreshFeed = document.getElementById('btnRefreshFeed');
  if (btnRefreshFeed) btnRefreshFeed.addEventListener('click', fetchSecurityFeed);

  const btnSimulate = document.getElementById('btnSimulateSession');
  if (btnSimulate) btnSimulate.addEventListener('click', simulateNewUserSession);

  const btnRefreshSessions = document.getElementById('btnRefreshSessions');
  if (btnRefreshSessions) btnRefreshSessions.addEventListener('click', fetchSessionsFeed);

  // Timezone toggle
  const btnTz = document.getElementById('btnToggleTimezone');
  if (btnTz) {
    btnTz.addEventListener('click', () => {
      timezoneMode = timezoneMode === 'local' ? 'utc' : 'local';
      btnTz.textContent = timezoneMode === 'local' ? 'Zona: Local' : 'Zona: UTC';
      renderSocTable();
    });
  }

  // Live Search Input (Debounced)
  const searchInput = document.getElementById('socSearchInput');
  let searchDebounce;
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(() => {
        searchQuery = e.target.value.trim();
        currentPage = 1;
        fetchSecurityFeed();
      }, 300);
    });
  }

  // Date range inputs
  const fromInput = document.getElementById('socDateFrom');
  if (fromInput) {
    fromInput.addEventListener('change', (e) => {
      dateFromFilter = e.target.value;
      currentPage = 1;
      fetchSecurityFeed();
    });
  }
  const toInput = document.getElementById('socDateTo');
  if (toInput) {
    toInput.addEventListener('change', (e) => {
      dateToFilter = e.target.value;
      currentPage = 1;
      fetchSecurityFeed();
    });
  }

  // Pagination buttons
  const btnPrev = document.getElementById('btnPrevPage');
  if (btnPrev) {
    btnPrev.addEventListener('click', () => {
      if (currentPage > 1) {
        currentPage--;
        renderSocTable();
      }
    });
  }
  const btnNext = document.getElementById('btnNextPage');
  if (btnNext) {
    btnNext.addEventListener('click', () => {
      currentPage++;
      renderSocTable();
    });
  }

  // Login Form Submission
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const usernameInput = document.getElementById('loginUsername').value.trim();
      const passwordInput = document.getElementById('loginPassword').value;
      const btn = document.getElementById('btnLoginSubmit');

      btn.disabled = true;
      btn.textContent = 'Verificando...';

      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: usernameInput, password: passwordInput })
        });
        const data = await res.json();

        if (res.ok && data.success) {
          currentUser = data.user;
          currentCsrfToken = data.csrfToken;
          applyRbacUi(currentUser);
          hideLoginModal();
          fetchSecurityFeed();
          fetchSystemStats();
          connectRealtimeStream();
        } else {
          showLoginModal(data.message || 'Credenciales de acceso no válidas.');
        }
      } catch (err) {
        showLoginModal('Error de conexión al iniciar sesión.');
      } finally {
        btn.disabled = false;
        btn.textContent = 'Entrar a la Consola';
      }
    });
  }

  // Incident Modal Close buttons
  const closeIncBtn = document.getElementById('btnCloseIncidentModal');
  if (closeIncBtn) closeIncBtn.addEventListener('click', () => document.getElementById('incidentDetailModal').classList.add('hidden'));
  const dismissIncBtn = document.getElementById('btnDismissIncidentModal');
  if (dismissIncBtn) dismissIncBtn.addEventListener('click', () => document.getElementById('incidentDetailModal').classList.add('hidden'));

  // Admin: Create API Key Modal
  const btnOpenCreateKey = document.getElementById('btnOpenCreateKeyModal');
  if (btnOpenCreateKey) btnOpenCreateKey.addEventListener('click', () => {
    document.getElementById('newKeyResultBox').classList.add('hidden');
    document.getElementById('newKeyName').value = '';
    document.getElementById('createApiKeyModal').classList.remove('hidden');
  });
  const btnCloseKeyModal = document.getElementById('btnCloseApiKeyModal');
  if (btnCloseKeyModal) btnCloseKeyModal.addEventListener('click', () => document.getElementById('createApiKeyModal').classList.add('hidden'));
  const btnCancelKey = document.getElementById('btnCancelCreateKey');
  if (btnCancelKey) btnCancelKey.addEventListener('click', () => document.getElementById('createApiKeyModal').classList.add('hidden'));

  const createKeyForm = document.getElementById('createApiKeyForm');
  if (createKeyForm) {
    createKeyForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const name = document.getElementById('newKeyName').value.trim();
      const hasIngest = document.getElementById('scopeIngest').checked;
      const hasRead = document.getElementById('scopeRead').checked;

      const scopes = [];
      if (hasIngest) scopes.push('ingest');
      if (hasRead) scopes.push('read');

      const res = await fetch('/api/v1/admin/api-keys', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': currentCsrfToken
        },
        body: JSON.stringify({ name, scopes: scopes.join(',') })
      });

      const data = await res.json();
      if (res.ok && data.success) {
        document.getElementById('newKeyResultBox').classList.remove('hidden');
        document.getElementById('newKeyValue').textContent = data.key;
        loadApiKeys();
      } else {
        alert(data.message || 'Error al generar API Key');
      }
    });
  }

  const btnRefBlocked = document.getElementById('btnRefreshBlockedIps');
  if (btnRefBlocked) btnRefBlocked.addEventListener('click', loadBlockedIps);
}

// -----------------------------------------------------------------------------
// View Switching & Subpage Navigation
// -----------------------------------------------------------------------------
function switchView(viewName) {
  document.querySelectorAll('.view-tab').forEach(t => {
    t.classList.toggle('active', t.dataset.view === viewName);
  });

  const viewSoc = document.getElementById('view-soc');
  const viewSessions = document.getElementById('view-sessions');
  const viewAdmin = document.getElementById('view-admin');

  if (viewSoc) viewSoc.classList.toggle('hidden', viewName !== 'soc');
  if (viewSessions) viewSessions.classList.toggle('hidden', viewName !== 'sessions');
  if (viewAdmin) viewAdmin.classList.toggle('hidden', viewName !== 'admin');

  if (viewName === 'admin') {
    loadAdminData();
  }
}

// -----------------------------------------------------------------------------
// KPIs & System Stats
// -----------------------------------------------------------------------------
function updateKpis(data) {
  const elThreats = document.getElementById('kpiThreats');
  if (elThreats) elThreats.textContent = (data.threatsDetected || 0).toLocaleString();

  const elBrute = document.getElementById('kpiBruteForce');
  if (elBrute) elBrute.textContent = (data.bruteForceBlocked || 0).toLocaleString();

  const elScans = document.getElementById('kpiScans');
  if (elScans) elScans.textContent = (data.totalScans || 0).toLocaleString();

  const elInspect = document.getElementById('kpiInspections');
  if (elInspect) elInspect.textContent = (data.inspectionsRun || 0).toLocaleString();

  const sec = data.uptimeSeconds || 0;
  const hrs = Math.floor(sec / 3600);
  const mins = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  const elUptime = document.getElementById('uptimeText');
  if (elUptime) elUptime.textContent = `${hrs}h ${mins}m ${s}s`;
}

async function fetchSystemStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const data = await res.json();
    updateKpis(data);
  } catch (err) {
    console.error('Stats fetch error:', err);
  }
}

// -----------------------------------------------------------------------------
// User Sessions & Activity Audit Subpage
// -----------------------------------------------------------------------------
async function fetchSessionsFeed() {
  try {
    const res = await fetch('/api/sessions');
    if (!res.ok) return;
    const sessions = await res.json();

    const tbody = document.getElementById('sessionsTableBody');
    const footerCount = document.getElementById('sessionsFooterCount');
    const kpiActive = document.getElementById('kpiActiveSessions');
    const kpiTotal = document.getElementById('kpiTotalSessions');
    const kpiActs = document.getElementById('kpiTotalActivities');

    if (kpiTotal) kpiTotal.textContent = sessions.length;

    let activeCount = 0;
    sessions.forEach(s => { if (s.status === 'ACTIVA') activeCount++; });
    if (kpiActive) kpiActive.textContent = activeCount;

    if (footerCount) footerCount.textContent = `Auditando ${sessions.length} sesiones en total (${activeCount} en curso)`;

    if (!tbody) return;

    if (sessions.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 30px; color: var(--text-muted);">Sin sesiones de usuario registradas. Use "Simular Sesión" para generar actividad de prueba.</td></tr>';
      return;
    }

    let totalActions = 0;

    tbody.innerHTML = sessions.map(s => {
      const isActiva = s.status === 'ACTIVA';
      const statusBadge = isActiva
        ? '<span class="status-pill status-present" style="font-size: 10px;">ACTIVA</span>'
        : '<span class="status-pill status-missing" style="font-size: 10px;">CERRADA</span>';

      const dur = s.duration_minutes !== null ? `${s.duration_minutes} min` : 'En curso';
      const logoutDisplay = s.logout_time ? s.logout_time.replace('T', ' ').substring(11, 19) : '--:--:--';
      const loginDisplay = s.login_time ? s.login_time.replace('T', ' ').substring(11, 19) : '--:--:--';

      return `
        <tr>
          <td>${statusBadge}</td>
          <td style="font-weight: 600;">${escapeHtml(s.username)} <span style="font-size: 10px; color: var(--text-muted); font-weight: normal;">[${escapeHtml(s.user_role)}]</span></td>
          <td style="font-family: var(--font-mono); color: var(--color-info);">${escapeHtml(s.ip_address)}</td>
          <td style="color: var(--text-secondary);">${escapeHtml(s.portal_location)}</td>
          <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${loginDisplay}</td>
          <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${logoutDisplay}</td>
          <td style="font-family: var(--font-mono); font-size: 11px;">${dur}</td>
          <td>
            <button class="btn btn-outline btn-sm" data-action="inspect-session" data-session-id="${escapeHtml(s.session_id)}" data-user="${escapeHtml(s.username)}" data-ip="${escapeHtml(s.ip_address)}" data-portal="${escapeHtml(s.portal_location)}">Ver Trazabilidad</button>
          </td>
        </tr>
      `;
    }).join('');

    if (kpiActs && totalActions > 0) kpiActs.textContent = totalActions;
  } catch (err) {
    console.error('Error fetching sessions:', err);
  }
}

async function loadSessionActivities(sessionId, username, ip, portal) {
  currentSelectedSessionId = sessionId;

  const chip = document.getElementById('selectedSessionChip');
  const sub = document.getElementById('selectedSessionSub');
  const container = document.getElementById('activityTimelineContainer');

  if (chip) chip.textContent = `${username} (${ip})`;
  if (sub) sub.textContent = `Portal: ${portal} &bull; Sesión ID: ${sessionId}`;
  if (!container) return;

  container.innerHTML = '<div style="padding: 20px; text-align: center; color: var(--text-muted);">Cargando trazabilidad de la sesión...</div>';

  try {
    const res = await fetch(`/api/sessions/activities?sessionId=${encodeURIComponent(sessionId)}`);
    if (!res.ok) return;
    const activities = await res.json();

    if (activities.length === 0) {
      container.innerHTML = '<div class="empty-state-notice">Sin acciones registradas para esta sesión.</div>';
      return;
    }

    container.innerHTML = activities.map(act => {
      const time = act.timestamp ? act.timestamp.replace('T', ' ').substring(11, 19) : '--:--:--';
      const riskClass = `risk-${act.risk_level || 'NORMAL'}`;

      return `
        <div class="timeline-step ${riskClass}">
          <div class="timeline-header">
            <span class="timeline-action">${escapeHtml(act.action_type)}</span>
            <span class="timeline-time">${time}</span>
          </div>
          <div class="timeline-endpoint">${escapeHtml(act.target_resource)}</div>
          <div class="timeline-desc">${escapeHtml(act.details)}</div>
        </div>
      `;
    }).join('');
  } catch (err) {
    container.innerHTML = `<div style="color: var(--color-critical); padding: 20px;">Fallo al cargar actividad: ${err.message}</div>`;
  }
}

async function simulateNewUserSession() {
  const btn = document.getElementById('btnSimulateSession');
  if (btn) btn.disabled = true;

  try {
    await fetch('/api/sessions/simulate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': currentCsrfToken
      }
    });
    fetchSessionsFeed();
  } catch (err) {
    alert('Error al simular sesión: ' + err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

// -----------------------------------------------------------------------------
// Interactive Tool Actions (Audit, Payload Inspection, SQL Console, Simulation)
// -----------------------------------------------------------------------------
async function executeUrlAudit() {
  const urlInput = document.getElementById('targetUrlInput').value.trim();
  const reportArea = document.getElementById('scanReportArea');
  const btn = document.getElementById('btnScanUrl');

  if (!urlInput) return alert('Por favor ingrese una URL válida');

  btn.disabled = true;
  btn.textContent = 'Verificando...';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': currentCsrfToken
      },
      body: JSON.stringify({ url: urlInput })
    });
    const data = await res.json();

    if (data.error) {
      alert('Error en auditoría: ' + data.error);
      return;
    }

    reportArea.classList.remove('hidden');

    const scoreVal = document.getElementById('scoreValue');
    const statusVal = document.getElementById('statusHttp');
    const latencyVal = document.getElementById('latencyHttp');

    if (scoreVal) scoreVal.textContent = `${data.securityScore}/100`;
    if (statusVal) statusVal.textContent = data.statusCode || '200';
    if (latencyVal) latencyVal.textContent = `${data.latencyMs || 0} ms`;

    const tbody = document.getElementById('headersTableBody');
    if (tbody && data.headerChecks) {
      tbody.innerHTML = Object.values(data.headerChecks).map(h => `
        <tr>
          <td style="font-family: var(--font-mono); font-weight: 500;">${escapeHtml(h.header)}</td>
          <td>
            ${h.present
              ? '<span class="status-pill status-present">PRESENTE</span>'
              : '<span class="status-pill status-missing">FALTANTE</span>'}
          </td>
        </tr>
      `).join('');
    }

    fetchSecurityFeed();
    fetchSystemStats();
  } catch (err) {
    alert('Fallo al conectar con la API de auditoría: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Auditar';
  }
}

async function executePayloadInspection() {
  const inputVal = document.getElementById('payloadInput').value;
  const honeypotVal = document.getElementById('honeypotInput').value;
  const badge = document.getElementById('inspectBadge');

  if (!inputVal && !honeypotVal) return alert('Ingrese un parámetro o active el honeypot');

  try {
    const res = await fetch('/api/analyze-request', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': currentCsrfToken
      },
      body: JSON.stringify({ input: inputVal, honeypot: honeypotVal })
    });
    const data = await res.json();

    badge.classList.remove('hidden');

    if (data.safe) {
      badge.className = 'status-pill status-present';
      badge.textContent = `LIMPIO (Score: ${data.scoreTotal || 0})`;
    } else if (data.action === 'FLAG') {
      badge.className = 'status-pill status-missing';
      badge.style.background = 'var(--color-medium-bg)';
      badge.style.color = 'var(--color-medium)';
      badge.textContent = `SOSPECHOSO (${data.scoreTotal}/${data.threshold})`;
    } else {
      badge.className = 'status-pill status-missing';
      badge.textContent = `AMENAZA BLOQUEADA (${data.scoreTotal}/${data.threshold})`;
    }

    fetchSecurityFeed();
    fetchSystemStats();
  } catch (err) {
    alert('Fallo al conectar con el motor de inspección: ' + err.message);
  }
}

async function executeSqlQuery() {
  const query = document.getElementById('sqlQueryInput').value.trim();
  const statusEl = document.getElementById('sqlExecutionStatus');
  const resultWrap = document.getElementById('sqlResultWrapper');
  const head = document.getElementById('sqlResultHead');
  const body = document.getElementById('sqlResultBody');
  const btn = document.getElementById('btnRunSql');

  if (!query) return;

  btn.disabled = true;
  btn.textContent = 'Ejecutando...';

  try {
    const res = await fetch('/api/sql/query', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': currentCsrfToken
      },
      body: JSON.stringify({ query })
    });

    const data = await res.json();
    statusEl.classList.remove('hidden');

    if (!data.success) {
      statusEl.className = 'status-pill status-missing';
      statusEl.textContent = data.message || 'Error en consulta SQL';
      resultWrap.classList.add('hidden');
      return;
    }

    statusEl.className = 'status-pill status-present';
    statusEl.textContent = `${data.count} filas en ${data.durationMs}ms`;

    if (data.rows && data.rows.length > 0) {
      const cols = Object.keys(data.rows[0]);
      head.innerHTML = `<tr>${cols.map(c => `<th>${escapeHtml(c.toUpperCase())}</th>`).join('')}</tr>`;
      body.innerHTML = data.rows.map(r => `
        <tr>${cols.map(c => `<td style="font-family: var(--font-mono); font-size: 11px;">${escapeHtml(String(r[c] !== null ? r[c] : 'NULL'))}</td>`).join('')}</tr>
      `).join('');
      resultWrap.classList.remove('hidden');
    } else {
      head.innerHTML = '';
      body.innerHTML = '<tr><td style="text-align: center; padding: 20px; color: var(--text-muted);">Sin resultados</td></tr>';
      resultWrap.classList.remove('hidden');
    }
  } catch (err) {
    statusEl.className = 'status-pill status-missing';
    statusEl.textContent = 'Error de conexión: ' + err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Ejecutar Consulta';
  }
}

async function runAttackSim(vector) {
  try {
    await fetch('/api/simulate-attack', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': currentCsrfToken
      },
      body: JSON.stringify({ vector })
    });
    fetchSecurityFeed();
    fetchSystemStats();
  } catch (err) {
    alert('Fallo en simulación: ' + err.message);
  }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------
function initClock() {
  function update() {
    const now = new Date();
    const utc = now.toUTCString().split(' ')[4] + ' UTC';
    const clockEl = document.getElementById('systemClock');
    if (clockEl) clockEl.textContent = utc;
  }
  update();
  setInterval(update, 1000);
}

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
