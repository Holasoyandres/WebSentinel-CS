/**
 * WebSentinel-CS :: Enterprise Frontend Telemetry Engine (Hardenized P0 Architecture)
 * Author: Holasoyandres
 */

let activeFilter = 'ALL';
let telemetryEvents = [];
let currentSelectedSessionId = null;
let currentCsrfToken = '';

document.addEventListener('DOMContentLoaded', () => {
  initClock();
  initAuthAndCsrf();
  fetchSystemStats();
  fetchSecurityFeed();
  fetchSessionsFeed();

  setInterval(fetchSystemStats, 3000);
  setInterval(fetchSecurityFeed, 3000);
  setInterval(fetchSessionsFeed, 5000);

  // Wire direct button event listeners
  const btnScan = document.getElementById('btnScanUrl');
  if (btnScan) btnScan.addEventListener('click', executeUrlAudit);

  const btnInspect = document.getElementById('btnInspectPayload');
  if (btnInspect) btnInspect.addEventListener('click', executePayloadInspection);

  const btnSql = document.getElementById('btnRunSql');
  if (btnSql) btnSql.addEventListener('click', executeSqlQuery);

  const btnExport = document.getElementById('btnExportCsv');
  if (btnExport) btnExport.addEventListener('click', () => {
    window.location.href = '/api/export-csv';
  });

  const btnRefreshFeed = document.getElementById('btnRefreshFeed');
  if (btnRefreshFeed) btnRefreshFeed.addEventListener('click', fetchSecurityFeed);

  const btnSimulate = document.getElementById('btnSimulateSession');
  if (btnSimulate) btnSimulate.addEventListener('click', simulateNewUserSession);

  const btnRefreshSessions = document.getElementById('btnRefreshSessions');
  if (btnRefreshSessions) btnRefreshSessions.addEventListener('click', fetchSessionsFeed);

  // Global Event Delegation (Zero inline onclick handlers)
  document.addEventListener('click', (e) => {
    // 1. Navigation View Switcher
    const viewBtn = e.target.closest('[data-view]');
    if (viewBtn) {
      switchView(viewBtn.dataset.view);
      return;
    }

    // 2. Attack Simulation Buttons
    const attackBtn = e.target.closest('[data-attack-sim]');
    if (attackBtn) {
      runAttackSim(attackBtn.dataset.attackSim);
      return;
    }

    // 3. SQL Presets
    const sqlPresetBtn = e.target.closest('[data-sql-preset]');
    if (sqlPresetBtn) {
      setSqlQuery(sqlPresetBtn.dataset.sqlPreset);
      return;
    }

    // 4. Severity Filter Buttons
    const filterBtn = e.target.closest('[data-filter]');
    if (filterBtn) {
      applyFilter(filterBtn.dataset.filter);
      return;
    }

    // 5. Session Inspection Action
    const inspectBtn = e.target.closest('[data-action="inspect-session"]');
    if (inspectBtn) {
      const sessionId = inspectBtn.dataset.sessionId;
      const user = inspectBtn.dataset.user;
      const ip = inspectBtn.dataset.ip;
      const portal = inspectBtn.dataset.portal;
      loadSessionActivities(sessionId, user, ip, portal);
      return;
    }
  });
});

// Discover session identity, CSRF token, and DEMO_MODE visibility
async function initAuthAndCsrf() {
  try {
    const res = await fetch('/api/auth/me');
    if (res.ok) {
      const data = await res.json();
      if (data.session && data.session.csrf_token) {
        currentCsrfToken = data.session.csrf_token;
      }
      if (data.demoMode === false) {
        // Hide simulation buttons and panels when DEMO_MODE is disabled
        document.querySelectorAll('[data-attack-sim]').forEach(el => {
          const panel = el.closest('.panel-box');
          if (panel) panel.classList.add('hidden');
        });
        const btnSimSession = document.getElementById('btnSimulateSession');
        if (btnSimSession) btnSimSession.style.display = 'none';
      }
    }
  } catch (_) {}
}

// UTC System Clock
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

// Global System Stats
async function fetchSystemStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const data = await res.json();

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
  } catch (err) {
    console.error('Stats poll error:', err);
  }
}

// Fetch Security Telemetry Feed
async function fetchSecurityFeed() {
  try {
    const res = await fetch('/api/events');
    if (!res.ok) return;
    telemetryEvents = await res.json();
    renderSocTable();
  } catch (err) {
    console.error('Telemetry stream error:', err);
  }
}

// Render SOC Data Table
function renderSocTable() {
  const tbody = document.getElementById('socTableBody');
  const countLabel = document.getElementById('eventsCountLabel');
  if (!tbody || !countLabel) return;

  const filtered = activeFilter === 'ALL'
    ? telemetryEvents
    : telemetryEvents.filter(e => e.severity === activeFilter);

  countLabel.textContent = `Mostrando ${filtered.length} de ${telemetryEvents.length} eventos en búfer`;

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">
          Sin incidentes registrados con el filtro [${escapeHtml(activeFilter)}]
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered.map(ev => {
    const date = new Date(ev.timestamp);
    const timeFormatted = date.toISOString().replace('T', ' ').substring(11, 19) + ' UTC';
    const actionClass = ev.action === 'BLOCKED' ? 'action-blocked' : (ev.action === 'IP_BLOCKED' ? 'action-ip-blocked' : 'action-passed');
    const validSev = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(ev.severity) ? ev.severity : 'INFO';

    return `
      <tr>
        <td style="color: var(--text-muted); font-size: 11px;">${timeFormatted}</td>
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

// Severity Filters
function applyFilter(filter) {
  activeFilter = filter;
  document.querySelectorAll('.btn-filter').forEach(btn => {
    if (btn.dataset.filter === filter) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });
  renderSocTable();
}

// Execute Remote URL Audit
async function executeUrlAudit() {
  const urlInput = document.getElementById('targetUrlInput').value.trim();
  const badge = document.getElementById('scanScoreBadge');
  const summaryBox = document.getElementById('auditSummaryBox');
  const btn = document.getElementById('btnScanUrl');

  if (!urlInput) return alert('Por favor ingrese una URL válida (ej. http://127.0.0.1:4000)');

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

    badge.classList.remove('hidden');
    badge.textContent = `${data.securityScore}/100`;

    if (data.securityScore >= 80) {
      badge.style.background = 'var(--color-success-bg)';
      badge.style.color = 'var(--color-success)';
      badge.style.border = '1px solid var(--color-success-border)';
    } else if (data.securityScore >= 50) {
      badge.style.background = 'var(--color-warning-bg)';
      badge.style.color = 'var(--color-warning)';
      badge.style.border = '1px solid var(--color-warning-border)';
    } else {
      badge.style.background = 'var(--color-critical-bg)';
      badge.style.color = 'var(--color-critical)';
      badge.style.border = '1px solid var(--color-critical-border)';
    }

    summaryBox.classList.remove('hidden');
    const tbody = document.getElementById('headersTableBody');
    if (!tbody || !data.headerChecks) return;

    tbody.innerHTML = Object.values(data.headerChecks).map(h => `
      <tr>
        <td style="font-family: var(--font-mono); font-weight: 500;">${escapeHtml(h.header)}</td>
        <td>
          ${h.present
            ? '<span class="status-present">PRESENTE</span>'
            : '<span class="status-missing">FALTANTE</span>'}
        </td>
        <td style="color: var(--text-secondary); font-size: 11px;">${escapeHtml(h.impact)}</td>
      </tr>
    `).join('');

    fetchSecurityFeed();
    fetchSystemStats();
  } catch (err) {
    alert('Fallo al conectar con la API de auditoría: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Auditar';
  }
}

// Execute Heuristic Payload Inspection
async function executePayloadInspection() {
  const input = document.getElementById('payloadInput').value;
  const honeypot = document.getElementById('honeypotInput').value;
  const badge = document.getElementById('inspectBadge');
  const btn = document.getElementById('btnInspectPayload');

  btn.disabled = true;
  try {
    const res = await fetch('/api/analyze-request', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': currentCsrfToken
      },
      body: JSON.stringify({ input, honeypot, targetEndpoint: '/api/v1/auth/probe' })
    });
    const data = await res.json();
    badge.classList.remove('hidden');

    if (data.safe) {
      badge.style.background = 'var(--color-success-bg)';
      badge.style.color = 'var(--color-success)';
      badge.style.border = '1px solid var(--color-success-border)';
      badge.textContent = 'INTEGRIDAD VERIFICADA: SEGURO';
    } else {
      badge.style.background = 'var(--color-critical-bg)';
      badge.style.color = 'var(--color-critical)';
      badge.style.border = '1px solid var(--color-critical-border)';
      badge.textContent = `AMENAZA INTERCEPTADA (${data.threatCount})`;
    }

    fetchSecurityFeed();
    fetchSystemStats();
  } catch (err) {
    alert('Error al ejecutar inspección: ' + err.message);
  } finally {
    btn.disabled = false;
  }
}

// Attack Simulation Benchmarks
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
    alert('Fallo en vector de simulación: ' + err.message);
  }
}

// HTML Sanitizer
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// SQL Query Helpers
function setSqlQuery(query) {
  document.getElementById('sqlQueryInput').value = query;
  executeSqlQuery();
}

async function executeSqlQuery() {
  const query = document.getElementById('sqlQueryInput').value.trim();
  const status = document.getElementById('sqlExecutionStatus');
  const wrapper = document.getElementById('sqlResultWrapper');
  const thead = document.getElementById('sqlResultHead');
  const tbody = document.getElementById('sqlResultBody');
  const btn = document.getElementById('btnRunSql');

  if (!query) return alert('Por favor escriba una consulta SQL');

  btn.disabled = true;
  status.classList.remove('hidden');
  status.textContent = 'EJECUTANDO...';
  status.style.color = 'var(--color-info)';

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

    if (!data.success) {
      status.style.color = 'var(--color-critical)';
      status.textContent = 'ERROR EN CONSULTA';
      alert('Error SQL: ' + (data.message || data.error));
      return;
    }

    status.style.color = 'var(--color-success)';
    status.textContent = `${data.count} FILA(S) RECUPERADAS`;
    wrapper.classList.remove('hidden');

    if (data.rows.length === 0) {
      thead.innerHTML = '';
      tbody.innerHTML = '<tr><td style="padding: 8px; color: var(--text-muted);">Sin resultados.</td></tr>';
      return;
    }

    const columns = Object.keys(data.rows[0]);
    thead.innerHTML = `<tr>${columns.map(c => `<th>${escapeHtml(c.toUpperCase())}</th>`).join('')}</tr>`;

    tbody.innerHTML = data.rows.map(r => `
      <tr>${columns.map(c => `<td>${escapeHtml(String(r[c]))}</td>`).join('')}</tr>
    `).join('');
  } catch (err) {
    status.style.color = 'var(--color-critical)';
    status.textContent = 'FALLO DE RED';
    alert('Error al ejecutar consulta SQL: ' + err.message);
  } finally {
    btn.disabled = false;
  }
}

// View Switcher
function switchView(viewName) {
  const socTab = document.getElementById('tabSoc');
  const sessionsTab = document.getElementById('tabSessions');
  const socView = document.getElementById('view-soc');
  const sessionsView = document.getElementById('view-sessions');

  if (viewName === 'soc') {
    socTab.classList.add('active');
    sessionsTab.classList.remove('active');
    socView.classList.remove('hidden');
    sessionsView.classList.add('hidden');
  } else if (viewName === 'sessions') {
    sessionsTab.classList.add('active');
    socTab.classList.remove('active');
    sessionsView.classList.remove('hidden');
    socView.classList.add('hidden');
    fetchSessionsFeed();
  }
}

// User Sessions & Activity Audit
async function fetchSessionsFeed() {
  try {
    const res = await fetch('/api/sessions');
    if (!res.ok) return;
    const sessions = await res.json();
    renderSessionsTable(sessions);
  } catch (err) {
    console.error('Sessions poll error:', err);
  }
}

function renderSessionsTable(sessions) {
  const tbody = document.getElementById('sessionsTableBody');
  const countLabel = document.getElementById('sessionsFooterCount');
  if (!tbody || !countLabel) return;

  const activeCount = sessions.filter(s => s.status === 'ACTIVA').length;
  let totalActs = 0;
  sessions.forEach(s => totalActs += (s.total_activities || 0));

  const elActive = document.getElementById('kpiActiveSessions');
  if (elActive) elActive.textContent = activeCount;

  const elTotal = document.getElementById('kpiTotalSessions');
  if (elTotal) elTotal.textContent = sessions.length;

  const elActs = document.getElementById('kpiTotalActivities');
  if (elActs) elActs.textContent = totalActs;

  countLabel.textContent = `Registradas ${sessions.length} sesiones en base de datos SQLite (${activeCount} activas actualmente)`;

  if (sessions.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; padding: 30px; color: var(--text-muted);">Sin sesiones registradas.</td></tr>`;
    return;
  }

  tbody.innerHTML = sessions.map(s => {
    const isSelected = s.session_id === currentSelectedSessionId ? 'row-selected' : '';
    const loginDate = new Date(s.login_time);
    const loginFormatted = loginDate.toISOString().replace('T', ' ').substring(11, 19) + ' UTC';
    
    let logoutFormatted = '<span style="color: var(--color-success); font-weight: 600;">En curso</span>';
    if (s.logout_time) {
      const logoutDate = new Date(s.logout_time);
      logoutFormatted = logoutDate.toISOString().replace('T', ' ').substring(11, 19) + ' UTC';
    }

    const durationText = s.duration_minutes > 0 ? `${s.duration_minutes} min` : '< 1 min';

    return `
      <tr class="${isSelected}">
        <td>
          <span class="badge-status badge-status-${escapeHtml(s.status)}">${escapeHtml(s.status)}</span>
        </td>
        <td>
          <div style="font-weight: 600; color: var(--text-primary);">
            ${escapeHtml(s.user_identifier)}
            ${s.is_simulated ? '<span style="background: rgba(147, 51, 234, 0.15); color: #c084fc; border: 1px solid rgba(192, 132, 252, 0.3); font-size: 9px; padding: 1px 4px; border-radius: 3px; margin-left: 4px;">SIMULADO</span>' : ''}
          </div>
          <div style="font-size: 9px; color: var(--text-muted);">${escapeHtml(s.role)}</div>
        </td>
        <td style="color: var(--color-info);">${escapeHtml(s.ip_address)}</td>
        <td>
          <span style="font-family: var(--font-mono); color: var(--text-secondary); background: var(--bg-control); padding: 2px 6px; border-radius: 3px; border: 1px solid var(--border-subtle);">
            ${escapeHtml(s.login_portal)}
          </span>
        </td>
        <td style="color: var(--text-muted); font-size: 10px;">${loginFormatted}</td>
        <td style="font-size: 10px;">${logoutFormatted}</td>
        <td style="color: var(--text-secondary); font-weight: 600;">${durationText}</td>
        <td>
          <button class="btn btn-outline btn-sm" 
            data-action="inspect-session" 
            data-session-id="${escapeHtml(s.session_id)}" 
            data-user="${escapeHtml(s.user_identifier)}" 
            data-ip="${escapeHtml(s.ip_address)}" 
            data-portal="${escapeHtml(s.login_portal)}">
            Ver Trazabilidad (${s.total_activities || 0})
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

// Load Activity Trail for a given session
async function loadSessionActivities(sessionId, userIdentifier, ip, portal) {
  currentSelectedSessionId = sessionId;
  const chip = document.getElementById('selectedSessionChip');
  if (chip) chip.textContent = sessionId;

  const sub = document.getElementById('selectedSessionSub');
  if (sub) sub.textContent = `${userIdentifier} • IP: ${ip} • Portal: ${portal}`;

  const container = document.getElementById('activityTimelineContainer');
  if (!container) return;

  container.innerHTML = `<div style="text-align: center; padding: 20px; color: var(--text-muted);">Cargando trazabilidad de actividades...</div>`;

  try {
    const res = await fetch(`/api/sessions/activities?sessionId=${encodeURIComponent(sessionId)}`);
    if (!res.ok) return;
    const activities = await res.json();

    if (activities.length === 0) {
      container.innerHTML = `<div style="text-align: center; padding: 30px; color: var(--text-muted);">Sin acciones registradas para esta sesión.</div>`;
      return;
    }

    container.innerHTML = activities.map(act => {
      const time = new Date(act.timestamp).toISOString().replace('T', ' ').substring(11, 19) + ' UTC';
      const safeRisk = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NORMAL'].includes(act.risk_level) ? act.risk_level : 'NORMAL';

      return `
        <div class="timeline-step risk-${safeRisk}">
          <div class="timeline-header">
            <span class="timeline-action">${escapeHtml(act.action_type)}</span>
            <span class="timeline-time">${time}</span>
          </div>
          <div class="timeline-endpoint">${escapeHtml(act.endpoint)}</div>
          <div class="timeline-desc">${escapeHtml(act.description)}</div>
        </div>
      `;
    }).join('');

    fetchSessionsFeed();
  } catch (err) {
    container.innerHTML = `<div style="color: var(--color-critical); padding: 20px;">Error al cargar actividades: ${escapeHtml(err.message)}</div>`;
  }
}

// Simulate New User Session
async function simulateNewUserSession() {
  try {
    const res = await fetch('/api/sessions/simulate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': currentCsrfToken
      },
      body: JSON.stringify({})
    });
    const data = await res.json();
    if (data.success) {
      fetchSessionsFeed();
    }
  } catch (err) {
    alert('Fallo al simular sesión: ' + err.message);
  }
}
