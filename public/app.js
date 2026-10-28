/**
 * WebSentinel-CS :: Enterprise Frontend Telemetry Engine
 * Author: Holasoyandres
 */

let activeFilter = 'ALL';
let telemetryEvents = [];
let currentSelectedSessionId = null;

document.addEventListener('DOMContentLoaded', () => {
  initClock();
  fetchSystemStats();
  fetchSecurityFeed();
  fetchSessionsFeed();

  setInterval(fetchSystemStats, 3000);
  setInterval(fetchSecurityFeed, 3000);
  setInterval(fetchSessionsFeed, 5000);

  // Wire event handlers
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
});

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
        <td colspan="7" style="text-align: center; padding: 30px; color: var(--text-muted);">
          Sin eventos registrados para el filtro [${activeFilter}].
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered.map(ev => {
    const date = new Date(ev.timestamp);
    const timeFormatted = date.toISOString().replace('T', ' ').substring(11, 19);

    return `
      <tr>
        <td style="color: var(--text-muted);">${timeFormatted}</td>
        <td>
          <span class="badge-sev badge-sev-${ev.severity}">${ev.severity}</span>
        </td>
        <td style="color: var(--text-secondary);">${escapeHtml(ev.ruleId || ev.rule_id || 'N/A')}</td>
        <td style="color: var(--color-info);">${escapeHtml(ev.sourceIp || ev.source_ip)}</td>
        <td style="color: var(--text-primary);">${escapeHtml(ev.target)}</td>
        <td class="col-desc">${escapeHtml(ev.details)}</td>
        <td>
          <span class="badge-action badge-action-${ev.action || 'LOGGED'}">${ev.action || 'LOGGED'}</span>
        </td>
      </tr>
    `;
  }).join('');
}

// Severity Filters
function applyFilter(filter) {
  activeFilter = filter;
  document.querySelectorAll('.filter-group .btn-filter').forEach(btn => {
    btn.classList.toggle('active', btn.textContent === filter || (filter === 'ALL' && btn.textContent === 'TODOS'));
  });
  renderSocTable();
}

// Execute Target URL Audit
async function executeUrlAudit() {
  const input = document.getElementById('targetUrlInput');
  const btn = document.getElementById('btnScanUrl');
  const area = document.getElementById('scanReportArea');
  const url = input.value.trim();

  if (!url) return alert('Por favor especifique una URL válida (http:// o https://)');

  btn.disabled = true;
  btn.textContent = 'Auditando...';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();
    area.classList.remove('hidden');

    if (data.error) {
      document.getElementById('scoreValue').textContent = 'FALLO';
      document.getElementById('scoreValue').style.color = 'var(--color-critical)';
      document.getElementById('statusHttp').textContent = 'ERR';
      document.getElementById('latencyHttp').textContent = '--';
      document.getElementById('headersTableBody').innerHTML = `
        <tr><td colspan="2" style="color: var(--color-critical); padding: 8px;">${escapeHtml(data.error)}</td></tr>
      `;
      return;
    }

    const score = data.securityScore;
    const scoreColor = score >= 80 ? 'var(--color-success)' : (score >= 50 ? 'var(--color-medium)' : 'var(--color-critical)');

    document.getElementById('scoreValue').textContent = `${score}%`;
    document.getElementById('scoreValue').style.color = scoreColor;
    document.getElementById('statusHttp').textContent = data.statusCode;
    document.getElementById('latencyHttp').textContent = `${data.latencyMs} ms`;

    const tbody = document.getElementById('headersTableBody');
    tbody.innerHTML = Object.values(data.headerChecks).map(h => `
      <tr>
        <td>
          <div style="font-weight: 600; color: var(--text-primary);">${h.header}</div>
          <div style="font-size: 9px; color: var(--text-muted);">${h.impact}</div>
        </td>
        <td style="text-align: right;">
          <span class="${h.present ? 'badge-state-pass' : 'badge-state-fail'}">
            ${h.present ? 'COMPLIANT' : 'MISSING'}
          </span>
        </td>
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
      headers: { 'Content-Type': 'application/json' },
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
      headers: { 'Content-Type': 'application/json' },
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
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query })
    });
    const data = await res.json();

    if (!data.success) {
      status.style.color = 'var(--color-critical)';
      status.textContent = 'ERROR EN CONSULTA';
      alert('Error SQL: ' + data.error);
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

// ==========================================
// VIEW SWITCHER (SUBPÁGINAS)
// ==========================================
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

// ==========================================
// USER SESSIONS & ACTIVITY AUDIT
// ==========================================
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
          <span class="badge-status badge-status-${s.status}">${s.status}</span>
        </td>
        <td>
          <div style="font-weight: 600; color: var(--text-primary);">${escapeHtml(s.user_identifier)}</div>
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
          <button class="btn btn-outline btn-sm" onclick="loadSessionActivities('${s.session_id}', '${escapeHtml(s.user_identifier)}', '${escapeHtml(s.ip_address)}', '${escapeHtml(s.login_portal)}')">
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
      return `
        <div class="timeline-step risk-${act.risk_level || 'NORMAL'}">
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
    container.innerHTML = `<div style="color: var(--color-critical); padding: 20px;">Error al cargar actividades: ${err.message}</div>`;
  }
}

// Simulate a brand new user session with live activity
async function simulateNewUserSession() {
  try {
    const res = await fetch('/api/sessions/simulate', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      await fetchSessionsFeed();
      loadSessionActivities(data.sessionId, data.user, '172.16.0.88', '/tramites-suit');
    }
  } catch (err) {
    alert('Error al simular sesión: ' + err.message);
  }
}
