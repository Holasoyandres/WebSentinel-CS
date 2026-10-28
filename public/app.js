/**
 * WebSentinel-CS :: Enterprise Frontend Telemetry Engine
 * Author: Holasoyandres
 */

let activeFilter = 'ALL';
let telemetryEvents = [];

document.addEventListener('DOMContentLoaded', () => {
  initClock();
  fetchSystemStats();
  fetchSecurityFeed();

  setInterval(fetchSystemStats, 3000);
  setInterval(fetchSecurityFeed, 3000);

  // Wire event handlers
  document.getElementById('btnScanUrl').addEventListener('click', executeUrlAudit);
  document.getElementById('btnInspectPayload').addEventListener('click', executePayloadInspection);
  document.getElementById('btnRunSql').addEventListener('click', executeSqlQuery);
  document.getElementById('btnExportCsv').addEventListener('click', () => {
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

    document.getElementById('kpiThreats').textContent = data.threatsDetected.toLocaleString();
    document.getElementById('kpiBruteForce').textContent = data.bruteForceBlocked.toLocaleString();
    document.getElementById('kpiScans').textContent = data.totalScans.toLocaleString();
    document.getElementById('kpiInspections').textContent = data.inspectionsRun.toLocaleString();

    const sec = data.uptimeSeconds;
    const hrs = Math.floor(sec / 3600);
    const mins = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    document.getElementById('uptimeText').textContent = `${hrs}h ${mins}m ${s}s`;
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
        <td style="color: var(--text-secondary);">${escapeHtml(ev.ruleId || 'N/A')}</td>
        <td style="color: var(--color-info);">${escapeHtml(ev.sourceIp)}</td>
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

    // Render columns
    const columns = Object.keys(data.rows[0]);
    thead.innerHTML = `<tr>${columns.map(c => `<th>${escapeHtml(c.toUpperCase())}</th>`).join('')}</tr>`;

    // Render rows
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

