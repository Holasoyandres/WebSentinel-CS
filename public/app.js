// WebSentinel-CS: Interactive Frontend Engine
let currentFilter = 'ALL';
let allEvents = [];

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
  fetchStats();
  fetchEvents();
  setInterval(fetchStats, 3000);
  setInterval(fetchEvents, 3000);

  // Bind Buttons
  document.getElementById('btnScanUrl').addEventListener('click', runUrlScan);
  document.getElementById('btnInspectPayload').addEventListener('click', runPayloadInspection);
});

// Fetch KPI metrics & uptime
async function fetchStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById('kpiThreats').textContent = data.threatsDetected;
    document.getElementById('kpiBruteForce').textContent = data.bruteForceBlocked;
    document.getElementById('kpiScans').textContent = data.totalScans;
    document.getElementById('kpiInspections').textContent = data.inspectionsRun;

    // Format Uptime
    const sec = data.uptimeSeconds;
    const hrs = Math.floor(sec / 3600);
    const mins = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    document.getElementById('uptimeBadge').textContent = `Uptime: ${hrs}h ${mins}m ${s}s`;
  } catch (err) {
    console.error('Stats poll error:', err);
  }
}

// Fetch security events stream
async function fetchEvents() {
  try {
    const res = await fetch('/api/events');
    if (!res.ok) return;
    allEvents = await res.json();
    renderEvents();
  } catch (err) {
    console.error('Events poll error:', err);
  }
}

// Render event list based on active filter
function renderEvents() {
  const container = document.getElementById('eventsStream');
  const filtered = currentFilter === 'ALL' 
    ? allEvents 
    : allEvents.filter(e => e.severity === currentFilter);

  document.getElementById('eventCounterLabel').textContent = `Mostrando ${filtered.length} de ${allEvents.length} eventos`;

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="padding: 32px; text-align: center; color: var(--text-muted); font-size: 0.85rem;">
        No hay eventos con filtro "${currentFilter}" registrados aún.
      </div>
    `;
    return;
  }

  container.innerHTML = filtered.map(ev => {
    const timeStr = new Date(ev.timestamp).toLocaleTimeString();
    return `
      <div class="event-row sev-${ev.severity}">
        <div class="event-top">
          <span class="event-type">${escapeHtml(ev.type)}</span>
          <span class="event-time">${timeStr}</span>
        </div>
        <div class="event-meta">
          <span>IP: ${escapeHtml(ev.sourceIp)}</span>
          <span>&bull;</span>
          <span>Objetivo: ${escapeHtml(ev.target)}</span>
        </div>
        <div class="event-details">${escapeHtml(ev.details)}</div>
      </div>
    `;
  }).join('');
}

// Filter event pills
function filterEvents(filter) {
  currentFilter = filter;
  document.querySelectorAll('.filter-pills .pill').forEach(btn => {
    btn.classList.toggle('active', btn.textContent.includes(filter) || (filter === 'ALL' && btn.textContent === 'TODOS'));
  });
  renderEvents();
}

// Run URL security audit
async function runUrlScan() {
  const input = document.getElementById('targetUrlInput');
  const btn = document.getElementById('btnScanUrl');
  const resultCard = document.getElementById('scanResultContainer');
  const url = input.value.trim();

  if (!url) return alert('Por favor ingresa una URL válida');

  btn.disabled = true;
  btn.textContent = 'Auditando...';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await res.json();

    resultCard.classList.remove('hidden');

    if (data.error) {
      document.getElementById('scoreCircle').textContent = 'ERR';
      document.getElementById('scoreCircle').style.borderColor = 'var(--accent-red)';
      document.getElementById('scoreCircle').style.color = 'var(--accent-red)';
      document.getElementById('scoreTitle').textContent = 'Error de Conexión';
      document.getElementById('scoreDetails').textContent = data.error;
      document.getElementById('headersChecklist').innerHTML = '';
      return;
    }

    const score = data.securityScore;
    const scoreColor = score >= 80 ? 'var(--accent-green)' : (score >= 50 ? 'var(--accent-amber)' : 'var(--accent-red)');

    const circle = document.getElementById('scoreCircle');
    circle.textContent = `${score}%`;
    circle.style.borderColor = scoreColor;
    circle.style.color = scoreColor;

    document.getElementById('scoreTitle').textContent = `Calificación de Blindaje: ${score}/100`;
    document.getElementById('scoreDetails').textContent = `Estado HTTP: ${data.statusCode} | Latencia: ${data.latencyMs}ms | Faltan ${data.missingHeadersCount} cabeceras`;

    // Render headers checklist
    const checklist = document.getElementById('headersChecklist');
    checklist.innerHTML = Object.entries(data.headerChecks).map(([header, check]) => {
      return `
        <div class="header-item">
          <div>
            <span class="header-name">${header}</span>
            <div style="font-size: 0.7rem; color: var(--text-muted);">${check.recommendation}</div>
          </div>
          <span class="badge ${check.present ? 'badge-pass' : 'badge-fail'}">
            ${check.present ? 'PRESENTE' : 'FALTANTE'}
          </span>
        </div>
      `;
    }).join('');

    fetchEvents();
    fetchStats();
  } catch (err) {
    alert('Error al conectar con la API de escaneo: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Auditar URL';
  }
}

// Run interactive payload inspection
async function runPayloadInspection() {
  const input = document.getElementById('payloadInput').value;
  const honeypot = document.getElementById('honeypotInput').value;
  const feedback = document.getElementById('inspectFeedback');
  const btn = document.getElementById('btnInspectPayload');

  btn.disabled = true;
  try {
    const res = await fetch('/api/analyze-request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input, honeypot, targetEndpoint: '/formulario-inspeccion' })
    });
    const data = await res.json();

    feedback.classList.remove('hidden');
    if (data.safe) {
      feedback.className = 'badge badge-pass';
      feedback.textContent = '✓ ENTRADA LIMPIA Y SEGURA';
    } else {
      feedback.className = 'badge badge-fail';
      feedback.textContent = `⚠️ ${data.threatCount} AMENAZA(S) DETECTADA(S)`;
    }

    fetchEvents();
    fetchStats();
  } catch (err) {
    alert('Error al analizar payload: ' + err.message);
  } finally {
    btn.disabled = false;
  }
}

// Simulate attack for live portfolio demo
async function simulateAttack(vector) {
  try {
    await fetch('/api/simulate-attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vector })
    });
    fetchEvents();
    fetchStats();
  } catch (err) {
    alert('Error al simular ataque: ' + err.message);
  }
}

// Helper: Escape HTML
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
