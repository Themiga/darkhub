/**
 * DarkHub — admin.js
 * Admin panel logic: auth check, routing, script CRUD, analytics.
 * All API calls use the JWT stored in sessionStorage.
 * No secrets or keys are present in this file.
 */

// ─── Configuration ────────────────────────────────────────────────────────────
// Replace with your actual Cloudflare Worker URL at deploy time.
const WORKER = 'https://darkhub-api.themiga.workers.dev';

// ─── State ────────────────────────────────────────────────────────────────────
let currentPage = 'dashboard';
let scriptsCache = [];
let analyticsCache = [];

// ─── Bootstrap ────────────────────────────────────────────────────────────────

window.addEventListener('DOMContentLoaded', async () => {
  // Set the GitHub login button href dynamically from worker
  const loginBtn = document.getElementById('github-login-btn');
  if (loginBtn) loginBtn.href = `${WORKER}/api/auth/github`;

  const token = sessionStorage.getItem('dh_token');
  if (!token) {
    showLogin();
    return;
  }

  // Verify token is still valid
  try {
    const me = await api('/api/auth/me');
    initShell(me);
  } catch {
    sessionStorage.removeItem('dh_token');
    showLogin();
  }
});

// ─── Auth ─────────────────────────────────────────────────────────────────────

function showLogin() {
  document.getElementById('admin-login').style.display = 'flex';
  document.getElementById('admin-shell').style.display  = 'none';
}

function initShell(user) {
  document.getElementById('admin-login').style.display = 'none';
  document.getElementById('admin-shell').style.display  = 'flex';

  document.getElementById('admin-name').textContent = user.login;
  document.getElementById('admin-avatar').src = user.avatar;

  navigate('dashboard');
}

async function logout() {
  try { await api('/api/auth/logout', { method: 'POST' }); } catch {}
  sessionStorage.removeItem('dh_token');
  showLogin();
}

// ─── Navigation ───────────────────────────────────────────────────────────────

async function navigate(page) {
  currentPage = page;

  // Update sidebar active state
  document.querySelectorAll('.sidebar-link').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page);
  });

  const titleEl  = document.getElementById('page-title');
  const actionEl = document.getElementById('topbar-action');
  const content  = document.getElementById('admin-content');

  actionEl.style.display = 'none';

  switch (page) {
    case 'dashboard':
      titleEl.textContent = 'Dashboard';
      await renderDashboard(content);
      break;
    case 'scripts':
      titleEl.textContent = 'Scripts';
      actionEl.textContent = '+ New Script';
      actionEl.style.display = 'inline-block';
      await renderScripts(content);
      break;
    case 'analytics':
      titleEl.textContent = 'Analytics';
      await renderAnalytics(content);
      break;
  }
}

function topbarAction() {
  if (currentPage === 'scripts') openNewModal();
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

async function renderDashboard(el) {
  el.innerHTML = `<div class="spinner" style="margin:4rem auto;"></div>`;

  const [scripts, analytics] = await Promise.all([
    api('/api/admin/scripts').catch(() => ({ scripts: [] })),
    api('/api/admin/analytics').catch(() => ({ analytics: [] })),
  ]);

  const totalScripts = scripts.scripts.length;
  const activeScripts = scripts.scripts.filter(s => s.enabled).length;
  const totalExec = analytics.analytics.reduce((s, a) => s + (a.total || 0), 0);
  const topGame = analytics.analytics[0]?.placeId ?? '—';

  el.innerHTML = `
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-label">Total Scripts</div>
        <div class="stat-value">${totalScripts}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Active Scripts</div>
        <div class="stat-value">${activeScripts}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Total Executions</div>
        <div class="stat-value">${totalExec.toLocaleString()}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Top Game (PlaceId)</div>
        <div class="stat-value" style="font-size:1.2rem">${topGame}</div>
      </div>
    </div>

    <div class="table-wrap">
      <div class="table-header">
        <h2>Recent Scripts</h2>
        <button class="btn-primary btn-sm" onclick="navigate('scripts')">View All</button>
      </div>
      ${renderScriptTable(scripts.scripts.slice(0, 5), analytics.analytics, false)}
    </div>
  `;
}

// ─── Scripts ──────────────────────────────────────────────────────────────────

async function renderScripts(el) {
  el.innerHTML = `<div class="spinner" style="margin:4rem auto;"></div>`;

  const [scriptsRes, analyticsRes] = await Promise.all([
    api('/api/admin/scripts').catch(() => ({ scripts: [] })),
    api('/api/admin/analytics').catch(() => ({ analytics: [] })),
  ]);

  scriptsCache   = scriptsRes.scripts || [];
  analyticsCache = analyticsRes.analytics || [];

  el.innerHTML = `
    <div class="table-wrap">
      <div class="table-header">
        <h2>All Scripts (${scriptsCache.length})</h2>
      </div>
      ${renderScriptTable(scriptsCache, analyticsCache, true)}
    </div>
  `;
}

function renderScriptTable(scripts, analytics, showActions) {
  if (!scripts.length) {
    return `<div class="empty-state"><div class="empty-icon">📜</div><p>No scripts yet. Click "+ New Script" to add one.</p></div>`;
  }

  const analyticsMap = {};
  analytics.forEach(a => { analyticsMap[a.placeId] = a.total; });

  const rows = scripts.map(s => `
    <tr>
      <td><strong>${esc(s.name)}</strong></td>
      <td><code>${esc(s.placeId)}</code></td>
      <td><span class="${s.enabled ? 'badge-enabled' : 'badge-disabled'}">${s.enabled ? 'Active' : 'Disabled'}</span></td>
      <td>${(analyticsMap[s.placeId] || 0).toLocaleString()}</td>
      <td>${fmtDate(s.updatedAt)}</td>
      ${showActions ? `
      <td>
        <div class="td-actions">
          <button class="btn-edit" onclick="openEditModal('${s.id}')">Edit</button>
          <button class="btn-danger btn-sm" onclick="deleteScript('${s.id}','${esc(s.name)}')">Delete</button>
        </div>
      </td>` : '<td></td>'}
    </tr>
  `).join('');

  return `
    <table>
      <thead><tr>
        <th>Name</th><th>Place ID</th><th>Status</th>
        <th>Executions</th><th>Updated</th>${showActions ? '<th>Actions</th>' : '<th></th>'}
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

// ─── Analytics ────────────────────────────────────────────────────────────────

async function renderAnalytics(el) {
  el.innerHTML = `<div class="spinner" style="margin:4rem auto;"></div>`;

  const [analyticsRes, scriptsRes] = await Promise.all([
    api('/api/admin/analytics').catch(() => ({ analytics: [] })),
    api('/api/admin/scripts').catch(() => ({ scripts: [] })),
  ]);

  const analytics = analyticsRes.analytics || [];
  const scripts   = scriptsRes.scripts || [];
  const scriptMap = {};
  scripts.forEach(s => { scriptMap[s.placeId] = s.name; });

  const rows = analytics.map(a => `
    <tr>
      <td><strong>${esc(scriptMap[a.placeId] || '—')}</strong></td>
      <td><code>${esc(a.placeId)}</code></td>
      <td><strong style="color:var(--accent)">${a.total.toLocaleString()}</strong></td>
      <td>${a.lastSeen ? fmtDate(a.lastSeen) : '—'}</td>
      <td>
        <button class="btn-edit" onclick="showScriptChart('${a.placeId}','${esc(scriptMap[a.placeId] || a.placeId)}')">
          View Chart
        </button>
      </td>
    </tr>
  `).join('');

  el.innerHTML = `
    <div id="chart-area" style="display:none;" class="chart-wrap">
      <h2 id="chart-title" style="font-size:1rem;font-weight:700;margin-bottom:.25rem;"></h2>
      <p id="chart-sub" style="color:var(--muted);font-size:.8rem;margin-bottom:.5rem;"></p>
      <div class="chart-bars" id="chart-bars"></div>
    </div>

    <div class="table-wrap">
      <div class="table-header"><h2>Execution Stats</h2></div>
      ${analytics.length ? `
        <table>
          <thead><tr><th>Script</th><th>Place ID</th><th>Total Executions</th><th>Last Seen</th><th></th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      ` : '<div class="empty-state"><div class="empty-icon">📈</div><p>No execution data yet.</p></div>'}
    </div>
  `;
}

async function showScriptChart(placeId, name) {
  const chartArea = document.getElementById('chart-area');
  chartArea.style.display = 'block';
  document.getElementById('chart-title').textContent = name;
  document.getElementById('chart-sub').textContent = `Daily executions for Place ID ${placeId} (last 30 days)`;
  document.getElementById('chart-bars').innerHTML = `<div class="spinner" style="margin:1rem auto;"></div>`;

  try {
    const data = await api(`/api/admin/analytics?placeId=${placeId}`);
    const daily = data.daily || [];
    const max = Math.max(...daily.map(d => d.count), 1);

    const bars = daily.map(d => {
      const pct = Math.max((d.count / max) * 100, 1);
      const label = d.date.slice(5); // MM-DD
      return `
        <div class="chart-bar" style="height:${pct}%;">
          <div class="chart-bar-tooltip">${label}: ${d.count}</div>
        </div>
      `;
    }).join('');

    document.getElementById('chart-bars').innerHTML = bars;
    chartArea.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch {
    document.getElementById('chart-bars').innerHTML = '<p style="color:var(--muted)">Failed to load data.</p>';
  }
}

// ─── Modal ────────────────────────────────────────────────────────────────────

function openNewModal() {
  document.getElementById('modal-title').textContent = 'New Script';
  document.getElementById('modal-script-id').value = '';
  document.getElementById('modal-name').value = '';
  document.getElementById('modal-placeid').value = '';
  document.getElementById('modal-desc').value = '';
  document.getElementById('modal-source').value = '';
  document.getElementById('modal-enabled').checked = true;
  document.getElementById('script-modal').classList.add('open');
}

async function openEditModal(id) {
  document.getElementById('modal-title').textContent = 'Edit Script';
  document.getElementById('script-modal').classList.add('open');

  try {
    const script = await api(`/api/admin/scripts/${id}`);
    document.getElementById('modal-script-id').value = script.id;
    document.getElementById('modal-name').value = script.name;
    document.getElementById('modal-placeid').value = script.placeId;
    document.getElementById('modal-desc').value = script.description || '';
    document.getElementById('modal-source').value = script.source || '';
    document.getElementById('modal-enabled').checked = script.enabled;
  } catch {
    toast('Failed to load script.', 'error');
    closeModal();
  }
}

function closeModal() {
  document.getElementById('script-modal').classList.remove('open');
}

async function saveScript() {
  const id      = document.getElementById('modal-script-id').value;
  const name    = document.getElementById('modal-name').value.trim();
  const placeId = document.getElementById('modal-placeid').value.trim();
  const desc    = document.getElementById('modal-desc').value.trim();
  const source  = document.getElementById('modal-source').value;
  const enabled = document.getElementById('modal-enabled').checked;

  if (!name || !placeId || !source) {
    toast('Name, Place ID, and source are required.', 'error');
    return;
  }

  if (!/^\d+$/.test(placeId)) {
    toast('Place ID must be numeric.', 'error');
    return;
  }

  try {
    if (id) {
      await api(`/api/admin/scripts/${id}`, {
        method: 'PUT',
        body: JSON.stringify({ name, placeId, description: desc, source, enabled }),
      });
      toast('Script updated successfully.', 'success');
    } else {
      await api('/api/admin/scripts', {
        method: 'POST',
        body: JSON.stringify({ name, placeId, description: desc, source, enabled }),
      });
      toast('Script created successfully.', 'success');
    }
    closeModal();
    navigate('scripts');
  } catch (err) {
    toast('Save failed: ' + err.message, 'error');
  }
}

async function deleteScript(id, name) {
  if (!confirm(`Delete "${name}"? This cannot be undone.`)) return;
  try {
    await api(`/api/admin/scripts/${id}`, { method: 'DELETE' });
    toast('Script deleted.', 'success');
    navigate('scripts');
  } catch {
    toast('Delete failed.', 'error');
  }
}

// ─── API helper ───────────────────────────────────────────────────────────────

async function api(path, opts = {}) {
  const token = sessionStorage.getItem('dh_token');
  const res = await fetch(`${WORKER}${path}`, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(opts.headers || {}),
    },
    credentials: 'omit',
  });

  if (res.status === 401 || res.status === 403) {
    sessionStorage.removeItem('dh_token');
    showLogin();
    throw new Error('Session expired.');
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `HTTP ${res.status}`);
  }

  return res.json();
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function toast(msg, type = 'success') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.getElementById('toasts').appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// Close modal on overlay click
document.getElementById('script-modal')?.addEventListener('click', function (e) {
  if (e.target === this) closeModal();
});
