//! F6.5: Web UI single-file untuk API v2 (login JWT, jobs, live WS, stop, report, audit).

pub const WEB_UI_HTML: &str = r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Veltrix Web UI v2</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1923; color: #e0e0e0; }
  .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
  h1 { color: #00ff88; font-size: 24px; margin-bottom: 20px; border-bottom: 1px solid #1a2d3d; padding-bottom: 10px; }
  h2 { color: #00ff88; font-size: 18px; margin: 15px 0; }
  h3 { color: #00ccff; font-size: 15px; margin: 12px 0 6px; }
  .card { background: #1a2d3d; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid #2a3d4d; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 20px; }
  .stat { text-align: center; padding: 15px; background: #0f1923; border-radius: 6px; }
  .stat-value { font-size: 28px; font-weight: bold; }
  .stat-label { font-size: 12px; color: #8899aa; margin-top: 5px; }
  label { display: block; margin: 10px 0 5px; color: #8899aa; font-size: 13px; }
  input, select, textarea { width: 100%; padding: 10px; background: #0f1923; border: 1px solid #2a3d4d; border-radius: 4px; color: #e0e0e0; font-size: 14px; }
  textarea { font-family: monospace; min-height: 80px; }
  button { background: #00ff88; color: #0f1923; border: none; padding: 12px 24px; border-radius: 4px; font-size: 14px; font-weight: bold; cursor: pointer; margin-top: 10px; }
  button:hover { background: #00cc6a; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  button.danger { background: #ff4444; color: #fff; }
  button.ghost { background: #2a3d4d; color: #e0e0e0; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  th, td { padding: 10px; text-align: left; border-bottom: 1px solid #2a3d4d; font-size: 13px; }
  th { color: #8899aa; font-weight: normal; text-transform: uppercase; font-size: 11px; }
  .success { color: #00ff88; }
  .failure { color: #ff4444; }
  .error { color: #ffaa00; }
  .badge { padding: 3px 8px; border-radius: 10px; font-size: 11px; }
  .badge-success { background: #003322; color: #00ff88; }
  .badge-failure { background: #330000; color: #ff4444; }
  .badge-running { background: #003366; color: #00aaff; }
  .badge-queued { background: #333300; color: #ffdd00; }
  #loading { text-align: center; padding: 40px; color: #8899aa; }
  .hidden { display: none; }
  .flex { display: flex; gap: 10px; }
  .flex-grow { flex: 1; }
  .job-row { cursor: pointer; }
  .job-row:hover { background: #1a3344; }
  #job-detail { display: none; }
  #event-log { background: #0a1118; border: 1px solid #2a3d4d; border-radius: 4px; padding: 10px; font-family: monospace; font-size: 12px; max-height: 220px; overflow-y: auto; margin-top: 10px; }
  #event-log div { padding: 2px 0; border-bottom: 1px dotted #1a2d3d; }
  .bar { background: #0f1923; border-radius: 4px; height: 10px; overflow: hidden; margin-top: 4px; }
  .bar > div { background: #00ff88; height: 100%; width: 0%; }
  .warn { background: #332200; border: 1px solid #ffaa00; color: #ffdd99; padding: 10px; border-radius: 4px; margin-bottom: 15px; font-size: 13px; }
</style>
</head>
<body>
<div class="container">
  <h1>⚡ Veltrix Web UI <small style="font-size:12px;color:#8899aa">API v2 · authorized testing only</small></h1>

  <div class="card" id="login-card">
    <h2>Login</h2>
    <div class="warn">Bind server ini ke 127.0.0.1 atau jaringan manajemen tepercaya. Token API bersifat sensitif.</div>
    <label>API token (pre-shared, dari --api-token atau startup log)</label>
    <input id="api-token" type="password" placeholder="vt-...">
    <label>Actor name (untuk audit log)</label>
    <input id="actor" placeholder="operator">
    <button onclick="doLogin()">Login</button>
    <div id="login-msg" style="margin-top:10px"></div>
  </div>

  <div id="app" class="hidden">
    <div class="grid" id="stats">
      <div class="stat"><div class="stat-value" id="stat-version">-</div><div class="stat-label">Version</div></div>
      <div class="stat"><div class="stat-value" id="stat-protocols">-</div><div class="stat-label">Protocols</div></div>
      <div class="stat"><div class="stat-value" id="stat-jobs">-</div><div class="stat-label">Active Jobs</div></div>
      <div class="stat"><div class="stat-value" id="stat-status" style="color:#00ff88">Running</div><div class="stat-label">Status</div></div>
    </div>

    <div class="card">
      <h2>New Attack (non-blocking)</h2>
      <div class="flex">
        <div class="flex-grow">
          <label>Target</label>
          <input id="target" placeholder="e.g. 192.168.1.1">
        </div>
        <div style="width:150px">
          <label>Port (0 = default)</label>
          <input id="port" placeholder="0">
        </div>
        <div style="width:150px">
          <label>Protocol</label>
          <select id="protocol"><option value="">Select...</option></select>
        </div>
      </div>
      <div class="flex">
        <div class="flex-grow">
          <label>Usernames (one per line)</label>
          <textarea id="usernames" placeholder="admin&#10;root&#10;user"></textarea>
        </div>
        <div class="flex-grow">
          <label>Passwords (one per line)</label>
          <textarea id="passwords" placeholder="password&#10;123456&#10;admin"></textarea>
        </div>
      </div>
      <div class="flex">
        <div style="width:150px"><label>Threads (1-50)</label><input id="threads" value="10"></div>
        <div style="width:150px"><label>Timeout (s)</label><input id="timeout" value="10"></div>
      </div>
      <button id="start-btn" onclick="startAttack()">▶ Queue Attack</button>
      <div id="attack-result" class="hidden" style="margin-top:10px;padding:10px;border-radius:4px;"></div>
    </div>

    <div class="card">
      <h2>Jobs</h2>
      <div style="text-align:right;margin-bottom:10px">
        <button class="ghost" onclick="loadJobs()">🔄 Refresh</button>
      </div>
      <div id="loading">Loading jobs...</div>
      <div id="jobs-table" class="hidden">
        <table>
          <thead><tr><th>ID</th><th>Target</th><th>Protocol</th><th>Progress</th><th>Found</th><th>Status</th></tr></thead>
          <tbody id="jobs-body"></tbody>
        </table>
      </div>
      <div id="no-jobs" class="hidden" style="text-align:center;padding:20px;color:#8899aa">No jobs yet. Queue an attack above!</div>
    </div>

    <div class="card" id="job-detail">
      <h2 id="detail-title">Job Detail</h2>
      <button class="ghost" onclick="hideDetail()">← Back</button>
      <button class="danger" id="stop-btn" onclick="stopCurrentJob()">■ Stop</button>
      <button class="ghost" onclick="downloadReport('json')">⬇ JSON</button>
      <button class="ghost" onclick="downloadReport('html')">⬇ HTML</button>
      <div id="detail-content"></div>
      <h3>Live events</h3>
      <div id="event-log"></div>
    </div>

    <div class="card">
      <h2>Audit Log</h2>
      <button class="ghost" onclick="loadAudit()">🔄 Refresh audit</button>
      <div id="audit-content" style="margin-top:10px;font-size:12px"></div>
    </div>
  </div>
</div>

<script>
const API = '/api/v2';
let JWT = sessionStorage.getItem('vt_jwt') || '';
let CURRENT_JOB = null;
let WS = null;

if (JWT) { document.getElementById('login-card').classList.add('hidden'); document.getElementById('app').classList.remove('hidden'); boot(); }

async function apiFetch(path, opts) {
  opts = opts || {};
  opts.headers = Object.assign({ 'Authorization': 'Bearer ' + JWT }, opts.headers || {});
  const r = await fetch(API + path, opts);
  if (r.status === 401) { doLogout(); throw new Error('Unauthorized - please login again'); }
  if (!r.ok) { const t = await r.text(); throw new Error(t); }
  const ct = r.headers.get('content-type') || '';
  return ct.includes('json') ? r.json() : r.text();
}

async function doLogin() {
  const token = document.getElementById('api-token').value;
  const actor = document.getElementById('actor').value || 'operator';
  try {
    const r = await fetch(API + '/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, actor }) });
    if (!r.ok) throw new Error(await r.text());
    const j = await r.json();
    JWT = j.token;
    sessionStorage.setItem('vt_jwt', JWT);
    document.getElementById('login-card').classList.add('hidden');
    document.getElementById('app').classList.remove('hidden');
    boot();
  } catch (e) {
    document.getElementById('login-msg').innerHTML = '<span class="failure">Login failed: ' + e.message + '</span>';
  }
}

function doLogout() {
  JWT = '';
  sessionStorage.removeItem('vt_jwt');
  document.getElementById('app').classList.add('hidden');
  document.getElementById('login-card').classList.remove('hidden');
}

function boot() { loadStatus(); loadProtocols(); loadJobs(); setInterval(loadStatus, 5000); setInterval(loadJobs, 8000); }

async function loadStatus() {
  try {
    const s = await apiFetch('/status');
    document.getElementById('stat-version').textContent = s.version || '-';
    document.getElementById('stat-jobs').textContent = s.active_jobs;
  } catch (e) { console.error(e); }
}

async function loadProtocols() {
  try {
    const p = await apiFetch('/protocols');
    document.getElementById('stat-protocols').textContent = p.count || '-';
    const sel = document.getElementById('protocol');
    sel.innerHTML = '<option value="">Select...</option>';
    (p.protocols || []).forEach(proto => {
      const opt = document.createElement('option');
      opt.value = proto; opt.textContent = proto;
      sel.appendChild(opt);
    });
  } catch (e) { console.error(e); }
}

async function loadJobs() {
  try {
    const j = await apiFetch('/jobs');
    const jobs = j.jobs || [];
    document.getElementById('loading').classList.add('hidden');
    if (jobs.length === 0) {
      document.getElementById('jobs-table').classList.add('hidden');
      document.getElementById('no-jobs').classList.remove('hidden');
      return;
    }
    document.getElementById('jobs-table').classList.remove('hidden');
    document.getElementById('no-jobs').classList.add('hidden');
    const body = document.getElementById('jobs-body');
    body.innerHTML = '';
    jobs.forEach(job => {
      const tr = document.createElement('tr');
      tr.className = 'job-row';
      tr.onclick = () => showJob(job.id);
      const cls = job.status === 'completed' ? 'badge-success' : (job.status === 'running' || job.status === 'queued') ? 'badge-running' : 'badge-failure';
      tr.innerHTML =
        '<td style="font-family:monospace;font-size:11px">' + job.id.substring(0, 8) + '</td>' +
        '<td>' + job.target + ':' + job.port + '</td>' +
        '<td>' + job.protocol + '</td>' +
        '<td>' + Math.round((job.progress || 0) * 100) + '%<div class="bar"><div style="width:' + Math.round((job.progress || 0) * 100) + '%"></div></div></td>' +
        '<td>' + job.successes + '</td>' +
        '<td><span class="badge ' + cls + '">' + job.status + '</span></td>';
      body.appendChild(tr);
    });
  } catch (e) { console.error(e); }
}

async function startAttack() {
  const btn = document.getElementById('start-btn');
  btn.disabled = true;
  const data = {
    target: document.getElementById('target').value.trim(),
    port: parseInt(document.getElementById('port').value) || 0,
    protocol: document.getElementById('protocol').value,
    usernames: document.getElementById('usernames').value.split('\n').map(s => s.trim()).filter(Boolean),
    passwords: document.getElementById('passwords').value.split('\n').map(s => s.trim()).filter(Boolean),
    threads: parseInt(document.getElementById('threads').value) || 10,
    timeout_secs: parseInt(document.getElementById('timeout').value) || 10,
  };
  try {
    const r = await apiFetch('/jobs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
    showResult('Job queued: ' + r.job_id + ' - progress streams live below.', true);
    loadJobs();
    showJob(r.job_id);
  } catch (e) {
    showResult('Error: ' + e.message, false);
  }
  btn.disabled = false;
}

function showResult(msg, ok) {
  const div = document.getElementById('attack-result');
  div.textContent = msg;
  div.className = ok ? 'success' : 'error';
  div.classList.remove('hidden');
}

async function showJob(id) {
  CURRENT_JOB = id;
  document.getElementById('event-log').innerHTML = '';
  try {
    const j = await apiFetch('/jobs/' + id);
    document.getElementById('detail-title').textContent = 'Job: ' + j.id.substring(0, 8) + '... (' + j.status + ')';
    document.getElementById('job-detail').style.display = 'block';
    let html = '<p><strong>Target:</strong> ' + j.target + ':' + j.port + ' (' + j.protocol + ')</p>' +
      '<p><strong>Attempts:</strong> ' + j.attempts + ' · <strong>Found:</strong> <span class="success">' + j.successes + '</span> · <strong>Failures:</strong> ' + j.failures + ' · <strong>Errors:</strong> ' + j.errors + '</p>' +
      '<p><strong>By:</strong> ' + j.submitted_by + ' · <strong>Run:</strong> <span style="font-family:monospace;font-size:11px">' + (j.run_id || '-') + '</span></p>';
    if (j.successes > 0) {
      const r = await apiFetch('/jobs/' + id + '/results');
      html += '<h3>Findings (passwords masked)</h3><table><thead><tr><th>User</th><th>Status</th><th>Severity</th><th>Evidence</th></tr></thead><tbody>';
      (r.results || []).filter(x => x.success).forEach(res => {
        html += '<tr><td>' + res.username + '</td><td class="success">SUCCESS</td><td>' + res.severity + '</td><td>' + res.evidence + '</td></tr>';
      });
      html += '</tbody></table>';
    }
    document.getElementById('detail-content').innerHTML = html;
    subscribeEvents(id);
  } catch (e) {
    document.getElementById('detail-content').innerHTML = '<p class="error">Error: ' + e.message + '</p>';
  }
}

function subscribeEvents(id) {
  if (WS) { try { WS.close(); } catch (e) {} }
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  WS = new WebSocket(proto + '//' + location.host + '/api/v2/jobs/' + id + '/events?token=' + encodeURIComponent(JWT));
  WS.onmessage = (ev) => {
    try {
      const j = JSON.parse(ev.data);
      const log = document.getElementById('event-log');
      const div = document.createElement('div');
      div.textContent = '[' + (j.status || '?') + '] attempts=' + j.attempts + ' found=' + j.successes + ' ' + (j.msg || '');
      log.appendChild(div);
      log.scrollTop = log.scrollHeight;
      if (['completed', 'failed', 'stopped'].includes(j.status)) { loadJobs(); showJobSummary(id); }
    } catch (e) {}
  };
}

async function showJobSummary(id) {
  try {
    const j = await apiFetch('/jobs/' + id);
    document.getElementById('detail-title').textContent = 'Job: ' + j.id.substring(0, 8) + '... (' + j.status + ')';
  } catch (e) {}
}

function hideDetail() {
  document.getElementById('job-detail').style.display = 'none';
  CURRENT_JOB = null;
  if (WS) { try { WS.close(); } catch (e) {} }
}

async function stopCurrentJob() {
  if (!CURRENT_JOB || !confirm('Stop job ' + CURRENT_JOB.substring(0, 8) + '?')) return;
  try {
    await apiFetch('/jobs/' + CURRENT_JOB + '/stop', { method: 'POST' });
    loadJobs();
  } catch (e) { alert('Stop failed: ' + e.message); }
}

function downloadReport(fmt) {
  if (!CURRENT_JOB) return;
  window.open(API + '/jobs/' + CURRENT_JOB + '/report?format=' + fmt, '_blank');
}

async function loadAudit() {
  try {
    const a = await apiFetch('/audit?limit=50');
    let html = '<table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Job</th><th>Detail</th></tr></thead><tbody>';
    (a.audit || []).forEach(e => {
      html += '<tr><td style="font-size:11px">' + e.ts + '</td><td>' + e.actor + '</td><td>' + e.action + '</td><td style="font-family:monospace;font-size:11px">' + (e.job_id || '-').substring(0, 8) + '</td><td>' + e.detail + '</td>';
    });
    document.getElementById('audit-content').innerHTML = html + '</tbody></table>';
  } catch (e) { console.error(e); }
}
</script>
</body>
</html>
"###;
