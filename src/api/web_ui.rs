pub const WEB_UI_HTML: &str = r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Veltrix Web UI</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1923; color: #e0e0e0; }
  .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
  h1 { color: #00ff88; font-size: 24px; margin-bottom: 20px; border-bottom: 1px solid #1a2d3d; padding-bottom: 10px; }
  h2 { color: #00ff88; font-size: 18px; margin: 15px 0; }
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
  #loading { text-align: center; padding: 40px; color: #8899aa; }
  .hidden { display: none; }
  .flex { display: flex; gap: 10px; }
  .flex-grow { flex: 1; }
  .job-row { cursor: pointer; }
  .job-row:hover { background: #1a3344; }
  #job-detail { display: none; }
  .back-btn { background: #2a3d4d; color: #e0e0e0; margin-right: 10px; }
  .clear-btn { background: #442200; color: #ffaa00; }
  ::-webkit-scrollbar { width: 8px; }
  ::-webkit-scrollbar-track { background: #0f1923; }
  ::-webkit-scrollbar-thumb { background: #2a3d4d; border-radius: 4px; }
</style>
</head>
<body>
<div class="container">
  <h1>⚡ Veltrix Web UI</h1>

  <div class="grid" id="stats">
    <div class="stat"><div class="stat-value" id="stat-version">-</div><div class="stat-label">Version</div></div>
    <div class="stat"><div class="stat-value" id="stat-protocols">-</div><div class="stat-label">Protocols</div></div>
    <div class="stat"><div class="stat-value" id="stat-jobs">-</div><div class="stat-label">Active Jobs</div></div>
    <div class="stat"><div class="stat-value" id="stat-status" style="color:#00ff88">Running</div><div class="stat-label">Status</div></div>
  </div>

  <div class="card">
    <h2>New Attack</h2>
    <div class="flex">
      <div class="flex-grow">
        <label>Target</label>
        <input id="target" placeholder="e.g. 192.168.1.1 or example.com:22">
      </div>
      <div style="width:150px">
        <label>Port</label>
        <input id="port" placeholder="auto">
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
    <button id="start-btn" onclick="startAttack()">▶ Start Attack</button>
    <div id="attack-result" class="hidden" style="margin-top:10px;padding:10px;border-radius:4px;"></div>
  </div>

  <div class="card">
    <h2>Jobs</h2>
    <div style="text-align:right;margin-bottom:10px">
      <button class="clear-btn" onclick="clearJobs()">Clear All</button>
      <button onclick="loadJobs()">🔄 Refresh</button>
    </div>
    <div id="loading">Loading jobs...</div>
    <div id="jobs-table" class="hidden">
      <table>
        <thead><tr><th>ID</th><th>Target</th><th>Protocol</th><th>Progress</th><th>Results</th><th>Status</th></tr></thead>
        <tbody id="jobs-body"></tbody>
      </table>
    </div>
    <div id="no-jobs" class="hidden" style="text-align:center;padding:20px;color:#8899aa">No jobs yet. Start an attack above!</div>
  </div>

  <div class="card" id="job-detail">
    <h2 id="detail-title">Job Detail</h2>
    <button class="back-btn" onclick="hideDetail()">← Back</button>
    <div id="detail-content"></div>
  </div>
</div>

<script>
const API = '/api/v1';

async function apiGet(path) {
  const r = await fetch(API + path);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

async function apiPost(path, data) {
  const r = await fetch(API + path, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data) });
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

async function loadStatus() {
  try {
    const s = await apiGet('/status');
    document.getElementById('stat-version').textContent = s.version || '-';
    document.getElementById('stat-jobs').textContent = s.active_jobs;
  } catch(e) { console.error('Status:', e); }
}

async function loadProtocols() {
  try {
    const p = await apiGet('/protocols');
    document.getElementById('stat-protocols').textContent = p.count || '-';
    const sel = document.getElementById('protocol');
    sel.innerHTML = '<option value="">Select...</option>';
    (p.protocols || []).forEach(proto => {
      const opt = document.createElement('option');
      opt.value = proto; opt.textContent = proto;
      sel.appendChild(opt);
    });
  } catch(e) { console.error('Protocols:', e); }
}

async function loadJobs() {
  try {
    const j = await apiGet('/jobs');
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
      const statusClass = job.status === 'completed' ? 'badge-success' : job.status === 'running' ? 'badge-running' : 'badge-failure';
      tr.innerHTML = `
        <td style="font-family:monospace;font-size:11px">${job.id.substring(0,8)}</td>
        <td>${job.target}:${job.port}</td>
        <td>${job.protocol}</td>
        <td>${Math.round(job.progress)}%</td>
        <td>${job.results_count}</td>
        <td><span class="badge ${statusClass}">${job.status}</span></td>
      `;
      body.appendChild(tr);
    });
  } catch(e) { console.error('Jobs:', e); }
}

async function startAttack() {
  const btn = document.getElementById('start-btn');
  btn.disabled = true;
  btn.textContent = '⏳ Running...';
  document.getElementById('attack-result').classList.add('hidden');

  const data = {
    target: document.getElementById('target').value.trim(),
    port: parseInt(document.getElementById('port').value) || 0,
    protocol: document.getElementById('protocol').value,
    usernames: document.getElementById('usernames').value.split('\n').filter(s => s.trim()),
    passwords: document.getElementById('passwords').value.split('\n').filter(s => s.trim()),
  };

  if (!data.target || !data.protocol || data.usernames.length === 0 || data.passwords.length === 0) {
    showResult('Fill in target, protocol, usernames, and passwords.', 'error');
    btn.disabled = false; btn.textContent = '▶ Start Attack';
    return;
  }

  try {
    const r = await apiPost('/attack', data);
    showResult(`Attack complete! ${r.successes} successes, ${r.failures} failures out of ${r.total_attempts} attempts. Job ID: ${r.job_id}`, 'success');
    loadJobs();
  } catch(e) {
    showResult('Error: ' + e.message, 'error');
  }
  btn.disabled = false;
  btn.textContent = '▶ Start Attack';
}

function showResult(msg, type) {
  const div = document.getElementById('attack-result');
  div.textContent = msg;
  div.className = type === 'success' ? 'success' : 'error';
  div.classList.remove('hidden');
}

async function showJob(id) {
  try {
    const j = await apiGet('/jobs/' + id);
    document.getElementById('detail-title').textContent = 'Job: ' + j.id.substring(0,8) + '...';
    document.getElementById('job-detail').style.display = 'block';

    let html = `
      <p><strong>Target:</strong> ${j.target}:${j.port}</p>
      <p><strong>Protocol:</strong> ${j.protocol}</p>
      <p><strong>Status:</strong> ${j.status}</p>
      <p><strong>Progress:</strong> ${Math.round(j.progress)}%</p>
      <p><strong>Total Results:</strong> ${j.results_count}</p>
    `;

    if (j.results_count > 0) {
      const r = await apiGet('/jobs/' + id + '/results');
      if (r.results && r.results.length > 0) {
        html += '<h3>Results</h3><table><thead><tr><th>User</th><th>Status</th><th>Duration</th><th>Error</th></tr></thead><tbody>';
        r.results.forEach(res => {
          const cls = res.success ? 'success' : 'failure';
          const statusText = res.success ? 'SUCCESS' : 'FAILED';
          html += `<tr><td>${res.username}</td><td class="${cls}">${statusText}</td><td>${res.duration_ms}ms</td><td>${res.error || '-'}</td></tr>`;
        });
        html += '</tbody></table>';
      }
    }
    document.getElementById('detail-content').innerHTML = html;
  } catch(e) {
    document.getElementById('detail-content').innerHTML = '<p class="error">Error: ' + e.message + '</p>';
  }
}

function hideDetail() {
  document.getElementById('job-detail').style.display = 'none';
}

async function clearJobs() {
  if (!confirm('Clear all jobs from view?')) return;
  document.getElementById('jobs-body').innerHTML = '';
  document.getElementById('no-jobs').classList.remove('hidden');
  document.getElementById('jobs-table').classList.add('hidden');
}

loadStatus();
loadProtocols();
loadJobs();
setInterval(loadStatus, 5000);
setInterval(loadJobs, 10000);
</script>
</body>
</html>
"###;
