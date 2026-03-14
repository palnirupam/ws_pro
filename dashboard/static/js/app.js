/* ── State ─────────────────────────────────────────────────── */
const socket = io({ reconnection: true });
let findings = [];
let interceptorMsgs = [];
const seenKeys = new Set();
let currentSort = 'time'; // time | severity | endpoint
let currentFilter = 'all'; // all | CRITICAL | HIGH | MEDIUM | LOW

/* ── Export Dropdown Toggle ────────────────────────────────── */
function toggleExportMenu(e) {
  e.stopPropagation();
  const dd = document.getElementById('exportDropdown');
  dd.classList.toggle('open');
}
function closeExportMenu() {
  document.getElementById('exportDropdown').classList.remove('open');
}
document.addEventListener('click', (e) => {
  const menu = document.querySelector('.export-menu');
  if (menu && !menu.contains(e.target)) closeExportMenu();
});

/* ── Socket Events ─────────────────────────────────────────── */
socket.on('connect', () => {
  addLog('✅ Connected to WS Tester Pro', 'success');
  initApiKey();
});
socket.on('disconnect', () => addLog('❌ Disconnected', 'error'));
socket.on('log',        d => addLog(d.message, d.level || 'info'));
socket.on('finding',    d => addFinding(d));
socket.on('progress',   d => setProgress(d.percent, d.text));
socket.on('status',     d => setStatus(d.status));

socket.on('ai_analysis', d => {
  const el = document.getElementById('ai-output');
  el.style.opacity = '0';
  setTimeout(() => {
    el.textContent = d.analysis || '';
    el.style.transition = 'opacity .4s';
    el.style.opacity = '1';
  }, 60);
});

socket.on('interceptor_message', d => addInterceptorMsg(d));

socket.on('scan_complete', () => {
  setStatus('complete');
  setProgress(100, `✅ Complete — ${findings.length} findings`);
  addLog(`✅ Done! ${findings.length} vulnerabilities found.`, 'success');
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('stopBtn').disabled = true;
  document.getElementById('pauseBtn').disabled = true;
  document.getElementById('progressBar').classList.remove('active');
  updateBountyList();

  // Browser notification
  if ('Notification' in window && Notification.permission === 'granted') {
    new Notification('WS Tester Pro — Scan Complete', {
      body: `${findings.length} vulnerabilities found`,
      icon: '🔐',
    });
  }
  // Sound alert
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain); gain.connect(ctx.destination);
    osc.frequency.value = 800; gain.gain.value = 0.1;
    osc.start(); osc.stop(ctx.currentTime + 0.15);
    setTimeout(() => { osc.frequency.value = 1000; const o2 = ctx.createOscillator(); const g2 = ctx.createGain(); o2.connect(g2); g2.connect(ctx.destination); o2.frequency.value = 1000; g2.gain.value = 0.1; o2.start(); o2.stop(ctx.currentTime + 0.15); }, 200);
  } catch(e) {}
});

socket.on('scan_notification', d => {
  if ('Notification' in window && Notification.permission === 'granted') {
    new Notification(d.title || 'WS Tester Pro', { body: d.body || '' });
  }
});

socket.on('report_ready', d => {
  addLog('✅ Report generated — downloading PDF...', 'success');
  window.location.href = '/download-pdf';
});

socket.on('session_saved', d => {
  addLog(`💾 Session #${d.id} saved (${d.total} findings)`, 'success');
});

socket.on('session_loaded', d => {
  findings = d.findings || [];
  seenKeys.clear();
  findings.forEach(f => seenKeys.add((f.title||'') + '|' + (f.endpoint||'')));
  rebuildFindingsUI();
  updateStats();
  updateBountyList();
  addLog(`📂 Loaded session with ${findings.length} findings`, 'success');
});

socket.on('history_list', list => {
  const el = document.getElementById('historyList');
  if (!list.length) { el.innerHTML = '<p style="color:var(--text3);font-size:.78rem">No saved sessions</p>'; return; }
  el.innerHTML = list.map(s => `
    <div class="history-item" onclick="socket.emit('load_session',{id:${s.id}})">
      <span class="history-target">${s.target}</span>
      <span class="history-meta">#${s.id} · ${s.total} findings · ${new Date(s.timestamp).toLocaleString()}</span>
    </div>
  `).join('');
});

socket.on('comparison_result', d => {
  const el = document.getElementById('comparisonResult');
  el.style.display = 'block';
  el.innerHTML = `
    <h4>📊 Comparison: #${d.session_a.id} vs #${d.session_b.id}</h4>
    <div class="compare-grid">
      <div class="compare-stat new"><h3>${d.new_count}</h3><p>New in #${d.session_b.id}</p></div>
      <div class="compare-stat fixed"><h3>${d.fixed_count}</h3><p>Fixed since #${d.session_a.id}</p></div>
      <div class="compare-stat common"><h3>${d.common.length}</h3><p>Common</p></div>
    </div>
  `;
});

/* ── Notification Permission ───────────────────────────────── */
if ('Notification' in window && Notification.permission === 'default') {
  Notification.requestPermission();
}

/* ── API Key ────────────────────────────────────────────────── */
function initApiKey() {
  socket.emit('check_api_key');
}
socket.on('api_key_status', d => {
  const st  = document.getElementById('apiKeyStatus');
  const inp = document.getElementById('apiKeyInput');
  if (d.valid) {
    st.textContent = '✅ ' + (d.message || 'Key active');
    st.style.color = 'var(--green)';
    if (d.masked_key && !inp.value) {
      inp.value    = d.masked_key;
      inp.disabled = true;
      inp.style.color = 'var(--green)';
    }
  } else {
    st.textContent = '⚠️ ' + (d.message || 'No key');
    st.style.color = 'var(--yellow)';
    inp.disabled = false;
    sessionStorage.removeItem('ws_api_key');
  }
});

function toggleKeyVis() {
  const i = document.getElementById('apiKeyInput');
  i.type = i.type === 'password' ? 'text' : 'password';
}

function saveApiKey() {
  const key = document.getElementById('apiKeyInput').value.trim();
  const st  = document.getElementById('apiKeyStatus');
  if (!key) { st.textContent = '⚠️ Enter a key'; st.style.color = 'var(--yellow)'; return; }
  if (!key.startsWith('sk-')) { st.textContent = '❌ Must start with sk-'; st.style.color = 'var(--red)'; return; }
  sessionStorage.setItem('ws_api_key', key);
  socket.emit('set_api_key', { key });
  st.textContent = '⏳ Verifying...';
  st.style.color = 'var(--text2)';
}

/* ── Theme Toggle ──────────────────────────────────────────── */
function toggleTheme() {
  const body = document.body;
  const isLight = body.classList.toggle('light-theme');
  localStorage.setItem('ws_theme', isLight ? 'light' : 'dark');
  const btn = document.getElementById('themeBtn');
  btn.textContent = isLight ? '🌙' : '☀️';
}
// Load saved theme
(function() {
  const saved = localStorage.getItem('ws_theme');
  if (saved === 'light') {
    document.body.classList.add('light-theme');
    setTimeout(() => {
      const btn = document.getElementById('themeBtn');
      if (btn) btn.textContent = '🌙';
    }, 0);
  }
})();

/* ── Interceptor toggle ─────────────────────────────────────── */
document.getElementById('optIntercept').addEventListener('change', e => {
  document.getElementById('interceptorCard').style.display = e.target.checked ? 'block' : 'none';
});

/* ── Tabs ───────────────────────────────────────────────────── */
function showTab(name, btn) {
  document.querySelectorAll('.tab-pane').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('pane-' + name).classList.add('active');
  if (btn) btn.classList.add('active');
}

/* ── Status & Progress ──────────────────────────────────────── */
function setStatus(s) {
  document.getElementById('statusDot').className = 'sdot ' + s;
  document.getElementById('statusText').textContent =
    { idle: 'Idle', running: 'Scanning...', complete: 'Complete', paused: 'Paused' }[s] || s;
}

function setProgress(pct, txt) {
  const bar = document.getElementById('progressBar');
  bar.style.width = pct + '%';
  pct > 0 && pct < 100 ? bar.classList.add('active') : bar.classList.remove('active');
  document.getElementById('progressText').textContent = txt || '';
}

/* ── Scan ───────────────────────────────────────────────────── */
function startScan(resume = false) {
  const urlInput = document.getElementById('targetUrl');
  const url = urlInput.value.trim();
  if (!url) { 
    urlInput.style.borderColor = 'var(--red)';
    urlInput.classList.add('shake');
    setTimeout(() => { urlInput.classList.remove('shake'); }, 400);
    return; 
  }
  urlInput.style.borderColor = '';

  if (!resume) {
    findings = [];
    seenKeys.clear();
    resetFindingsUI();
    document.getElementById('log').innerHTML = '';
    document.getElementById('ai-output').textContent = 'AI analysis will appear here after scan completes...';
    updateStats();
  }

  setProgress(0, 'Starting...');
  setStatus('running');
  document.getElementById('scanBtn').disabled = true;
  document.getElementById('stopBtn').disabled = false;
  document.getElementById('pauseBtn').disabled = false;

  socket.emit('start_scan', {
    url,
    resume,
    options: {
      ai:               document.getElementById('optAI').checked,
      playwright:       document.getElementById('optPlaywright').checked,
      jwt:              document.getElementById('optJWT').checked,
      timing:           document.getElementById('optTiming').checked,
      fuzzing:          document.getElementById('optFuzzer').checked,
      fast_mode:        document.getElementById('optFastMode').checked,
      concurrent_count: parseInt(document.getElementById('concurrentCount').value),
      intercept:        document.getElementById('optIntercept').checked,
      intercept_url:    document.getElementById('interceptWsUrl').value,
      intercept_port:   parseInt(document.getElementById('interceptPort').value) || 8765,
    }
  });
  addLog('🚀 Scan started: ' + url, 'info');
}

function stopScan() {
  socket.emit('stop_scan');
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('stopBtn').disabled = true;
  document.getElementById('pauseBtn').disabled = true;
  setStatus('idle');
  setProgress(0, 'Stopped');
  addLog('⏹ Scan stopped.', 'warning');
}

function pauseScan() {
  socket.emit('pause_scan');
  const btn = document.getElementById('pauseBtn');
  const isPaused = btn.textContent.includes('Resume');
  btn.textContent = isPaused ? '⏸ Pause' : '▶ Resume';
}

function resumeScan() {
  startScan(true);
}

function clearAll() {
  findings = [];
  seenKeys.clear();
  resetFindingsUI();
  document.getElementById('log').innerHTML = '';
  clearInterceptorUI();
  document.getElementById('ai-output').textContent = 'AI analysis will appear here after scan completes...';
  setProgress(0, 'Ready');
  updateStats();
}

/* ── Findings ───────────────────────────────────────────────── */
function addFinding(data) {
  const key = (data.title || data.test || '') + '|' + (data.endpoint || '');
  if (seenKeys.has(key)) return;
  seenKeys.add(key);
  data._ts = Date.now(); // For sorting
  findings.push(data);
  renderFindingCard(data);
  updateStats();
}

function renderFindingCard(data) {
  // Check filter
  if (currentFilter !== 'all' && data.severity !== currentFilter) return;

  const box   = document.getElementById('findingsBox');
  const empty = box.querySelector('.empty-state');
  if (empty) empty.remove();

  const sev  = data.severity || 'LOW';
  const card = document.createElement('div');
  card.className = 'finding ' + sev;
  card.setAttribute('data-severity', sev);
  card.setAttribute('data-endpoint', data.endpoint || '');
  card.setAttribute('data-ts', data._ts || 0);

  // Header
  const hdr   = document.createElement('div'); hdr.className = 'f-hdr';
  const badge = document.createElement('span'); badge.className = 'badge ' + sev; badge.textContent = sev;
  const title = document.createElement('span'); title.className = 'f-title'; title.textContent = data.title || data.test || '';
  const ts    = document.createElement('span'); ts.className = 'f-time';  ts.textContent = data.timestamp || data.time || '';
  hdr.append(badge, title, ts);

  // Endpoint
  const ep = document.createElement('div'); ep.className = 'f-ep';
  ep.textContent = '📡 ' + (data.endpoint || '');
  ep.title = data.endpoint || '';

  // Detail
  const det = document.createElement('div'); det.className = 'f-detail';
  det.textContent = data.description || data.detail || '';

  card.append(hdr, ep, det);

  // CVSS
  const cvssScore = data.cvss_score || (data.cvss && data.cvss.score);
  const cvssVec   = data.cvss_vector || (data.cvss && data.cvss.vector) || '';
  if (cvssScore) {
    const cv = document.createElement('div'); cv.className = 'f-cvss';
    cv.textContent = `CVSS ${cvssScore}  ·  ${cvssVec}`;
    card.appendChild(cv);
  }

  // Remediation
  const rem = data.remediation;
  if (rem) {
    const r = document.createElement('div'); r.className = 'f-rem';
    const b = document.createElement('b'); b.textContent = '🔧 Fix: ';
    r.append(b, document.createTextNode(rem));
    card.appendChild(r);
  }

  // Evidence
  const ev = data.evidence || {};
  const evKeys = Object.keys(ev).filter(k => ev[k]);
  if (evKeys.length) {
    const btn  = document.createElement('div'); btn.className = 'f-ev-btn';
    btn.textContent = '📎 View Evidence';
    const body = document.createElement('div'); body.className = 'f-ev-body';
    body.textContent = JSON.stringify(ev, null, 2);
    btn.onclick = () => {
      const open = body.style.display === 'block';
      body.style.display = open ? 'none' : 'block';
      btn.textContent = open ? '📎 View Evidence' : '📎 Hide Evidence';
    };
    card.append(btn, body);
  }

  box.prepend(card);
}

function rebuildFindingsUI() {
  resetFindingsUI();
  let sorted = [...findings];

  // Sort
  if (currentSort === 'severity') {
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    sorted.sort((a, b) => (order[a.severity] || 4) - (order[b.severity] || 4));
  } else if (currentSort === 'endpoint') {
    sorted.sort((a, b) => (a.endpoint || '').localeCompare(b.endpoint || ''));
  }
  // time sort = reverse chronological (default order)

  sorted.forEach(f => renderFindingCard(f));
}

function sortFindings(by) {
  currentSort = by;
  // Highlight active sort button
  document.querySelectorAll('.sort-btn').forEach(b => b.classList.remove('active'));
  const btn = document.querySelector(`.sort-btn[data-sort="${by}"]`);
  if (btn) btn.classList.add('active');
  rebuildFindingsUI();
}

function filterFindings(sev) {
  currentFilter = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  const btn = document.querySelector(`.filter-btn[data-filter="${sev}"]`);
  if (btn) btn.classList.add('active');
  rebuildFindingsUI();
}

function resetFindingsUI() {
  document.getElementById('findingsBox').innerHTML =
    '<div class="empty-state"><div class="icon">🔍</div><p>Start a scan to see findings here</p></div>';
}

function updateStats() {
  const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach(f => { if (c[f.severity] !== undefined) c[f.severity]++; });

  [['sCrit','CRITICAL'], ['sHigh','HIGH'], ['sMed','MEDIUM'], ['sLow','LOW']].forEach(([id, sev]) => {
    const el = document.getElementById(id);
    el.textContent = c[sev];
    el.classList.remove('stat-bump');
    void el.offsetWidth;
    el.classList.add('stat-bump');
  });
  const tot = document.getElementById('sTotal');
  tot.textContent = findings.length;
  tot.classList.remove('stat-bump');
  void tot.offsetWidth;
  tot.classList.add('stat-bump');
}

/* ── Log ────────────────────────────────────────────────────── */
function addLog(msg, level) {
  const log = document.getElementById('log');
  const d   = document.createElement('div');
  d.className = 'log-ln ' + (level || 'info');
  const ts = document.createElement('span'); ts.className = 'log-ts';
  ts.textContent = new Date().toLocaleTimeString();
  d.append(ts, document.createTextNode(msg || ''));
  log.appendChild(d);
  log.scrollTop = log.scrollHeight;
}

/* ── Interceptor ────────────────────────────────────────────── */
function startInterceptor() {
  const wsUrl = document.getElementById('interceptWsUrl').value.trim();
  const port  = parseInt(document.getElementById('interceptPort').value) || 8765;
  if (!wsUrl) { alert('Enter WS URL'); return; }
  socket.emit('start_interceptor', { ws_url: wsUrl, port });
  addLog('🕵️ Interceptor started on port ' + port, 'info');
}

function addInterceptorMsg(data) {
  interceptorMsgs.push(data);
  const log   = document.getElementById('interceptorLog');
  const empty = log.querySelector('.empty-state');
  if (empty) empty.remove();

  const row = document.createElement('div');
  row.className = 'msg-row' + (data.flagged ? ' flagged' : '');
  row.setAttribute('data-dir', (data.direction || '').includes('CLIENT') ? 'client' : 'server');

  const t   = document.createElement('span'); t.className = 'msg-time';    t.textContent = data.time || '';
  const dir = document.createElement('span'); dir.className = 'msg-dir ' + (data.direction === 'CLIENT→SERVER' ? 'c' : 's');
  dir.textContent = data.direction || '';
  const msg = document.createElement('span'); msg.className = 'msg-content';

  const msgText = (data.message || '').slice(0, 300);
  try {
    JSON.parse(msgText);
    msg.classList.add('json-msg');
  } catch(e) {}
  msg.textContent = msgText;

  row.append(t, dir, msg);
  if (data.flagged) {
    const f = document.createElement('span'); f.className = 'flag-tag';
    f.textContent = '⚠️ FLAGGED';
    if (data.flags && data.flags.length) {
      f.title = data.flags.join(', ');
    }
    row.appendChild(f);
  }
  log.appendChild(row);
  log.scrollTop = log.scrollHeight;
  document.getElementById('msgCount').textContent  = interceptorMsgs.length;
  document.getElementById('flagCount').textContent = interceptorMsgs.filter(m => m.flagged).length;
}

function clearInterceptorUI() {
  interceptorMsgs = [];
  socket.emit('clear_interceptor');
  document.getElementById('interceptorLog').innerHTML =
    '<div class="empty-state"><div class="icon">🕵️</div><p>Enable interceptor and start proxy</p></div>';
  document.getElementById('msgCount').textContent  = 0;
  document.getElementById('flagCount').textContent = 0;
}

/* ── AI ─────────────────────────────────────────────────────── */
function rerunAI() {
  socket.emit('request_ai_analysis', { findings });
  document.getElementById('ai-output').textContent = '⏳ Analyzing findings...';
  showTab('ai', document.querySelectorAll('.tab')[4]);
}

/* ── Bug Bounty ────────────────────────────────────────────── */
function updateBountyList() {
  const list = document.getElementById('bountyList');
  if (!findings.length) {
    list.innerHTML = '<div class="empty-state"><div class="icon">🎯</div><p>Run a scan first — findings will appear here</p></div>';
    return;
  }
  list.innerHTML = '';
  findings.forEach((f, i) => {
    const card = document.createElement('div');
    card.className = 'bounty-card ' + (f.severity || 'LOW');
    card.innerHTML = `
      <div class="bounty-row">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="bounty-title">${f.title || f.test || ''}</span>
        <button class="bounty-copy-btn" onclick="copyBountyReport(${i})">📋 Copy</button>
      </div>
      <div class="bounty-ep">${f.endpoint || ''}</div>
    `;
    list.appendChild(card);
  });
}

function generateBountyMarkdown(f) {
  const target = document.getElementById('targetUrl').value || 'Unknown';
  const cvss = f.cvss_score || (f.cvss && f.cvss.score) || 'N/A';
  const vec = f.cvss_vector || (f.cvss && f.cvss.vector) || '';
  const ev = f.evidence || {};
  let md = `## ${f.title || f.test || 'Vulnerability'}\n\n`;
  md += `**Severity:** ${f.severity}  \n`;
  md += `**CVSS Score:** ${cvss}  \n`;
  if (vec) md += `**CVSS Vector:** \`${vec}\`  \n`;
  md += `**Target:** ${target}  \n`;
  md += `**Endpoint:** \`${f.endpoint || ''}\`  \n\n`;
  md += `### Description\n${f.description || f.detail || ''}\n\n`;
  md += `### Steps to Reproduce\n`;
  md += `1. Open a WebSocket connection to \`${f.endpoint || target}\`\n`;
  if (ev.payload) md += `2. Send payload: \`${ev.payload}\`\n`;
  if (ev.reproduce) md += `${ev.reproduce}\n`;
  md += `\n### Impact\n`;
  md += f.severity === 'CRITICAL' ? 'This vulnerability allows an attacker to execute arbitrary commands on the server, leading to full system compromise.\n' :
        f.severity === 'HIGH' ? 'This vulnerability can lead to unauthorized access to sensitive data or functionalities.\n' :
        f.severity === 'MEDIUM' ? 'This vulnerability could be exploited to gather sensitive information or perform limited unauthorized actions.\n' :
        'This is a low-severity issue that may provide minor information to attackers.\n';
  md += `\n### Remediation\n${f.remediation || 'Apply appropriate input validation and security controls.'}\n`;
  if (Object.keys(ev).length) {
    md += `\n### Evidence\n\`\`\`json\n${JSON.stringify(ev, null, 2)}\n\`\`\`\n`;
  }
  return md;
}

function copyBountyReport(idx) {
  const f = findings[idx];
  if (!f) return;
  const md = generateBountyMarkdown(f);
  navigator.clipboard.writeText(md).then(() => {
    addLog(`📋 Copied bounty report for: ${f.title || f.test}`, 'success');
    const btns = document.querySelectorAll('.bounty-copy-btn');
    if (btns[idx]) {
      btns[idx].textContent = '✅ Copied!';
      setTimeout(() => btns[idx].textContent = '📋 Copy', 1500);
    }
  });
}

function copyAllBounty() {
  if (!findings.length) { addLog('⚠️ No findings to copy', 'warning'); return; }
  const target = document.getElementById('targetUrl').value || 'Unknown';
  let md = `# WebSocket Security Report — ${target}\n\n`;
  md += `**Date:** ${new Date().toLocaleDateString()}\n`;
  md += `**Total Findings:** ${findings.length}\n\n---\n\n`;
  findings.forEach(f => md += generateBountyMarkdown(f) + '\n---\n\n');
  navigator.clipboard.writeText(md).then(() => {
    addLog('📋 All findings copied as bounty report!', 'success');
  });
}

/* ── Interceptor Advanced ──────────────────────────────────── */
function filterInterceptor() {
  const q = (document.getElementById('interceptSearch').value || '').toLowerCase();
  const dir = document.getElementById('interceptDirFilter').value;
  document.querySelectorAll('#interceptorLog .msg-row').forEach(row => {
    const content = row.textContent.toLowerCase();
    const rowDir = row.getAttribute('data-dir') || '';
    const dirMatch = dir === 'all' || rowDir === dir;
    row.style.display = (content.includes(q) && dirMatch) ? '' : 'none';
  });
}

function exportMessages() {
  if (!interceptorMsgs.length) { addLog('⚠️ No messages to export', 'warning'); return; }
  const blob = new Blob([JSON.stringify(interceptorMsgs, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `ws_interceptor_${Date.now()}.json`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  addLog(`💾 Exported ${interceptorMsgs.length} messages`, 'success');
}

/* ── Report Downloads ──────────────────────────────────────── */
function downloadReport() {
  const target  = document.getElementById('targetUrl').value || 'Unknown';
  const aiText  = document.getElementById('ai-output').textContent;
  const ai      = (aiText.startsWith('AI analysis') || aiText.startsWith('⏳')) ? '' : aiText;
  addLog('📄 Generating report...', 'info');
  socket.emit('generate_report', { findings, target, ai_analysis: ai });
}

function downloadHTML() {
  if (!findings.length) { addLog('⚠️ No findings to export. Run a scan first.', 'warning'); return; }
  addLog('📄 Downloading HTML report...', 'info');
  
  const target  = document.getElementById('targetUrl').value || 'Unknown';
  const aiText  = document.getElementById('ai-output').textContent;
  const ai      = (aiText.startsWith('AI analysis') || aiText.startsWith('⏳')) ? '' : aiText;

  fetch('/download-html', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ findings, target, ai_analysis: ai })
  })
  .then(res => res.blob())
  .then(blob => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `ws_security_report_${Date.now()}.html`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
  });
}

function downloadSARIF() {
  if (!findings.length) { addLog('⚠️ No findings to export. Run a scan first.', 'warning'); return; }
  addLog('📄 Downloading SARIF report...', 'info');
  
  const target  = document.getElementById('targetUrl').value || 'Unknown';

  fetch('/download-sarif', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ findings, target })
  })
  .then(res => res.blob())
  .then(blob => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `ws_security_report_${Date.now()}.sarif`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
  });
}

function downloadJSON() {
  window.location.href = '/download-json';
  addLog('📄 Downloading JSON export...', 'info');
}

function exportFindings() {
  if (!findings.length) { addLog('⚠️ No findings to export', 'warning'); return; }
  const data = { tool: 'WS Tester Pro', timestamp: new Date().toISOString(), findings };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `ws_findings_${Date.now()}.json`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  addLog(`💾 Exported ${findings.length} findings`, 'success');
}

function importFindings() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.onchange = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        const data = JSON.parse(ev.target.result);
        const fList = data.findings || data;
        socket.emit('import_findings', { findings: Array.isArray(fList) ? fList : [] });
      } catch(err) {
        addLog('❌ Invalid JSON file', 'error');
      }
    };
    reader.readAsText(file);
  };
  input.click();
}

/* ── Session History ───────────────────────────────────────── */
function saveSession() {
  const target = document.getElementById('targetUrl').value || 'Unknown';
  socket.emit('save_session', { target });
}

function loadHistory() {
  socket.emit('get_history');
  showTab('history', document.querySelectorAll('.tab')[5]);
}

function compareSessions() {
  const a = parseInt(document.getElementById('compareA').value);
  const b = parseInt(document.getElementById('compareB').value);
  if (isNaN(a) || isNaN(b)) { addLog('⚠️ Enter valid session IDs', 'warning'); return; }
  socket.emit('compare_sessions', { session_a: a, session_b: b });
}

/* ── Keyboard Shortcuts ────────────────────────────────────── */
document.addEventListener('keydown', (e) => {
  // Ctrl+Enter → Start scan
  if (e.ctrlKey && e.key === 'Enter') {
    e.preventDefault();
    if (!document.getElementById('scanBtn').disabled) startScan();
  }
  // Escape → Stop scan
  if (e.key === 'Escape') {
    if (!document.getElementById('stopBtn').disabled) stopScan();
  }
  // Ctrl+Shift+T → Toggle theme
  if (e.ctrlKey && e.shiftKey && e.key === 'T') {
    e.preventDefault();
    toggleTheme();
  }
  // Ctrl+Shift+S → Save session
  if (e.ctrlKey && e.shiftKey && e.key === 'S') {
    e.preventDefault();
    saveSession();
  }
  // Ctrl+Shift+E → Export JSON
  if (e.ctrlKey && e.shiftKey && e.key === 'E') {
    e.preventDefault();
    exportFindings();
  }
  // Tab shortcuts: 1-6
  if (e.altKey && e.key >= '1' && e.key <= '6') {
    e.preventDefault();
    const tabs = ['findings', 'bounty', 'log', 'interceptor', 'ai', 'history'];
    const idx = parseInt(e.key) - 1;
    if (idx < tabs.length) {
      showTab(tabs[idx], document.querySelectorAll('.tab')[idx]);
    }
  }
});
