/* ── State ─────────────────────────────────────────────────── */
const socket = io({ reconnection: true });
let findings = [];
let proxyMsgs = [];
let heldMsgs = new Map(); // id -> last message payload
const seenKeys = new Set();
let currentSort = 'time'; // time | severity | endpoint
let currentFilter = 'all'; // all | CRITICAL | HIGH | MEDIUM | LOW

// Background WebSocket connection to the proxy so "Replay" works even
// when the user doesn't keep an external client connected.
let replayWs = null;
let replayWsPort = null;
function ensureReplayWs(port) {
  const p = parseInt(port) || 8080;
  if (replayWs && replayWs.readyState === WebSocket.OPEN && replayWsPort === p) return;
  try { if (replayWs) replayWs.close(); } catch(e) {}
  replayWs = null;
  replayWsPort = p;
  try {
    const url = `ws://localhost:${p}`;
    replayWs = new WebSocket(url);
    replayWs.onopen = () => addLog(`🧷 Replay channel connected: ${url}`, 'info');
    replayWs.onclose = () => { replayWs = null; addLog('🧷 Replay channel disconnected', 'warning'); };
    replayWs.onerror = () => { /* ignore */ };
    replayWs.onmessage = () => { /* ignore */ };
  } catch(e) {
    replayWs = null;
  }
}

function closeReplayWs() {
  try { if (replayWs) replayWs.close(); } catch(e) {}
  replayWs = null;
  replayWsPort = null;
}

// Report JS errors to server (helps debug "UI not updating").
window.addEventListener('error', (e) => {
  try {
    socket.emit('client_error', {
      message: e?.message || 'error',
      source:  (e?.filename || '') + ':' + (e?.lineno || '') + ':' + (e?.colno || ''),
      stack:   e?.error?.stack || '',
    });
  } catch(err) {}
});
window.addEventListener('unhandledrejection', (e) => {
  try {
    const r = e?.reason;
    socket.emit('client_error', {
      message: 'unhandledrejection: ' + (r?.message || String(r)),
      source:  'promise',
      stack:   r?.stack || '',
    });
  } catch(err) {}
});

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
  socket.emit('get_proxy_status', {});
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

socket.on('proxy_status', d => {
  updateProxyStatus(d);
  const local = `ws://localhost:${d.port || ''}`;
  if (d.running) addLog(`🧲 Proxy running on ${local}`, 'success');
  else if ((d.error || '') === 'starting') addLog('🧲 Proxy starting...', 'info');
  else addLog(`🧲 Proxy stopped${d.error ? ` (${d.error})` : ''}`, d.error ? 'error' : 'info');
});
socket.on('proxy_message', d => addProxyMsg(d));
socket.on('proxy_reset', d => {
  // Clear only proxy UI state (do not touch scan).
  proxyMsgs = [];
  heldMsgs = new Map();
  const feed = document.getElementById('proxyFeed');
  if (feed) {
    feed.innerHTML = '<div class="empty-state"><div class="icon">🧲</div><p>Proxy reset — waiting for new traffic</p></div>';
  }
  const list = document.getElementById('heldList');
  if (list) list.innerHTML = '';
  const wrap = document.getElementById('heldWrap');
  if (wrap) wrap.style.display = 'none';
  ['pTotal','pC2S','pS2C','pFlagged','pHeld'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '0';
  });
  addLog(`🧹 Proxy UI reset${d && d.reason ? ` (${d.reason})` : ''}`, 'info');
});
function resolveHeldUI(id, action) {
  if (!id) return;
  const m = proxyMsgs.find(x => x.id === id);
  if (m) m.held = false;
  heldMsgs.delete(id);

  // Update stats
  const held = heldMsgs.size;
  const total = proxyMsgs.length;
  const c2s = proxyMsgs.filter(x => x.direction === 'CLIENT→SERVER').length;
  const s2c = proxyMsgs.filter(x => x.direction === 'SERVER→CLIENT').length;
  const flagged = proxyMsgs.filter(x => x.flagged).length;
  document.getElementById('pTotal').textContent = total;
  document.getElementById('pC2S').textContent = c2s;
  document.getElementById('pS2C').textContent = s2c;
  document.getElementById('pFlagged').textContent = flagged;
  document.getElementById('pHeld').textContent = held;

  // Remove HELD badge styling on the feed row if present
  const row = document.querySelector(`#proxyFeed .p-msg-row[data-id="${id}"]`);
  if (row) row.classList.remove('held');
  const hb = row ? row.querySelector('.held-badge') : null;
  if (hb) hb.remove();

  renderHeldList();
  addLog(`✅ Held message ${action || 'resolved'}: ${id.slice(0, 8)}…`, 'success');
}

socket.on('proxy_held_resolved', d => {
  resolveHeldUI(d && d.id, d && d.action);
});

socket.on('proxy_action_result', d => {
  if (!d) return;
  const id = (d.id || '').toString();
  if (d.ok) {
    addLog(`✅ ${d.action} OK ${id ? '(' + id.slice(0, 8) + '…)' : ''}`, 'success');
    // Fallback: if proxy_held_resolved was missed, still update UI.
    if (id) resolveHeldUI(id, d.action);
  } else {
    addLog(`❌ ${d.action} failed ${id ? '(' + id.slice(0, 8) + '…)' : ''}: ${d.error || 'unknown'}`, 'error');
    renderHeldList();
  }
});

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

// ── Auth Profile UI ──────────────────────────────────────────────
function onAuthMethodChange() {
  const method = document.getElementById('authMethod').value;

  // Hide all
  ['authLoginFields','authTokenField','authCookieField','authHeadersField']
    .forEach(id => {
      const el = document.getElementById(id);
      if (el) el.style.display = 'none';
    });

  // Show relevant
  const map = {
    'login':   'authLoginFields',
    'token':   'authTokenField',
    'cookie':  'authCookieField',
    'headers': 'authHeadersField',
  };
  if (map[method]) {
    const target = document.getElementById(map[method]);
    if (target) target.style.display = 'block';
  }

  const st = document.getElementById('authStatus');
  if (st) {
    st.textContent = method ? `Auth method: ${method}` : '—';
    st.style.color = method ? 'var(--blue)' : 'var(--text2)';
  }
}

function getAuthData() {
  const methodEl = document.getElementById('authMethod');
  const method = methodEl ? methodEl.value : '';
  if (!method) return {};

  return {
    method,
    username:       document.getElementById('authUsername')?.value?.trim()  || '',
    password:       document.getElementById('authPassword')?.value?.trim()  || '',
    login_url:      document.getElementById('authLoginUrl')?.value?.trim()  || '',
    token:          document.getElementById('authToken')?.value?.trim()     || '',
    cookie:         document.getElementById('authCookie')?.value?.trim()    || '',
    custom_headers: document.getElementById('authCustomHeaders')?.value?.trim() || '',
  };
}

socket.on('auth_test_result', d => {
  if (window._authTimeout) { clearTimeout(window._authTimeout); window._authTimeout = null; }
  const st  = document.getElementById('authStatus');
  const btn = document.getElementById('testAuthBtn');
  if (btn) btn.disabled = false;

  if (!st) return;

  if (d.success) {
    st.textContent = '✅ ' + (d.message || 'Authentication successful');
    st.style.color = 'var(--green)';
    addLog('✅ Auth test passed: ' + (d.message || ''), 'success');
  } else {
    st.textContent = '❌ ' + (d.message || 'Authentication failed');
    st.style.color = 'var(--red)';
    addLog('❌ Auth test failed: ' + (d.message || ''), 'error');
  }
});

function testAuth() {
  const url  = (document.getElementById('targetUrl')?.value || '').trim();
  const auth = getAuthData();
  const st   = document.getElementById('authStatus');
  const btn  = document.getElementById('testAuthBtn');

  if (!auth.method) {
    if (st) { st.textContent = '⚠️ Select an auth method'; st.style.color = 'var(--yellow)'; }
    return;
  }

  if (st) { st.textContent = '⏳ Testing...'; st.style.color = 'var(--text2)'; }
  if (btn) btn.disabled = true;

  // Clear any previous timeout
  if (window._authTimeout) { clearTimeout(window._authTimeout); }

  // 10 second safety timeout — prevents stuck UI
  window._authTimeout = setTimeout(() => {
    if (btn) btn.disabled = false;
    if (st)  { st.textContent = '❌ No response — check server'; st.style.color = 'var(--red)'; }
    addLog('⚠️ Auth test timed out', 'warning');
  }, 10000);

  socket.emit('test_auth', { url, auth });
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
function selectAllAttacks(on) {
  const ids = [
    // main scan options
    'optAI', 'optPlaywright', 'optJWT', 'optTiming', 'optFuzzer',
    'optRace', 'optSSRF', 'optSSTI', 'optMassAssign', 'optLogic',
    'optFastMode',
    // baseline tests
    'optEnc', 'optInjection', 'optCSWSH', 'optRateLimit', 'optMsgSize',
    'optInfoDisc', 'optGraphQL', 'optIDOR', 'optSubprotocol', 'optAuthBypass',
  ];
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el && el.type === 'checkbox') el.checked = !!on;
  });
  addLog(on ? '✅ Enabled all attacks' : '🧹 Cleared all attacks', 'info');
}

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
      race_condition:   document.getElementById('optRace').checked,
      ssrf:             document.getElementById('optSSRF').checked,
      ssti:             document.getElementById('optSSTI').checked,
      mass_assignment:  document.getElementById('optMassAssign').checked,
      business_logic:   document.getElementById('optLogic').checked,
      fast_mode:        document.getElementById('optFastMode').checked,
      enc_check:        document.getElementById('optEnc').checked,
      injection_tests:  document.getElementById('optInjection').checked,
      cswsh_check:      document.getElementById('optCSWSH').checked,
      rate_limit_check: document.getElementById('optRateLimit').checked,
      msg_size_check:   document.getElementById('optMsgSize').checked,
      info_disc_check:  document.getElementById('optInfoDisc').checked,
      graphql_check:    document.getElementById('optGraphQL').checked,
      idor_check:       document.getElementById('optIDOR').checked,
      subproto_check:   document.getElementById('optSubprotocol').checked,
      auth_bypass:      document.getElementById('optAuthBypass').checked,
      concurrent_count: parseInt(document.getElementById('concurrentCount').value),
      auth:             getAuthData(),
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
  clearProxyUI();
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

/* ── Proxy (real WS MITM) ───────────────────────────────────── */
function startProxy() {
  const wsUrl = (document.getElementById('proxyTargetUrl')?.value || '').trim();
  const port  = parseInt(document.getElementById('proxyPort')?.value) || 8080;
  const interceptMode = !!document.getElementById('proxyInterceptMode')?.checked;

  if (!wsUrl) { addLog('⚠️ Enter a target WS URL first', 'warning'); return; }

  addLog(`🧲 Starting proxy… target=${wsUrl} local_port=${port} intercept=${interceptMode}`, 'info');

  // Update info box immediately (even before server responds).
  const localEl = document.getElementById('proxyLocalUrl');
  if (localEl) localEl.textContent = `ws://localhost:${port}`;

  // Simple conflict warning (common mistake: using same port as target).
  try {
    const u = new URL(wsUrl.replace(/^ws/, 'http'));
    const targetPort = u.port ? parseInt(u.port) : (u.protocol === 'https:' ? 443 : 80);
    if (targetPort === port) {
      addLog(`⚠️ Local port ${port} matches target port ${targetPort}. Choose a different local port (e.g. 8080).`, 'warning');
    }
  } catch(e) {}

  document.getElementById('startProxyBtn').disabled = true;
  document.getElementById('stopProxyBtn').disabled  = true;
  const st = document.getElementById('proxyStatusText');
  if (st) st.textContent = 'Proxy Status: Starting...';

  socket.emit('start_proxy', { ws_url: wsUrl, port, intercept_mode: interceptMode });
  // If server-side emit is missed, request status shortly after.
  setTimeout(() => socket.emit('get_proxy_status', {}), 600);
  setTimeout(() => socket.emit('get_proxy_status', {}), 1600);
}

function stopProxy() {
  addLog('🧲 Stopping proxy…', 'info');
  socket.emit('stop_proxy', {});
  setTimeout(() => socket.emit('get_proxy_status', {}), 600);
  setTimeout(() => socket.emit('get_proxy_status', {}), 1600);
}

function quickProxyTest() {
  const port = parseInt(document.getElementById('proxyPort')?.value) || 8080;
  const url = `ws://localhost:${port}`;

  addLog(`🧪 Quick Test: connecting to ${url}`, 'info');

  let opened = false;
  const ws = new WebSocket(url);

  const to = setTimeout(() => {
    try { ws.close(); } catch(e) {}
    if (!opened) addLog('❌ Quick Test failed: could not open WebSocket to proxy (is it running?)', 'error');
    else addLog('⚠️ Quick Test: no response (target may not reply to ping)', 'warning');
  }, 4000);

  ws.onopen = () => {
    opened = true;
    addLog('🧪 Quick Test: sending {"type":"ping"}', 'info');
    try { ws.send('{"type":"ping"}'); } catch(e) {}
  };
  ws.onmessage = (e) => {
    clearTimeout(to);
    addLog('✅ Quick Test got response (see interceptor feed).', 'success');
    try { ws.close(); } catch(err) {}
  };
  ws.onerror = () => {
    clearTimeout(to);
    addLog('❌ Quick Test WebSocket error (check proxy status / port).', 'error');
  };
}

function updateProxyStatus(d) {
  const running = !!d.running;
  const port = d.port || parseInt(document.getElementById('proxyPort')?.value) || 8080;
  const dot = document.getElementById('proxyDot');
  const st  = document.getElementById('proxyStatusText');
  const localUrl = `ws://localhost:${port}`;
  const localEl = document.getElementById('proxyLocalUrl');
  const im = document.getElementById('proxyInterceptMode');

  if (localEl) localEl.textContent = localUrl;
  if (dot) dot.className = 'p-dot ' + (running ? 'running' : 'stopped');

  // Keep UI in sync with server-side intercept mode.
  if (im && typeof d.intercept_mode === 'boolean') {
    im.checked = d.intercept_mode;
  }

  if (st) {
    if (running) st.textContent = `Proxy Status: Running on ${localUrl}`;
    else if ((d.error || '') === 'starting') st.textContent = 'Proxy Status: Starting...';
    else if ((d.error || '') === 'stopping') st.textContent = 'Proxy Status: Stopping...';
    else st.textContent = 'Proxy Status: Stopped' + (d.error ? ` (${d.error})` : '');
  }

  const startBtn = document.getElementById('startProxyBtn');
  const stopBtn  = document.getElementById('stopProxyBtn');
  if (startBtn) startBtn.disabled = running;
  if (stopBtn)  stopBtn.disabled  = !running;

  // Keep replay channel alive while proxy is running.
  if (running) ensureReplayWs(port);
  else closeReplayWs();

  // Update empty-state hint in the feed.
  const feed = document.getElementById('proxyFeed');
  if (feed) {
    const empty = feed.querySelector('.empty-state');
    if (empty) {
      empty.innerHTML = running
        ? '<div class="icon">🧲</div><p>Proxy is running — connect a client to <b>' + localUrl + '</b> to capture traffic</p>'
        : '<div class="icon">🧲</div><p>Start the proxy to see live WebSocket traffic</p>';
    }
  }
}

function _safePrettyJSON(s) {
  try {
    const o = JSON.parse(s);
    return JSON.stringify(o, null, 2);
  } catch(e) { return null; }
}

function _truncateText(s, n=200) {
  if (!s) return '';
  if (s.length <= n) return s;
  return s.slice(0, n) + '…';
}

function addProxyMsg(data) {
  proxyMsgs.push(data);
  if (data.held) heldMsgs.set(data.id, data);
  else heldMsgs.delete(data.id);

  // Update stats
  const total = proxyMsgs.length;
  const c2s = proxyMsgs.filter(m => m.direction === 'CLIENT→SERVER').length;
  const s2c = proxyMsgs.filter(m => m.direction === 'SERVER→CLIENT').length;
  const flagged = proxyMsgs.filter(m => m.flagged).length;
  const held = heldMsgs.size;
  document.getElementById('pTotal').textContent = total;
  document.getElementById('pC2S').textContent = c2s;
  document.getElementById('pS2C').textContent = s2c;
  document.getElementById('pFlagged').textContent = flagged;
  document.getElementById('pHeld').textContent = held;

  // Feed row
  const feed = document.getElementById('proxyFeed');
  const empty = feed.querySelector('.empty-state');
  if (empty) empty.remove();

  const row = document.createElement('div');
  row.className = 'p-msg-row' + (data.flagged ? ' flagged' : '') + (data.held ? ' held' : '');
  row.setAttribute('data-id', data.id || '');
  row.setAttribute('data-dir', (data.direction || '').includes('CLIENT') ? 'client' : 'server');

  const t = document.createElement('span'); t.className = 'p-msg-time'; t.textContent = data.time || '';

  const dir = document.createElement('span');
  dir.className = 'p-msg-dir ' + (data.direction === 'CLIENT→SERVER' ? 'c' : 's');
  dir.textContent = data.direction === 'CLIENT→SERVER' ? 'CLIENT→SERVER' : 'SERVER→CLIENT';

  const size = document.createElement('span'); size.className = 'size-badge';
  size.textContent = `${data.size || 0}B`;

  const body = document.createElement('div'); body.className = 'p-msg-body';
  const msgRaw = (data.message || '');
  const pretty = (data.message_type === 'json') ? _safePrettyJSON(msgRaw) : null;
  const msgToShow = pretty || msgRaw;

  const pre = document.createElement('pre');
  pre.className = 'p-msg-content' + ((data.message_type === 'json' || pretty) ? ' json' : '');
  pre.textContent = _truncateText(msgToShow, 400);

  const moreBtn = document.createElement('button');
  moreBtn.className = 'mini-link';
  moreBtn.textContent = (msgToShow.length > 400) ? 'Show more' : '';
  if (msgToShow.length <= 400) moreBtn.style.display = 'none';
  let expanded = false;
  moreBtn.onclick = () => {
    expanded = !expanded;
    pre.textContent = expanded ? msgToShow : _truncateText(msgToShow, 400);
    moreBtn.textContent = expanded ? 'Show less' : 'Show more';
  };

  body.append(pre, moreBtn);

  const badges = document.createElement('div'); badges.className = 'p-badges';
  if (data.held) {
    const hb = document.createElement('span'); hb.className = 'held-badge'; hb.textContent = 'HELD';
    badges.appendChild(hb);
  }
  if (data.flags && data.flags.length) {
    data.flags.forEach(fl => {
      const b = document.createElement('span'); b.className = 'flag-badge'; b.textContent = fl;
      badges.appendChild(b);
    });
  }

  const actions = document.createElement('div'); actions.className = 'p-actions';
  const replay = document.createElement('button'); replay.className = 'btn btn-secondary btn-mini';
  replay.textContent = '🔄 Replay';
  // Don't offer replay for synthetic/system error rows (0B "Target Unreachable", etc).
  const isSystem = (data.direction || '') === 'SYSTEM';
  const isEmpty = !((data.message || '').toString().trim());
  if (isSystem || isEmpty) {
    replay.disabled = true;
    replay.title = 'Replay unavailable for system/error rows';
  } else {
    replay.onclick = () => replayMessage(data.id);
  }
  actions.appendChild(replay);

  row.append(t, dir, size, body, badges, actions);
  feed.appendChild(row);
  feed.scrollTop = feed.scrollHeight;

  // Held list (only if intercept mode is enabled in UI)
  renderHeldList();
}

function renderHeldList() {
  const wrap = document.getElementById('heldWrap');
  const list = document.getElementById('heldList');
  const enabled = !!document.getElementById('proxyInterceptMode')?.checked;
  const held = Array.from(heldMsgs.values());

  if (!enabled) {
    wrap.style.display = 'none';
    return;
  }
  wrap.style.display = 'block';
  list.innerHTML = '';
  if (!held.length) {
    list.innerHTML = '<div class="empty-state" style="padding:22px 10px"><div class="icon">⏸</div><p>No held messages</p></div>';
    return;
  }

  held.slice(-50).reverse().forEach(m => {
    const card = document.createElement('div');
    card.className = 'held-card';
    const hdr = document.createElement('div');
    hdr.className = 'held-hdr';
    hdr.innerHTML = `<span class="held-meta">${m.time || ''} · ${m.direction || ''} · ${m.size || 0}B</span>`;

    const ta = document.createElement('textarea');
    ta.className = 'held-edit';
    const pretty = (m.message_type === 'json') ? _safePrettyJSON(m.message || '') : null;
    ta.value = pretty || (m.message || '');
    ta.setAttribute('data-id', m.id || '');

    const btns = document.createElement('div');
    btns.className = 'held-btns';
    const fwd = document.createElement('button'); fwd.className = 'btn btn-secondary btn-mini'; fwd.textContent = 'Forward';
    fwd.onclick = () => {
      fwd.disabled = true; mod.disabled = true; drop.disabled = true;
      forwardHeld(m.id, null);
    };
    const mod = document.createElement('button'); mod.className = 'btn btn-secondary btn-mini'; mod.textContent = 'Modify & Forward';
    mod.onclick = () => {
      fwd.disabled = true; mod.disabled = true; drop.disabled = true;
      forwardHeld(m.id, ta.value);
    };
    const drop = document.createElement('button'); drop.className = 'btn btn-danger btn-mini'; drop.textContent = 'Drop';
    drop.onclick = () => {
      fwd.disabled = true; mod.disabled = true; drop.disabled = true;
      dropHeld(m.id);
    };
    btns.append(fwd, mod, drop);

    card.append(hdr, ta, btns);
    list.appendChild(card);
  });
}

function forwardHeld(messageId, modifiedContent) {
  // Optimistic UI update: remove immediately to avoid "stuck" UX.
  resolveHeldUI(messageId, 'forward');
  socket.emit('forward_message', { message_id: messageId, modified_content: modifiedContent });
}

function dropHeld(messageId) {
  resolveHeldUI(messageId, 'drop');
  socket.emit('drop_message', { message_id: messageId });
}

function replayMessage(messageId) {
  const m = proxyMsgs.find(x => x.id === messageId);
  if (!m) { addLog('⚠️ Message not found for replay', 'warning'); return; }
  const raw = (m.message || '').toString();
  const msg = raw.trim();
  if (!msg) { addLog('⚠️ Empty message — nothing to replay', 'warning'); return; }
  if (m.direction === 'SERVER→CLIENT') {
    // Practical replay: send payload back to the target (C→S).
    addLog('ℹ️ Replay sends payload to target (C→S)', 'info');
  }
  const port = parseInt(document.getElementById('proxyPort')?.value) || 8080;
  ensureReplayWs(port);
  if (replayWs && replayWs.readyState === WebSocket.OPEN) {
    try {
      replayWs.send(msg);
      addLog('✅ Replay sent via proxy (replay channel)', 'success');
      return;
    } catch(e) {}
  }

  // Fallback: ask backend to replay via any active session (if present).
  socket.emit('replay_via_proxy', { message: msg, direction: 'client_to_server' }, (res) => {
    if (res && res.ok) addLog('✅ Replay sent via proxy', 'success');
    else addLog(`❌ Replay failed: ${(res && res.error) ? res.error : 'unknown_error'}`, 'error');
  });
  addLog('🔄 Replaying via proxy...', 'info');
}

function clearProxyUI() {
  proxyMsgs = [];
  heldMsgs = new Map();
  document.getElementById('proxyFeed').innerHTML =
    '<div class="empty-state"><div class="icon">🧲</div><p>Start the proxy to see live WebSocket traffic</p></div>';
  document.getElementById('heldList').innerHTML = '';
  document.getElementById('heldWrap').style.display = 'none';
  ['pTotal','pC2S','pS2C','pFlagged','pHeld'].forEach(id => document.getElementById(id).textContent = '0');
}

function filterProxyFeed() {
  const q = (document.getElementById('proxySearch').value || '').toLowerCase();
  const dir = document.getElementById('proxyDirFilter').value;
  document.querySelectorAll('#proxyFeed .p-msg-row').forEach(row => {
    const content = row.textContent.toLowerCase();
    const rowDir = row.getAttribute('data-dir') || '';
    const dirMatch = dir === 'all' || rowDir === dir;
    row.style.display = (content.includes(q) && dirMatch) ? '' : 'none';
  });
}

function exportProxyMessages() {
  if (!proxyMsgs.length) { addLog('⚠️ No proxy messages to export', 'warning'); return; }
  const blob = new Blob([JSON.stringify(proxyMsgs, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `ws_proxy_${Date.now()}.json`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  addLog(`💾 Exported ${proxyMsgs.length} proxy messages`, 'success');
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
// (old fake interceptor helpers removed)

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
