/* ─── ShieldWatch Dashboard — Real-Time Client ──────────────────────────── */

/* ══════════════════════════════════════════════════════════════════════════
   PIN GATE — runs before anything else
   ══════════════════════════════════════════════════════════════════════════ */
(function PinGate() {
  const SESSION_KEY = 'sw_pin_auth';
  const gate        = document.getElementById('pinGate');
  if (!gate) return;

  // Already authenticated? Skip PIN gate
  if (localStorage.getItem(SESSION_KEY) === '1') {
    gate.style.display = 'none';
    return;
  }

  const dots    = [0,1,2,3].map(i => document.getElementById('pd' + i));
  const msgEl   = document.getElementById('pinMsg');
  const card    = gate.querySelector('.pin-card');
  const granted = document.getElementById('pgGranted');

  let pin      = '';
  let locked   = false;
  let lockTick = null;

  /* ── helpers ── */
  function updateDots() {
    dots.forEach((d, i) => d.classList.toggle('filled', i < pin.length));
  }

  function shake() {
    card.classList.remove('shake');
    void card.offsetWidth;          // force reflow to restart animation
    card.classList.add('shake');
  }

  function showSuccess() {
    dots.forEach(d => { d.classList.remove('filled'); d.classList.add('success'); });
    if (granted) granted.classList.add('show');
    setTimeout(() => {
      gate.classList.add('hidden');
      setTimeout(() => { gate.style.display = 'none'; }, 450);
    }, 1000);
  }

  function setMsg(text, color) {
    msgEl.textContent   = text;
    msgEl.style.color   = color || 'var(--red)';
  }

  /* ── digit input ── */
  function appendDigit(d) {
    if (locked || pin.length >= 4) return;
    pin += d;
    updateDots();
    setMsg('');
    if (pin.length === 4) submitPin();
  }

  function backspace() {
    if (locked || pin.length === 0) return;
    pin = pin.slice(0, -1);
    updateDots();
    setMsg('');
  }

  function clearPin() {
    if (locked) return;
    pin = '';
    updateDots();
    setMsg('');
  }

  /* ── lockdown countdown ── */
  function startLockdown(secsLeft) {
    locked = true;
    let secs = secsLeft;

    function tick() {
      setMsg('Locked — ' + secs + 's remaining');
      if (secs <= 0) {
        clearTimeout(lockTick);
        locked = false;
        pin    = '';
        updateDots();
        setMsg('');
        return;
      }
      secs--;
      lockTick = setTimeout(tick, 1000);
    }
    tick();
  }

  /* ── submit to server ── */
  async function submitPin() {
    locked = true;
    try {
      const res  = await fetch('/api/auth/pin', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ pin })
      });
      const data = await res.json();

      if (data.ok) {
        localStorage.setItem(SESSION_KEY, '1');
        localStorage.setItem('sw_token', data.token || '');
        showSuccess();
        return;
      }

      if (data.locked) {
        startLockdown(data.secsLeft);
        return;
      }

      // Wrong PIN
      shake();
      pin = '';
      updateDots();
      locked = false;
      const left = data.attemptsLeft;
      setMsg(left > 0
        ? 'Wrong PIN — ' + left + ' attempt' + (left !== 1 ? 's' : '') + ' left'
        : 'Too many attempts — locked for 60s');

    } catch (err) {
      pin = '';
      updateDots();
      locked = false;
      setMsg('Connection error — try again');
    }
  }

  /* ── physical keyboard ── */
  document.addEventListener('keydown', e => {
    if (e.key >= '0' && e.key <= '9') appendDigit(e.key);
    else if (e.key === 'Backspace')    backspace();
    else if (e.key === 'Escape')       clearPin();
  });
})();

/* ══════════════════════════════════════════════════════════════════════════ */

// ─── Auth token helper ────────────────────────────────────────────────────────
function swToken() { return localStorage.getItem('sw_token') || ''; }

function authHeaders(extra = {}) {
  return { 'Content-Type': 'application/json', 'x-sw-token': swToken(), ...extra };
}

function forceLogout() {
  localStorage.removeItem('sw_pin_auth');
  localStorage.removeItem('sw_token');
  location.reload();
}

const socket = io();

// ─── State ────────────────────────────────────────────────────────────────────
let allAttackers    = [];
let selectedSession = null;
let blockedIPSet    = new Set();
let blockedFPSet    = new Set();

// ─── DOM ──────────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ─── Socket Events ────────────────────────────────────────────────────────────
socket.on('connect', () => {
  setStatus(true);
  console.log('[SW] Connected to collector');
});

socket.on('disconnect', () => {
  setStatus(false);
});

socket.on('init', ({ events, attackers, blocked = [], blockedFPs = [], lastNexaChatAt }) => {
  allAttackers      = attackers;
  blockedIPSet      = new Set(blocked);
  blockedFPSet      = new Set(blockedFPs);
  events.slice().reverse().forEach(e => prependFeedItem(e, false));
  renderLeft(attackers);
  renderBlockedList();
  updateCounters(events, attackers);
  if (attackers.length > 0) selectAttacker(attackers[0]);
  // Show NexaChat connection state based on last contact time
  const recentContact = lastNexaChatAt && (Date.now() - lastNexaChatAt) < 300_000;
  setNexaChatStatus(recentContact);
});

socket.on('blocked_update', (list) => {
  blockedIPSet = new Set(list);
  renderBlockedList();
  if (selectedSession) {
    const a = allAttackers.find(x => x.session === selectedSession);
    if (a) updateBlockBtn(a);
  }
});

socket.on('blocked_fp_update', (list) => {
  blockedFPSet = new Set(list);
  if (selectedSession) {
    const a = allAttackers.find(x => x.session === selectedSession);
    if (a) updateBlockBtn(a);
  }
});

socket.on('new_event', (evt) => {
  prependFeedItem(evt, true);
  fetchStats();
});

socket.on('attackers_update', (attackers) => {
  allAttackers = attackers;
  renderLeft(attackers);
  updateCounters(null, attackers);
  // Refresh selected profile if still active
  if (selectedSession) {
    const current = attackers.find(a => a.session === selectedSession);
    if (current) renderProfile(current);
  } else if (attackers.length > 0) {
    selectAttacker(attackers[0]);
  }
});

socket.on('reset', () => {
  $('feedList').innerHTML = '<div class="feed-empty" id="feedEmpty"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="52" height="52"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><div>Monitoring NexaChat — no threats detected</div><div style="font-size:9px;margin-top:4px;letter-spacing:.04em">Attacks will appear here in real-time</div></div>';
  $('attackerList').innerHTML = '<div class="att-empty">No attackers identified</div>';
  $('attackTypes').innerHTML  = '<div class="at-empty">No attacks detected yet</div>';
  allAttackers = [];
  selectedSession = null;
  $('profileEmpty').style.display = '';
  $('profileContent').style.display = 'none';
  $('profileContent').classList.add('hidden');
  ['cntTotal','cntBlocked','cntAttackers','statTotal','statBlocked','statLogged'].forEach(id => { $(id).textContent = '0'; });
});

// ─── Status ───────────────────────────────────────────────────────────────────
let _socketOnline = false;

function setStatus(online) {
  _socketOnline = online;
  if (!online) {
    $('statusPill').classList.remove('online');
    $('statusText').textContent = 'Disconnected';
  }
  // If socket reconnects, re-evaluate NexaChat status (don't auto-show "Connected")
}

function setNexaChatStatus(active) {
  const pill = $('statusPill');
  pill.classList.toggle('online', active);
  $('statusText').textContent = active ? 'LIVE — Connected' : 'Awaiting NexaChat…';
}

socket.on('nexachat_status', (active) => setNexaChatStatus(active));

// ─── Fetch stats from REST ────────────────────────────────────────────────────
async function fetchStats() {
  try {
    const r = await fetch('/api/stats', { headers: authHeaders() });
    if (!r.ok) return;
    const s = await r.json();
    animateNum('cntTotal',    s.total);
    animateNum('cntBlocked',  s.blocked);
    animateNum('cntAttackers',s.attackers);
    animateNum('statTotal',   s.total);
    animateNum('statBlocked', s.blocked);
    animateNum('statLogged',  s.logged);
    renderAttackTypes(s.byType, s.total);
  } catch {}
}

function updateCounters(events, attackers) {
  // Only count users who have actually committed attacks
  const realCount = attackers.filter(a => (a.threatScore || 0) > 0).length;
  animateNum('cntAttackers', realCount);
  fetchStats();
}

function animateNum(id, val) {
  const el = $(id);
  if (!el) return;
  const prev = parseInt(el.textContent) || 0;
  if (prev !== val) {
    el.textContent = val;
    el.classList.remove('bump');
    void el.offsetWidth;
    el.classList.add('bump');
  }
}

// ─── Render Left Panel ────────────────────────────────────────────────────────
function renderLeft(attackers) {
  renderAttackerList(attackers);
}

// ─── Attack type meta (icon, display name, bar colour) ───────────────────────
const ATTACK_META = {
  sqli:           { icon: '💉', label: 'SQL Injection',    color: '#ef4444' },
  xss:            { icon: '📜', label: 'XSS',              color: '#f97316' },
  pathTraversal:  { icon: '📂', label: 'Path Traversal',   color: '#f59e0b' },
  cmdInjection:   { icon: '💻', label: 'Cmd Injection',    color: '#a855f7' },
  ddos:           { icon: '🌊', label: 'DDoS Flood',       color: '#06b6d4' },
  csrf:           { icon: '🎭', label: 'CSRF',             color: '#ec4899' },
  bruteforce:     { icon: '🔐', label: 'Brute Force',      color: '#8b5cf6' },
  idor:           { icon: '🔓', label: 'IDOR',             color: '#10b981' },
  sessionFixation:{ icon: '🔑', label: 'Session Fixation', color: '#eab308' },
  unknown:        { icon: '❓', label: 'Unknown',           color: '#6b7280' },
};

function attackMeta(type) {
  return ATTACK_META[type] || { icon: '⚠️', label: type.replace(/([A-Z])/g,' $1').trim(), color: '#6b7280' };
}

function renderAttackTypes(byType, total) {
  const el = $('attackTypes');
  const entries = Object.entries(byType).sort((a,b) => b[1]-a[1]);
  if (!entries.length) { el.innerHTML = '<div class="at-empty">No attacks detected yet</div>'; return; }

  el.innerHTML = entries.map(([type, count]) => {
    const pct  = total > 0 ? count / total : 0;
    const meta = attackMeta(type);
    return `
      <div class="at-item">
        <div class="at-dot" style="background:${meta.color}"></div>
        <span class="at-name">${meta.label}</span>
        <span class="at-cnt" style="color:${meta.color}">${count}</span>
        <div class="at-bar-track">
          <div class="at-bar-fill" style="background:${meta.color};transform:scaleX(${pct.toFixed(3)})"></div>
        </div>
      </div>`;
  }).join('');
}

function renderAttackerList(attackers) {
  const el = $('attackerList');
  if (!attackers.length) { el.innerHTML = '<div class="att-empty">No attackers identified</div>'; return; }

  el.innerHTML = attackers.map(a => {
    const geo = a.geo || {};
    const loc = [geo.city, geo.country_name].filter(Boolean).join(' · ') || a.ip || '—';
    return `
    <div class="att-item ${a.session === selectedSession ? 'active' : ''}"
         onclick="selectAttacker(${JSON.stringify(a).replace(/"/g,'&quot;')})">
      <div class="att-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
          <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/>
        </svg>
      </div>
      <div class="att-info">
        <div class="att-ip">${escHtml(a.ip || a.session)}</div>
        <div class="att-meta">${escHtml(loc)}</div>
      </div>
      <div class="att-cnt-badge" style="background:${(a.threat?.color||'#ef4444')}18;border-color:${(a.threat?.color||'#ef4444')}30;color:${(a.threat?.color||'#ef4444')}">${a.threatScore}</div>
    </div>`;
  }).join('');
}

// ─── Feed ─────────────────────────────────────────────────────────────────────
function prependFeedItem(evt, animate) {
  const feedEmpty = $('feedEmpty');
  if (feedEmpty) feedEmpty.remove();

  const feed  = $('feedList');
  const item  = document.createElement('div');
  item.className = 'fi';
  if (!animate) item.style.animationDuration = '0s';

  const threatType = evt.threat?.type || 'unknown';
  const payload    = evt.threat?.raw  || '';
  const time       = new Date(evt.timestamp || evt.receivedAt).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit', second:'2-digit' });
  const meta       = attackMeta(threatType);
  const verdict    = evt.verdict || 'LOGGED';
  const isBlocked  = verdict === 'BLOCKED';

  item.innerHTML = `
    <div class="fi-accent" style="background:${meta.color}"></div>
    <div class="fi-body">
      <div class="fi-top">
        <span class="fi-badge" style="background:${meta.color}18;color:${meta.color};border:1px solid ${meta.color}30">${meta.label.toUpperCase()}</span>
        <span class="fi-verdict ${isBlocked ? 'fi-blocked' : 'fi-logged'}">${verdict}</span>
        <span class="fi-time">${time}</span>
      </div>
      <div class="fi-path">${escHtml(evt.method || 'HTTP')} ${escHtml(evt.path || '/')}</div>
      <div class="fi-meta">
        <span class="fi-ip">${escHtml(evt.ip || evt.session || 'unknown')}</span>
        ${payload ? `<span class="fi-payload">${escHtml(payload.slice(0,80))}</span>` : ''}
      </div>
    </div>`;

  item.addEventListener('click', () => {
    const attacker = allAttackers.find(a => a.session === (evt.session || evt.ip));
    if (attacker) selectAttacker(attacker);
  });

  feed.insertBefore(item, feed.firstChild);
  while (feed.children.length > 100) feed.removeChild(feed.lastChild);
}

// ─── Attacker Profile ─────────────────────────────────────────────────────────
function selectAttacker(attacker) {
  selectedSession = attacker.session;

  // Update chip highlights
  document.querySelectorAll('.attacker-chip').forEach(el => {
    el.classList.toggle('selected', el.querySelector('.attacker-name')?.textContent === attacker.session);
  });

  renderProfile(attacker);
}

function renderProfile(a) {
  $('profileEmpty').style.display = 'none';
  const pc = $('profileContent');
  pc.classList.remove('hidden');
  pc.style.display = 'flex';
  updateBlockBtn(a);

  // ── Threat Score Ring ──
  const score   = a.threatScore || 0;
  const level   = a.threat || { label: 'LOW', color: '#10b981' };
  const circumf = 188;
  const offset  = circumf - (score / 100) * circumf;

  $('scoreValue').textContent = score;
  $('scoreLevel').textContent = level.label;
  $('scoreLevel').style.color = level.color;
  $('scoreCard').style.borderLeftColor = level.color;

  const ring = $('scoreRing');
  ring.style.strokeDashoffset = offset;
  ring.style.stroke           = level.color;

  // ── Identity ──
  // Show clean session name — strip "anon@" prefix for display
  const displayName = (a.session || '—').replace(/^anon@/, 'Guest ');
  $('pSession').textContent = displayName;
  $('pIP').textContent      = a.ip || '—';

  // Status — VPN detected or Active
  const statusEl = $('pHoneypot');
  if (a.vpnDetected) {
    statusEl.innerHTML = `<span class="vpn-badge">🔄 VPN ROTATION DETECTED</span>`;
  } else {
    statusEl.textContent = 'Active';
  }

  // VPN history
  const vpnHistEl = $('pVPNHistory');
  if (vpnHistEl) {
    if (a.vpnHistory && a.vpnHistory.length > 0) {
      vpnHistEl.textContent = a.vpnHistory.join(' → ');
      vpnHistEl.closest('.profile-row').style.display = 'flex';
    } else {
      vpnHistEl.closest('.profile-row').style.display = 'none';
    }
  }

  // Device ID (hardware fingerprint hash + human-readable raw if available)
  const fpEl = $('pFPID');
  if (fpEl) {
    if (a.fpId) {
      const raw = a.fingerprint?.deviceRaw || '';
      // Show hash + first meaningful hw segment (platform|cores|ram)
      const hint = raw ? ' · ' + raw.split('|').slice(0,3).join(' ') : '';
      fpEl.textContent = a.fpId + hint;
    } else {
      fpEl.textContent = '—';
    }
  }

  // ── Geo ──
  const geo = a.geo || {};
  $('pCountry').textContent = geo.country_name ? `${getFlagEmoji(geo.country_code)} ${geo.country_name}` : '—';
  $('pCity').textContent    = [geo.city, geo.region].filter(Boolean).join(', ') || '—';
  $('pOrg').textContent     = geo.org      || '—';
  $('pTZ').textContent      = geo.timezone || '—';

  // ── Device (UA parsed) ──
  const ua  = a.ua || {};
  const fp  = a.fingerprint || {};

  $('pBrowser').textContent = fp.browser || ua.browser || '—';
  $('pOS').textContent      = fp.os      || ua.os      || '—';
  $('pScreen').textContent  = fp.screen  || '—';
  $('pLang').textContent    = fp.language || '—';
  $('pFPTZ').textContent    = fp.timezone || geo.timezone || '—';
  $('pCores').textContent   = fp.cores != null ? `${fp.cores} cores` : '—';
  $('pGPU').textContent     = fp.gpu     || '—';
  $('pTouch').textContent   = fp.touch != null ? (fp.touch ? 'Yes' : 'No') : '—';

  // ── Attack Summary ──
  const summary  = $('attackSummary');
  const counts   = a.attackCounts || {};
  const entries  = Object.entries(counts);

  if (!entries.length) {
    summary.innerHTML = '<span style="color:var(--text-muted);font-size:12px">No attacks yet</span>';
  } else {
    summary.innerHTML = entries.map(([type, count]) => {
      const meta = attackMeta(type);
      return `<span class="atk-tag" style="background:${meta.color}18;color:${meta.color};border-color:${meta.color}33">
        ${meta.icon} ${meta.label} ×${count}
      </span>`;
    }).join('');
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function getFlagEmoji(code) {
  if (!code || code.length !== 2) return '🌐';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

// ─── IP Blocking ──────────────────────────────────────────────────────────────
function updateBlockBtn(a) {
  const blockIPBtn    = $('blockIPBtn');
  const unblockIPBtn  = $('unblockIPBtn');
  const blockFPBtn    = $('blockFPBtn');
  const unblockFPBtn  = $('unblockFPBtn');
  if (!blockIPBtn) return;

  const ipBlocked = blockedIPSet.has(a.ip);
  const fpBlocked = a.fpId && blockedFPSet.has(a.fpId);

  blockIPBtn.style.display   = ipBlocked ? 'none' : 'flex';
  unblockIPBtn.style.display = ipBlocked ? 'flex'  : 'none';

  if (blockFPBtn) {
    blockFPBtn.style.display   = (!a.fpId || fpBlocked) ? 'none' : 'flex';
    unblockFPBtn.style.display = (a.fpId && fpBlocked)   ? 'flex' : 'none';
  }
}

async function blockCurrentIP() {
  const a = allAttackers.find(x => x.session === selectedSession);
  if (!a || !a.ip) return;
  await fetch('/api/block', { method:'POST', headers: authHeaders(), body:JSON.stringify({ ip: a.ip }) });
  showToast(`🚫 ${a.ip} blocked!`, 'red');
}

async function unblockCurrentIP() {
  const a = allAttackers.find(x => x.session === selectedSession);
  if (!a || !a.ip) return;
  await fetch('/api/unblock', { method:'POST', headers: authHeaders(), body:JSON.stringify({ ip: a.ip }) });
  showToast(`✅ ${a.ip} unblocked`, 'green');
}

async function blockCurrentFP() {
  const a = allAttackers.find(x => x.session === selectedSession);
  if (!a || !a.fpId) return;
  await fetch('/api/block-fp', { method:'POST', headers: authHeaders(), body:JSON.stringify({ fpId: a.fpId }) });
  showToast(`🔒 Device fingerprint blocked — VPN won't help!`, 'red');
}

async function unblockCurrentFP() {
  const a = allAttackers.find(x => x.session === selectedSession);
  if (!a || !a.fpId) return;
  await fetch('/api/unblock-fp', { method:'POST', headers: authHeaders(), body:JSON.stringify({ fpId: a.fpId }) });
  showToast(`✅ Fingerprint unblocked`, 'green');
}

function renderBlockedList() {
  const el    = $('blockedList');
  const count = $('blockedCount');
  const list  = Array.from(blockedIPSet);
  if (count) count.textContent = list.length;
  if (!list.length) {
    el.innerHTML = '<div class="attack-empty">No IPs blocked</div>';
    return;
  }
  el.innerHTML = list.map(ip => `
    <div class="blocked-ip-row">
      <span class="blocked-ip-addr">🚫 ${escHtml(ip)}</span>
      <button class="unblock-btn" onclick="unblockIP('${escHtml(ip)}')">Unblock</button>
    </div>`).join('');
}

async function unblockIP(ip) {
  await fetch('/api/unblock', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ ip }),
  });
  showToast(`✅ ${ip} unblocked`, 'green');
}

// ─── Toast notification ───────────────────────────────────────────────────────
function showToast(msg, color = 'red') {
  const t = document.createElement('div');
  t.className = 'sw-toast';
  t.style.borderColor = color === 'green' ? '#10b981' : '#ef4444';
  t.style.color       = color === 'green' ? '#10b981' : '#ef4444';
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.classList.add('show'), 10);
  setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 300); }, 2500);
}

// ─── Reset button ─────────────────────────────────────────────────────────────
$('resetBtn').addEventListener('click', async () => {
  if (!confirm('Clear all ShieldWatch data?')) return;
  await fetch('/api/reset', { method: 'POST', headers: authHeaders() });
});

// ─── Logout ───────────────────────────────────────────────────────────────────
$('logoutBtn').addEventListener('click', async () => {
  await fetch('/api/auth/logout', { method: 'POST', headers: authHeaders() });
  forceLogout();
});

// ─── Change PIN ───────────────────────────────────────────────────────────────
function openChangePinModal() {
  // Reset all fields and messages
  $('cpnCurrent').value  = '';
  $('cpnNew').value      = '';
  $('cpnConfirm').value  = '';
  ['cpnCurrent','cpnNew','cpnConfirm'].forEach(id => $( id).classList.remove('error'));
  setCpnMsg('', '');
  $('cpnSubmitBtn').disabled = false;
  $('changePinOverlay').classList.remove('hidden');
  setTimeout(() => $('cpnCurrent').focus(), 60);
}

function closeChangePinModal() {
  $('changePinOverlay').classList.add('hidden');
}

// Close if user clicks the dark backdrop (not the card itself)
function closePinModalOnBackdrop(e) {
  if (e.target === $('changePinOverlay')) closeChangePinModal();
}

// Allow Enter to move between fields or submit on the last field
function cpnKeydown(e) {
  if (e.key !== 'Enter') return;
  const fields = ['cpnCurrent', 'cpnNew', 'cpnConfirm'];
  const idx    = fields.indexOf(e.target.id);
  if (idx < fields.length - 1) {
    $(fields[idx + 1]).focus();
  } else {
    submitPinChange();
  }
}

function setCpnMsg(text, type) {
  const el = $('cpnMsg');
  el.textContent  = text;
  el.className    = `cpn-msg ${type}`;
}

async function submitPinChange() {
  const currentPin = $('cpnCurrent').value.trim();
  const newPin     = $('cpnNew').value.trim();
  const confirmPin = $('cpnConfirm').value.trim();

  // ── Client-side validation ──
  let error = null;
  let focus = null;

  ['cpnCurrent','cpnNew','cpnConfirm'].forEach(id => $(id).classList.remove('error'));

  if (!currentPin) { error = 'Enter your current PIN'; focus = 'cpnCurrent'; }
  else if (!/^\d{4}$/.test(newPin))    { error = 'New PIN must be exactly 4 digits'; focus = 'cpnNew'; }
  else if (newPin === currentPin)      { error = 'New PIN must differ from current PIN'; focus = 'cpnNew'; }
  else if (newPin !== confirmPin)      { error = 'PINs do not match'; focus = 'cpnConfirm'; }

  if (error) {
    if (focus) { $(focus).classList.add('error'); $(focus).focus(); }
    setCpnMsg(error, 'err');
    return;
  }

  // ── Submit to server ──
  $('cpnSubmitBtn').disabled = true;
  setCpnMsg('Verifying…', '');

  try {
    const res  = await fetch('/api/auth/change-pin', {
      method:  'POST',
      headers: authHeaders(),
      body:    JSON.stringify({ currentPin, newPin, confirmPin }),
    });
    const data = await res.json();

    if (!data.ok) {
      // Wrong current PIN or validation error from server
      $('cpnSubmitBtn').disabled = false;
      if (data.error?.toLowerCase().includes('current')) {
        $('cpnCurrent').classList.add('error');
        $('cpnCurrent').focus();
      }
      setCpnMsg(data.error || 'Change failed', 'err');
      return;
    }

    // ── Success — show message then force re-login ──
    setCpnMsg('PIN changed! Logging out…', 'ok');

    setTimeout(() => {
      closeChangePinModal();
      forceLogout(); // clears localStorage and reloads → shows PIN gate
    }, 1400);

  } catch (err) {
    $('cpnSubmitBtn').disabled = false;
    setCpnMsg('Connection error — try again', 'err');
  }
}

// ─── Boot ─────────────────────────────────────────────────────────────────────
fetchStats();

/* ══════════════════════════════════════════════════════════════════════════
   HISTORY — Encrypted Audit Log viewer
   ══════════════════════════════════════════════════════════════════════════ */

let _histEvents = [];   // decrypted events for the selected date
let _histIntact = true; // HMAC chain status
let _histDate   = null; // currently viewed date string (YYYY-MM-DD)

// ── Open overlay and fetch available dates ────────────────────────────────────
async function openHistory() {
  const overlay = $('historyOverlay');
  overlay.classList.remove('hidden');
  $('histDateTabs').innerHTML = '<span class="hist-date-placeholder">Loading dates…</span>';
  $('histIntegrityBadge').className = '';
  $('histIntegrityBadge').textContent = '';
  $('histEventList').innerHTML = '<div class="hist-empty">Select a date above to decrypt and view attack records</div>';
  $('histEventCount').textContent = '';

  try {
    const res  = await fetch('/api/history/dates', { headers: authHeaders() });
    const data = await res.json();

    if (!data.ok || !data.dates || !data.dates.length) {
      $('histDateTabs').innerHTML = '<span class="hist-date-placeholder">No history yet — attacks are recorded as they happen.</span>';
      return;
    }

    renderDateTabs(data.dates);
    loadHistoryDate(data.dates[0]); // auto-load newest
  } catch (err) {
    $('histDateTabs').innerHTML = `<span class="hist-date-placeholder" style="color:#ef4444">Error: ${escHtml(err.message)}</span>`;
  }
}

// ── Close overlay ─────────────────────────────────────────────────────────────
function closeHistory() {
  $('historyOverlay').classList.add('hidden');
}

// ── Render date tab strip ─────────────────────────────────────────────────────
function renderDateTabs(dates) {
  $('histDateTabs').innerHTML = dates.map(d =>
    `<button class="hist-date-btn ${d === _histDate ? 'active' : ''}"
             onclick="loadHistoryDate('${d}')">${d}</button>`
  ).join('');
}

// ── Load and decrypt one day's records ───────────────────────────────────────
async function loadHistoryDate(date) {
  _histDate  = date;
  _histEvents = [];

  // Update active tab highlight
  document.querySelectorAll('.hist-date-btn').forEach(b => {
    b.classList.toggle('active', b.textContent.trim() === date);
  });

  // Reset badge and list while loading
  $('histIntegrityBadge').className  = '';
  $('histIntegrityBadge').textContent = '';
  $('histEventList').innerHTML = '<div class="hist-empty">Decrypting records…</div>';
  $('histEventCount').textContent = '';

  try {
    const res  = await fetch(`/api/history/${date}`, { headers: authHeaders() });
    const data = await res.json();

    _histEvents = (data.events || []).filter(e => !e._tampered && !e._error);
    _histIntact = data.intact !== false;

    // Integrity badge
    const badge = $('histIntegrityBadge');
    badge.className   = `hist-badge ${_histIntact ? 'hist-badge-intact' : 'hist-badge-tampered'}`;
    badge.textContent = _histIntact ? '✓ CHAIN INTACT' : '⚠ TAMPERED';

    // Reset filters
    $('histFilterType').value    = '';
    $('histFilterIP').value      = '';
    $('histFilterVerdict').value = '';

    renderHistoryEvents();
  } catch (err) {
    $('histEventList').innerHTML =
      `<div class="hist-empty" style="color:#ef4444">Failed to load records: ${escHtml(err.message)}</div>`;
  }
}

// ── Filter changed ────────────────────────────────────────────────────────────
function applyHistoryFilters() { renderHistoryEvents(); }

// ── Render filtered event list ────────────────────────────────────────────────
function renderHistoryEvents() {
  const typeFilter    = ($('histFilterType')?.value    || '').trim();
  const ipFilter      = ($('histFilterIP')?.value      || '').trim().toLowerCase();
  const verdictFilter = ($('histFilterVerdict')?.value || '').trim();

  const filtered = _histEvents.filter(evt => {
    if (typeFilter    && (evt.threat?.type || '') !== typeFilter)           return false;
    if (ipFilter      && !(evt.ip || '').toLowerCase().includes(ipFilter))  return false;
    if (verdictFilter && (evt.verdict || '') !== verdictFilter)             return false;
    return true;
  });

  $('histEventCount').textContent = `${filtered.length} event${filtered.length !== 1 ? 's' : ''}`;

  if (!filtered.length) {
    $('histEventList').innerHTML = '<div class="hist-empty">No events match the current filters</div>';
    return;
  }

  const header = `<div class="hist-header-row">
    <span>Attack Type</span>
    <span>IP Address</span>
    <span>Verdict</span>
    <span>Endpoint</span>
    <span style="text-align:right">Time</span>
  </div>`;

  const rows = filtered.map(evt => {
    const type    = evt.threat?.type || 'unknown';
    const meta    = attackMeta(type);
    const verdict = evt.verdict || 'LOGGED';
    const ip      = evt.ip || evt.session || '—';
    const p       = `${evt.method || 'HTTP'} ${evt.path || '/'}`;
    const ts      = evt.timestamp || evt.receivedAt || '';
    const timeStr = ts
      ? new Date(ts).toLocaleString([], { month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit' })
      : '—';
    const payload   = evt.threat?.raw ? String(evt.threat.raw).slice(0, 80) : '';
    const isBlocked = verdict === 'BLOCKED';

    return `<div class="hist-event-row" title="${escHtml(payload)}">
      <span class="hist-col-type">
        <span class="fi-badge" style="background:${meta.color}18;color:${meta.color};border:1px solid ${meta.color}30">
          ${escHtml(meta.label.toUpperCase())}
        </span>
      </span>
      <span class="hist-col-ip">${escHtml(ip)}</span>
      <span><span class="fi-verdict ${isBlocked ? 'fi-blocked' : 'fi-logged'}">${escHtml(verdict)}</span></span>
      <span class="hist-col-path" title="${escHtml(p)}">${escHtml(p)}</span>
      <span class="hist-col-time">${escHtml(timeStr)}</span>
    </div>`;
  }).join('');

  $('histEventList').innerHTML = header + rows;
}

// ── PDF Export ────────────────────────────────────────────────────────────────
function exportHistoryPDF() {
  const typeFilter    = ($('histFilterType')?.value    || '').trim();
  const ipFilter      = ($('histFilterIP')?.value      || '').trim().toLowerCase();
  const verdictFilter = ($('histFilterVerdict')?.value || '').trim();

  const filtered = _histEvents.filter(evt => {
    if (typeFilter    && (evt.threat?.type || '') !== typeFilter)           return false;
    if (ipFilter      && !(evt.ip || '').toLowerCase().includes(ipFilter))  return false;
    if (verdictFilter && (evt.verdict || '') !== verdictFilter)             return false;
    return true;
  });

  const rows = filtered.map((evt, i) => {
    const type    = evt.threat?.type || 'unknown';
    const meta    = attackMeta(type);
    const verdict = evt.verdict || 'LOGGED';
    const ip      = evt.ip || evt.session || '—';
    const geo     = evt.geo ? [evt.geo.country_name, evt.geo.city].filter(Boolean).join(', ') : '';
    const endpoint= `${evt.method || 'HTTP'} ${evt.path || '/'}`;
    const ts      = evt.timestamp || evt.receivedAt || '';
    const timeStr = ts ? new Date(ts).toLocaleString() : '—';
    const payload = evt.threat?.raw ? String(evt.threat.raw).slice(0, 140) : '—';
    const bg      = i % 2 === 0 ? '#ffffff' : '#f9fafb';

    return `<tr style="background:${bg}">
      <td>${i + 1}</td>
      <td><strong>${escHtml(meta.label)}</strong></td>
      <td>${escHtml(ip)}</td>
      <td>${escHtml(geo)}</td>
      <td><strong>${escHtml(verdict)}</strong></td>
      <td>${escHtml(endpoint)}</td>
      <td>${escHtml(timeStr)}</td>
      <td style="font-family:monospace;font-size:8px;word-break:break-all;color:#555">${escHtml(payload)}</td>
    </tr>`;
  }).join('');

  const integrityLine = _histIntact
    ? '<span style="color:#10b981;font-weight:700">✓ HMAC-SHA256 chain verified — log is tamper-free</span>'
    : '<span style="color:#ef4444;font-weight:700">⚠ TAMPERED — HMAC chain broken, log may have been modified</span>';

  const activeFilters = [
    typeFilter    ? `Type: ${typeFilter}`       : '',
    ipFilter      ? `IP contains: ${ipFilter}`  : '',
    verdictFilter ? `Verdict: ${verdictFilter}` : '',
  ].filter(Boolean).join('  ·  ') || 'None';

  const html = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<title>ShieldWatch Audit Report — ${escHtml(_histDate || '—')}</title>
<style>
  body{font-family:Arial,sans-serif;font-size:11px;color:#111;margin:24px;}
  h1{font-size:20px;margin:0 0 4px}
  .meta{color:#666;font-size:10px;margin-bottom:10px}
  .integrity{margin-bottom:14px;padding:8px 12px;background:#f1f5f9;border-radius:4px;border:1px solid #e2e8f0}
  table{width:100%;border-collapse:collapse;font-size:10px}
  th{background:#1a1a2e;color:#fff;padding:7px 8px;text-align:left;font-size:9px;
     text-transform:uppercase;letter-spacing:.05em}
  td{padding:5px 8px;border-bottom:1px solid #e5e7eb;vertical-align:top}
  @media print{
    body{margin:12px}
    .no-print{display:none}
    @page{size:A4 landscape;margin:1.5cm}
  }
</style>
</head>
<body>
<h1>ShieldWatch — Attack Audit Report</h1>
<div class="meta">
  Date: <strong>${escHtml(_histDate || '—')}</strong>&nbsp;&nbsp;|&nbsp;&nbsp;
  Events: <strong>${filtered.length}</strong>&nbsp;&nbsp;|&nbsp;&nbsp;
  Filters: ${escHtml(activeFilters)}&nbsp;&nbsp;|&nbsp;&nbsp;
  Generated: ${new Date().toLocaleString()}
</div>
<div class="integrity">${integrityLine}</div>
<table>
  <thead><tr>
    <th>#</th><th>Attack Type</th><th>IP Address</th><th>Location</th>
    <th>Verdict</th><th>Endpoint</th><th>Timestamp</th><th>Payload (truncated)</th>
  </tr></thead>
  <tbody>
    ${rows || '<tr><td colspan="8" style="text-align:center;padding:20px;color:#999">No events match the active filters</td></tr>'}
  </tbody>
</table>
</body></html>`;

  const w = window.open('', '_blank', 'width=1100,height=720');
  if (!w) { alert('Allow pop-ups for this site to export PDF.'); return; }
  w.document.write(html);
  w.document.close();
  w.focus();
  setTimeout(() => w.print(), 350);
}
