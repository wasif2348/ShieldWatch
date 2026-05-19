/* ─── ShieldWatch Dashboard — Real-Time Client ──────────────────────────── */

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

socket.on('init', ({ events, attackers, blocked = [], blockedFPs = [] }) => {
  allAttackers      = attackers;
  blockedIPSet      = new Set(blocked);
  blockedFPSet      = new Set(blockedFPs);
  events.slice().reverse().forEach(e => prependFeedItem(e, false));
  renderLeft(attackers);
  renderBlockedList();
  updateCounters(events, attackers);
  if (attackers.length > 0) selectAttacker(attackers[0]);
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
  $('feed').innerHTML = '<div class="feed-empty" id="feedEmpty"><div class="feed-empty-icon">🛡️</div><div>Monitoring NexaChat — no threats detected</div><div class="feed-empty-sub">Attacks will appear here in real-time</div></div>';
  $('attackerList').innerHTML = '<div class="attack-empty">No attackers identified</div>';
  $('attackTypes').innerHTML  = '<div class="attack-empty">No attacks detected yet</div>';
  allAttackers = [];
  selectedSession = null;
  $('profileEmpty').classList.remove('hidden');
  $('profileContent').classList.add('hidden');
  ['cntTotal','cntBlocked','cntDecoys','cntAttackers','statTotal','statBlocked','statDecoys','statLogged'].forEach(id => { $(id).textContent = '0'; });
});

// ─── Status ───────────────────────────────────────────────────────────────────
function setStatus(online) {
  const pill = $('statusPill');
  pill.classList.toggle('online', online);
  $('statusText').textContent = online ? 'LIVE — Connected' : 'Disconnected';
}

// ─── Fetch stats from REST ────────────────────────────────────────────────────
async function fetchStats() {
  try {
    const r = await fetch('/api/stats');
    const s = await r.json();
    animateNum('cntTotal',    s.total);
    animateNum('cntBlocked',  s.blocked);
    animateNum('cntDecoys',   s.decoys);
    animateNum('cntAttackers',s.attackers);
    animateNum('statTotal',   s.total);
    animateNum('statBlocked', s.blocked);
    animateNum('statDecoys',  s.decoys);
    animateNum('statLogged',  s.logged);
    renderAttackTypes(s.byType, s.total);
  } catch {}
}

function updateCounters(events, attackers) {
  animateNum('cntAttackers', attackers.length);
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
  honeypot:       { icon: '🍯', label: 'Honeypot',         color: '#f97316' },
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
  if (!entries.length) { el.innerHTML = '<div class="attack-empty">No attacks detected yet</div>'; return; }

  el.innerHTML = entries.map(([type, count]) => {
    const pct  = total > 0 ? Math.round((count / total) * 100) : 0;
    const meta = attackMeta(type);
    return `
      <div class="attack-type-row">
        <span class="attack-type-icon">${meta.icon}</span>
        <div style="flex:1">
          <div style="display:flex;align-items:center">
            <span class="attack-type-name">${meta.label}</span>
            <span class="attack-type-count" style="color:${meta.color}">${count}</span>
          </div>
          <div class="attack-type-bar">
            <div class="attack-type-bar-fill" style="width:${pct}%;background:${meta.color}"></div>
          </div>
        </div>
      </div>`;
  }).join('');
}

function renderAttackerList(attackers) {
  const el = $('attackerList');
  if (!attackers.length) { el.innerHTML = '<div class="attack-empty">No attackers identified</div>'; return; }

  el.innerHTML = attackers.map(a => `
    <div class="attacker-chip ${a.session === selectedSession ? 'selected' : ''}"
         onclick="selectAttacker(${JSON.stringify(a).replace(/"/g,'&quot;')})">
      <div class="attacker-dot" style="background:${a.threat?.color || '#10b981'}"></div>
      <span class="attacker-name">${escHtml(a.session)}</span>
      <span class="attacker-score">${a.threatScore}</span>
    </div>`
  ).join('');
}

// ─── Feed ─────────────────────────────────────────────────────────────────────
function prependFeedItem(evt, animate) {
  const feedEmpty = $('feedEmpty');
  if (feedEmpty) feedEmpty.remove();

  const feed  = $('feed');
  const item  = document.createElement('div');
  item.className = `feed-item verdict-${evt.verdict || 'LOGGED'}`;
  item.style.animationDuration = animate ? '0.25s' : '0s';

  const threatType = evt.threat?.type || 'unknown';
  const payload    = evt.threat?.raw  || '';
  const time       = new Date(evt.timestamp || evt.receivedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const meta       = attackMeta(threatType);

  item.innerHTML = `
    <div class="feed-item-top">
      <span class="feed-verdict">${evt.verdict || 'LOGGED'}</span>
      <span class="feed-type">${meta.icon} ${meta.label}</span>
      <span class="feed-time">${time}</span>
    </div>
    <div class="feed-detail">
      <span class="feed-path">${escHtml(evt.method || 'HTTP')} ${escHtml(evt.path || '/')}</span>
      <span class="feed-sep">•</span>
      <span class="feed-session">${escHtml(evt.session || evt.ip || 'unknown')}</span>
    </div>
    ${payload ? `<div class="feed-payload">${escHtml(payload.slice(0, 120))}</div>` : ''}
  `;

  item.addEventListener('click', () => {
    const attacker = allAttackers.find(a => a.session === (evt.session || evt.ip));
    if (attacker) selectAttacker(attacker);
  });

  feed.insertBefore(item, feed.firstChild);

  // Keep feed trim
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
  $('profileEmpty').classList.add('hidden');
  $('profileContent').classList.remove('hidden');
  updateBlockBtn(a);

  // ── Threat Score Ring ──
  const score   = a.threatScore || 0;
  const level   = a.threat || { label: 'LOW', color: '#10b981' };
  const circumf = 264;
  const offset  = circumf - (score / 100) * circumf;

  $('scoreValue').textContent = score;
  $('scoreLevel').textContent = level.label;
  $('scoreLevel').style.color = level.color;
  $('scoreCard').style.borderColor = level.color + '44';

  const ring = $('scoreRing');
  ring.style.strokeDashoffset = offset;
  ring.style.stroke           = level.color;

  // ── Identity ──
  // Show clean session name — strip "anon@" prefix for display
  const displayName = (a.session || '—').replace(/^anon@/, 'Guest ');
  $('pSession').textContent = displayName;
  $('pIP').textContent      = a.ip || '—';

  // Status — VPN, Honeypot, or Active
  const statusEl = $('pHoneypot');
  if (a.vpnDetected) {
    statusEl.innerHTML = `<span class="vpn-badge">🔄 VPN ROTATION DETECTED</span>`;
  } else if (a.inHoneypot) {
    statusEl.innerHTML = `<span class="hp-badge">🍯 IN HONEYPOT</span>`;
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
  await fetch('/api/block', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ ip: a.ip }) });
  showToast(`🚫 ${a.ip} blocked!`, 'red');
}

async function unblockCurrentIP() {
  const a = allAttackers.find(x => x.session === selectedSession);
  if (!a || !a.ip) return;
  await fetch('/api/unblock', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ ip: a.ip }) });
  showToast(`✅ ${a.ip} unblocked`, 'green');
}

async function blockCurrentFP() {
  const a = allAttackers.find(x => x.session === selectedSession);
  if (!a || !a.fpId) return;
  await fetch('/api/block-fp', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ fpId: a.fpId }) });
  showToast(`🔒 Device fingerprint blocked — VPN won't help!`, 'red');
}

async function unblockCurrentFP() {
  const a = allAttackers.find(x => x.session === selectedSession);
  if (!a || !a.fpId) return;
  await fetch('/api/unblock-fp', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ fpId: a.fpId }) });
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
    headers: { 'Content-Type': 'application/json' },
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
  await fetch('/api/reset', { method: 'POST' });
});

// ─── Boot ─────────────────────────────────────────────────────────────────────
fetchStats();
