/**
 * ShieldWatch UADR — Intelligence Collector
 * ─────────────────────────────────────────────────────────────────────────────
 * Receives threat events + browser fingerprints from NexaChat sensor.
 * Enriches with IP geolocation. Builds attacker profiles.
 * Serves the real-time red dashboard.
 *
 * Start: node collector.js
 * Port:  3002 (or SW_PORT env var)
 * ─────────────────────────────────────────────────────────────────────────────
 */

const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const path       = require('path');
const cors       = require('cors');
const crypto     = require('crypto');
const fs         = require('fs');

// ─── PIN + Session config (must be before io middleware) ──────────────────────
// PIN_CODE is mutable — it can be updated at runtime via the change-PIN endpoint.
// Source priority: logs/.pin (persisted change) → SW_PIN env var → default '2348'
let PIN_CODE    = process.env.SW_PIN || '2348';
const validTokens = new Set();

// Deterministic HMAC token — same PIN always produces the same token.
// This means auth survives server restarts without a database.
function computeHmacToken() {
  return crypto.createHmac('sha256', PIN_CODE + 'shieldwatch-uadr-secret')
               .digest('hex');
}

// ─── Encrypted Audit Log (AES-256-GCM + HMAC-SHA256 chain) ───────────────────
//
//  Every attack event is:
//    1. Serialised to JSON
//    2. Encrypted with AES-256-GCM (random 12-byte IV per entry)
//    3. Given an HMAC: mac = HMAC-SHA256( prevMac ‖ iv ‖ ciphertext+tag )
//
//  The HMAC chain means editing ANY past entry breaks every subsequent MAC.
//  Tampering is detected at read-time.
//
//  Key material: PBKDF2(PIN_CODE, randomSalt, 100 000, 32, sha256)
//  Salt is stored once in logs/.salt — lost salt means unreadable logs.
//
const LOG_DIR   = path.join(__dirname, 'logs');
const SALT_FILE = path.join(LOG_DIR, '.salt');

if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

// ── Load persisted PIN (overrides env var if the user changed it via dashboard) ──
const PIN_FILE = path.join(LOG_DIR, '.pin');
if (fs.existsSync(PIN_FILE)) {
  const saved = fs.readFileSync(PIN_FILE, 'utf8').trim();
  if (/^\d{4}$/.test(saved)) {
    PIN_CODE = saved;
    console.log('[PIN] Loaded saved PIN from logs/.pin');
  }
}

// Persistent salt — created once on first run, never regenerated
let _logSalt;
if (fs.existsSync(SALT_FILE)) {
  _logSalt = fs.readFileSync(SALT_FILE, 'utf8').trim();
} else {
  _logSalt = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SALT_FILE, _logSalt, 'utf8');
  console.log('[AuditLog] New salt created — logs/.salt  (keep this file safe!)');
}

// Derive AES-256 key — mutable so it can be re-derived after a PIN change
let LOG_KEY = crypto.pbkdf2Sync(PIN_CODE, _logSalt, 100_000, 32, 'sha256');

// In-memory chain tail per calendar day: date → { prevMac, seq }
const _chainState = new Map();

function _todayDate() { return new Date().toISOString().slice(0, 10); } // YYYY-MM-DD UTC

function _logFilePath(date) { return path.join(LOG_DIR, `${date}.log`); }

// Load the last line of an existing log file to restore the chain tail
function _getChainTail(date) {
  if (_chainState.has(date)) return _chainState.get(date);
  const file = _logFilePath(date);
  if (!fs.existsSync(file)) {
    const s = { prevMac: 'GENESIS', seq: 0 };
    _chainState.set(date, s);
    return s;
  }
  const lines = fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean);
  if (!lines.length) {
    const s = { prevMac: 'GENESIS', seq: 0 };
    _chainState.set(date, s);
    return s;
  }
  try {
    const last = JSON.parse(lines[lines.length - 1]);
    const s    = { prevMac: last.mac, seq: last.seq };
    _chainState.set(date, s);
    return s;
  } catch {
    const s = { prevMac: 'GENESIS', seq: 0 };
    _chainState.set(date, s);
    return s;
  }
}

// Encrypt + chain + append one attack event to today's log file
function writeLogEntry(event) {
  try {
    const date  = _todayDate();
    const state = _getChainTail(date);

    const iv        = crypto.randomBytes(12);
    const cipher    = crypto.createCipheriv('aes-256-gcm', LOG_KEY, iv);
    const plaintext = JSON.stringify(event);
    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag   = cipher.getAuthTag();               // 16-byte GCM tag
    const data      = Buffer.concat([encrypted, authTag]); // ciphertext ‖ tag

    state.seq += 1;

    // HMAC chain: each MAC covers the previous MAC + this entry's iv + ciphertext+tag
    const mac = crypto.createHmac('sha256', LOG_KEY)
      .update(state.prevMac + iv.toString('hex') + data.toString('hex'))
      .digest('hex');

    fs.appendFileSync(
      _logFilePath(date),
      JSON.stringify({ seq: state.seq, iv: iv.toString('hex'), data: data.toString('hex'), mac }) + '\n',
      'utf8'
    );

    state.prevMac = mac;
    _chainState.set(date, state);
  } catch (err) {
    console.error('[AuditLog] Write failed:', err.message);
  }
}

// Decrypt a day's log file and verify the HMAC chain entry by entry
function readLogFile(date) {
  const file = _logFilePath(date);
  if (!fs.existsSync(file)) return { events: [], intact: true, count: 0 };

  const lines   = fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean);
  const events  = [];
  let   intact  = true;
  let   prevMac = 'GENESIS';

  for (const line of lines) {
    try {
      const { seq, iv, data: dataHex, mac } = JSON.parse(line);

      // Verify HMAC chain
      const expected = crypto.createHmac('sha256', LOG_KEY)
        .update(prevMac + iv + dataHex)
        .digest('hex');
      if (expected !== mac) {
        intact = false;
        events.push({ _tampered: true, seq, note: `Chain broken at entry ${seq}` });
        prevMac = mac;
        continue;
      }

      // Decrypt AES-256-GCM
      const dataBuf = Buffer.from(dataHex, 'hex');
      const dec     = crypto.createDecipheriv('aes-256-gcm', LOG_KEY, Buffer.from(iv, 'hex'));
      dec.setAuthTag(dataBuf.slice(-16));
      const plain = Buffer.concat([dec.update(dataBuf.slice(0, -16)), dec.final()]).toString('utf8');

      events.push(JSON.parse(plain));
      prevMac = mac;
    } catch (err) {
      intact = false;
      events.push({ _error: true, note: err.message });
    }
  }

  return { events, intact, count: events.filter(e => !e._tampered && !e._error).length };
}

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

function requireAuth(req, res, next) {
  const token = req.headers['x-sw-token'];
  if (!token) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  // Accept either: active session token OR the deterministic HMAC token
  if (validTokens.has(token) || token === computeHmacToken()) return next();
  return res.status(401).json({ ok: false, error: 'Session expired — re-authenticate' });
}

// Socket.io — no connection-level auth needed.
// The socket is read-only (pushes events to the dashboard).
// All write actions (block/unblock/reset) are protected by requireAuth on REST routes.

const PORT = process.env.PORT || process.env.SW_PORT || 3002;

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── In-Memory Store ──────────────────────────────────────────────────────────
const events    = [];           // all threat events, newest first
const attackers = new Map();    // sessionKey → attacker profile
const geoCache  = new Map();    // ip → geo data
const blockedIPs          = new Set();   // manually blocked IPs
const blockedFingerprints = new Set();   // blocked browser fingerprint hashes
const fingerprintIndex    = new Map();   // fpId → { sessionKey, ip } (for VPN detection)
let   lastNexaChatAt      = null;        // timestamp of last contact from NexaChat sensor

// ─── UA Parser ────────────────────────────────────────────────────────────────
function parseUA(ua) {
  if (!ua) return { browser: 'Unknown', os: 'Unknown', device: 'Desktop' };

  let browser = 'Unknown', os = 'Unknown', device = 'Desktop';

  // Browser
  if (/Edg\/([0-9]+)/.test(ua))                           browser = `Edge ${RegExp.$1}`;
  else if (/OPR\/([0-9]+)/.test(ua))                      browser = `Opera ${RegExp.$1}`;
  else if (/Chrome\/([0-9]+)/.test(ua) && !/Chromium/.test(ua)) browser = `Chrome ${RegExp.$1}`;
  else if (/Firefox\/([0-9]+)/.test(ua))                  browser = `Firefox ${RegExp.$1}`;
  else if (/Version\/([0-9]+).+Safari/.test(ua))          browser = `Safari ${RegExp.$1}`;
  else if (/curl\//.test(ua))                              browser = 'curl (CLI)';
  else if (/python-requests/.test(ua))                     browser = 'Python Requests';
  else if (/sqlmap/.test(ua))                              browser = '⚠ sqlmap';

  // OS
  if (/Windows NT 10|Windows NT 11/.test(ua))             os = 'Windows 11/10';
  else if (/Windows NT 6\.3/.test(ua))                    os = 'Windows 8.1';
  else if (/Windows NT 6\.1/.test(ua))                    os = 'Windows 7';
  else if (/Mac OS X ([0-9_]+)/.test(ua))                 os = `macOS ${RegExp.$1.replace(/_/g,'.')}`;
  else if (/Android ([0-9.]+)/.test(ua))                  { os = `Android ${RegExp.$1}`; device = 'Mobile'; }
  else if (/iPhone|iPad/.test(ua))                        { os = 'iOS'; device = 'Mobile'; }
  else if (/Linux/.test(ua))                              os = 'Linux';

  return { browser, os, device };
}

// ─── IP Geolocation (ipapi.co, free tier) ────────────────────────────────────
async function getGeoInfo(ip) {
  // Clean IP (strip port / IPv6 prefix)
  const cleanIP = ip.replace(/^::ffff:/, '').split(':')[0];

  if (geoCache.has(cleanIP)) return geoCache.get(cleanIP);

  // Local / private IPs — demo mode
  const isLocal =
    cleanIP === '127.0.0.1' || cleanIP === '::1' ||
    /^192\.168\./.test(cleanIP) || /^10\./.test(cleanIP) ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(cleanIP);

  if (isLocal) {
    const geo = {
      ip: cleanIP, city: 'Local Network', region: 'Demo Mode',
      country_name: 'Pakistan', country_code: 'PK',
      org: 'NexaCorp Internal', timezone: 'Asia/Karachi',
      latitude: 33.6844, longitude: 73.0479, is_local: true
    };
    geoCache.set(cleanIP, geo);
    return geo;
  }

  try {
    const ctrl = new AbortController();
    const tid  = setTimeout(() => ctrl.abort(), 3000);
    const res  = await fetch(`https://ipapi.co/${cleanIP}/json/`, { signal: ctrl.signal });
    clearTimeout(tid);
    const data = await res.json();
    geoCache.set(cleanIP, data);
    return data;
  } catch {
    const fallback = { ip: cleanIP, city: 'Unknown', country_name: 'Unknown', org: 'Unknown' };
    geoCache.set(cleanIP, fallback);
    return fallback;
  }
}

// ─── Threat Scoring ───────────────────────────────────────────────────────────
function calcThreatScore(profile) {
  const c = profile.attackCounts || {};
  let s = 0;
  s += (c.sqli         || 0) * 25;
  s += (c.xss          || 0) * 20;
  s += (c.pathTraversal|| 0) * 20;
  s += (c.cmdInjection || 0) * 30;
  s += (c.honeypot     || 0) * 15;
  s += (c.ddos         || 0) *  8;
  s += (c.csrf           || 0) * 18;
  s += (c.bruteforce     || 0) * 10;
  s += (c.idor           || 0) * 15;
  s += (c.sessionFixation|| 0) * 20;
  return Math.min(100, s);
}

function threatLevel(score) {
  if (score >= 75) return { label: 'CRITICAL', color: '#ef4444' };
  if (score >= 50) return { label: 'HIGH',     color: '#f97316' };
  if (score >= 25) return { label: 'MEDIUM',   color: '#f59e0b' };
  return                  { label: 'LOW',       color: '#10b981' };
}

// ─── Only real attackers (at least one confirmed attack event) ────────────────
function realAttackers() {
  return Array.from(attackers.values()).filter(p => {
    const total = Object.values(p.attackCounts || {}).reduce((s, n) => s + n, 0);
    return total > 0;
  });
}

// ─── Upsert Attacker Profile ──────────────────────────────────────────────────
function upsertProfile(sessionKey, ip, ua, geo, extraData = {}) {
  if (!attackers.has(sessionKey)) {
    attackers.set(sessionKey, {
      session:      sessionKey,
      ip,
      geo,
      ua:           parseUA(ua),
      rawUA:        ua || '',
      firstSeen:    new Date().toISOString(),
      lastSeen:     new Date().toISOString(),
      attackCounts: {},
      recentEvents: [],
      fingerprint:  null,
      inHoneypot:   false,
      threatScore:  0,
      threat:       threatLevel(0),
    });
  }

  const p = attackers.get(sessionKey);
  p.lastSeen = new Date().toISOString();
  if (ip)  p.ip  = ip;
  if (geo) p.geo = geo;
  if (ua)  p.rawUA = ua;
  Object.assign(p, extraData);

  return p;
}

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/event  — receive threat event from NexaChat sensor
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/event', async (req, res) => {
  const evt = req.body;
  if (!evt || !evt.id) return res.json({ ok: false, error: 'Missing event id' });

  // Enrich with geo
  evt.geo     = await getGeoInfo(evt.ip || '127.0.0.1');
  evt.uaParsed = parseUA(evt.ua);
  evt.receivedAt = new Date().toISOString();

  // Store (cap at 500)
  events.unshift(evt);
  if (events.length > 500) events.splice(500);

  // ── Session key: use username if logged in, otherwise "anon@IP" so two
  //    anonymous attackers with different IPs get SEPARATE profiles ──────────
  const rawSession = evt.session || '';
  const sessionKey = (rawSession && rawSession !== 'anonymous')
    ? rawSession
    : `anon@${evt.ip || 'unknown'}`;

  const profile = upsertProfile(sessionKey, evt.ip, evt.ua, evt.geo);

  const tType = evt.threat?.type || 'unknown';
  profile.attackCounts[tType] = (profile.attackCounts[tType] || 0) + 1;
  profile.recentEvents.unshift(evt);
  if (profile.recentEvents.length > 20) profile.recentEvents.splice(20);

  if (evt.verdict === 'DECOY' || tType === 'honeypot') profile.inHoneypot = true;

  profile.threatScore = calcThreatScore(profile);
  profile.threat      = threatLevel(profile.threatScore);

  console.log(`[Event] ${tType.toUpperCase()} | ${evt.verdict} | ${sessionKey} | score:${profile.threatScore}`);

  // Persist to encrypted tamper-evident audit log
  writeLogEntry(evt);

  // Mark NexaChat as active
  const wasConnected = lastNexaChatAt && (Date.now() - lastNexaChatAt) < 300_000;
  lastNexaChatAt = Date.now();
  if (!wasConnected) io.emit('nexachat_status', true); // first contact after silence

  // Broadcast
  io.emit('new_event',       evt);
  io.emit('attackers_update', realAttackers());

  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/fingerprint  — receive browser fingerprint from sw-beacon.js
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/fingerprint', async (req, res) => {
  const { session, fingerprint, ip } = req.body;
  if (!session || !fingerprint) return res.json({ ok: false });

  // Build same session key logic as /api/event
  const sessionKey = (session && session !== 'anonymous')
    ? session
    : `anon@${ip || 'unknown'}`;

  const geo     = await getGeoInfo(ip || '127.0.0.1');

  // ── Device ID — hardware-level signals survive browser/VPN changes ────────
  // Priority: deviceId (Mac hardware hash) → canvasHash → canvas → gpu fallback
  const fpId = fingerprint.deviceId
            || fingerprint.canvasHash
            || fingerprint.canvas
            || fingerprint.gpu
            || null;

  // ── VPN Detection ─────────────────────────────────────────────────────────
  // Real VPN rotation = same device fingerprint, DIFFERENT IP address.
  // A session key change alone (e.g. login turning anon→username) is NOT VPN.
  let vpnDetected = false;
  if (fpId) {
    const prev = fingerprintIndex.get(fpId);  // { sessionKey, ip }

    if (prev && prev.ip && prev.ip !== ip) {
      // Same physical device, genuinely different IP → VPN rotation
      vpnDetected = true;
      console.log(`[VPN] 🔄 Device ${fpId.slice(0,8)}… IP changed ${prev.ip} → ${ip} (session: "${prev.sessionKey}" → "${sessionKey}")`);

      // Merge attack history from old profile into new profile
      const oldProfile = attackers.get(prev.sessionKey);
      if (oldProfile) {
        const newProfile = upsertProfile(sessionKey, ip, fingerprint.ua, geo);
        // Merge attack counts
        for (const [type, count] of Object.entries(oldProfile.attackCounts || {})) {
          newProfile.attackCounts[type] = (newProfile.attackCounts[type] || 0) + count;
        }
        // Build deduped IP history — no duplicates, no same-IP false repeats
        const prevHistory = oldProfile.vpnHistory || [oldProfile.ip];
        const allIPs      = [...new Set([...prevHistory, ip])];
        newProfile.vpnHistory  = allIPs;
        newProfile.vpnDetected = true;
        newProfile.threatScore = calcThreatScore(newProfile);
        newProfile.threat      = threatLevel(newProfile.threatScore);
      }
    }

    // Always update index with current session + IP so next check is accurate
    fingerprintIndex.set(fpId, { sessionKey, ip });
  }

  const profile = upsertProfile(sessionKey, ip, fingerprint.ua, geo, {
    fingerprint,
    fpId,
    vpnDetected,
  });

  // Flag if fingerprint is in blocklist
  if (fpId && blockedFingerprints.has(fpId)) {
    profile.fpBlocked = true;
  }

  console.log(`[Fingerprint] session:${sessionKey} | ${fingerprint.os || '?'} | ${fingerprint.screen || '?'}${vpnDetected ? ' | ⚠️ VPN ROTATION' : ''}`);

  // Mark NexaChat as active
  const wasConnectedFP = lastNexaChatAt && (Date.now() - lastNexaChatAt) < 300_000;
  lastNexaChatAt = Date.now();
  if (!wasConnectedFP) io.emit('nexachat_status', true);

  // Only push attacker update if this session is a known attacker (score > 0)
  if (realAttackers().find(p => p.session === sessionKey)) {
    io.emit('attackers_update', realAttackers());
  }
  res.json({ ok: true, fpId, vpnDetected });
});

// ─────────────────────────────────────────────────────────────────────────────
// REST — dashboard data (all protected — dashboard must send x-sw-token header)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/events',   (_req, res) => res.json(events.slice(0, 100)));
app.get('/api/attackers',(_req, res) => res.json(realAttackers()));

app.get('/api/stats', (_req, res) => {
  const byType = {};
  events.forEach(e => {
    const t = e.threat?.type || 'unknown';
    byType[t] = (byType[t] || 0) + 1;
  });
  res.json({
    total:     events.length,
    blocked:   events.filter(e => e.verdict === 'BLOCKED').length,
    decoys:    events.filter(e => e.verdict === 'DECOY').length,
    logged:    events.filter(e => e.verdict === 'LOGGED').length,
    attackers: realAttackers().length,
    byType
  });
});

app.get('/ping', (_req, res) => {
  res.json({ status: 'online', app: 'shieldwatch-collector', events: events.length });
});

// ─────────────────────────────────────────────────────────────────────────────
// IP BLOCKING — dashboard-controlled blocklist
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/blocked',    (_req, res) => res.json(Array.from(blockedIPs)));
app.get('/api/blocked-fp', (_req, res) => res.json(Array.from(blockedFingerprints)));

app.post('/api/block-fp', requireAuth, (req, res) => {
  const { fpId } = req.body;
  if (!fpId) return res.json({ ok: false, error: 'fpId required' });
  blockedFingerprints.add(fpId);
  console.log(`[Block-FP] 🔒 Fingerprint blocked: ${fpId.slice(0,12)}… | total: ${blockedFingerprints.size}`);
  io.emit('blocked_fp_update', Array.from(blockedFingerprints));
  res.json({ ok: true, blocked: fpId });
});

app.post('/api/unblock-fp', requireAuth, (req, res) => {
  const { fpId } = req.body;
  if (!fpId) return res.json({ ok: false, error: 'fpId required' });
  blockedFingerprints.delete(fpId);
  console.log(`[Unblock-FP] ✅ Fingerprint unblocked: ${fpId.slice(0,12)}…`);
  io.emit('blocked_fp_update', Array.from(blockedFingerprints));
  res.json({ ok: true, unblocked: fpId });
});

app.post('/api/block', requireAuth, (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.json({ ok: false, error: 'ip required' });
  const clean = ip.replace(/^::ffff:/, '').split(':')[0].trim();
  blockedIPs.add(clean);
  console.log(`[Block] 🚫 IP blocked: ${clean} | total blocked: ${blockedIPs.size}`);
  io.emit('blocked_update', Array.from(blockedIPs));
  res.json({ ok: true, blocked: clean, total: blockedIPs.size });
});

app.post('/api/unblock', requireAuth, (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.json({ ok: false, error: 'ip required' });
  const clean = ip.replace(/^::ffff:/, '').split(':')[0].trim();
  blockedIPs.delete(clean);
  console.log(`[Unblock] ✅ IP unblocked: ${clean}`);
  io.emit('blocked_update', Array.from(blockedIPs));
  res.json({ ok: true, unblocked: clean });
});

// ─── PIN Authentication ───────────────────────────────────────────────────────
const pinAttempts = new Map(); // ip → { count, lockedUntil }

app.post('/api/auth/pin', (req, res) => {
  const raw   = req.ip || req.socket?.remoteAddress || 'unknown';
  const ip    = raw.replace(/^::ffff:/, '');
  const now   = Date.now();
  const rec   = pinAttempts.get(ip) || { count: 0, lockedUntil: 0 };

  if (rec.lockedUntil > now) {
    const secsLeft = Math.ceil((rec.lockedUntil - now) / 1000);
    return res.status(429).json({ ok: false, locked: true, secsLeft });
  }

  if (String(req.body?.pin) === String(PIN_CODE)) {
    pinAttempts.delete(ip);
    const token = computeHmacToken(); // deterministic — survives server restarts
    validTokens.add(token);
    console.log(`[PIN] ✅ Dashboard unlocked from ${ip}`);
    return res.json({ ok: true, token });
  }

  // Wrong PIN — track attempts
  rec.count += 1;
  const attemptsLeft = Math.max(0, 5 - rec.count);
  if (rec.count >= 5) {
    rec.lockedUntil = now + 60_000;
    rec.count       = 0;
    console.log(`[PIN] 🔒 Brute-force lockout triggered for ${ip}`);
  }
  pinAttempts.set(ip, rec);
  console.log(`[PIN] ❌ Wrong PIN from ${ip} | attempts left: ${attemptsLeft}`);
  return res.status(401).json({ ok: false, locked: false, attemptsLeft });
});

// ─── Logout ───────────────────────────────────────────────────────────────────
app.post('/api/auth/logout', (req, res) => {
  const token = req.headers['x-sw-token'];
  if (token) {
    validTokens.delete(token);
    console.log('[Auth] Dashboard session terminated');
  }
  res.json({ ok: true });
});

// ─── Change PIN ───────────────────────────────────────────────────────────────
// Protected: must be logged in (requireAuth) AND know the current PIN.
// After a successful change:
//   • New PIN saved to logs/.pin (survives restarts)
//   • LOG_KEY re-derived for future log entries
//   • All active sessions invalidated → everyone must re-authenticate
//   • Chain state cache cleared (it held offsets computed under the old key)
//
// ⚠ Existing log files stay encrypted under the old key — they are not lost,
//   but the History tab cannot decrypt them with the new key. New entries from
//   this point forward use the new key.
app.post('/api/auth/change-pin', requireAuth, (req, res) => {
  const { currentPin, newPin, confirmPin } = req.body || {};

  // 1 — Verify the caller knows the current PIN
  if (String(currentPin) !== String(PIN_CODE)) {
    console.log('[PIN-Change] ❌ Wrong current PIN supplied');
    return res.status(401).json({ ok: false, error: 'Current PIN is incorrect' });
  }

  // 2 — Validate format: exactly 4 digits
  if (!/^\d{4}$/.test(String(newPin))) {
    return res.json({ ok: false, error: 'New PIN must be exactly 4 digits (0–9)' });
  }

  // 3 — Must be a different PIN
  if (String(newPin) === String(PIN_CODE)) {
    return res.json({ ok: false, error: 'New PIN must be different from the current PIN' });
  }

  // 4 — Confirmation must match
  if (String(newPin) !== String(confirmPin)) {
    return res.json({ ok: false, error: 'PINs do not match — please re-enter' });
  }

  // ── Apply the change ───────────────────────────────────────────────────────
  const oldPin = PIN_CODE;

  // Persist new PIN to file
  fs.writeFileSync(PIN_FILE, String(newPin), 'utf8');

  // Update in-memory PIN
  PIN_CODE = String(newPin);

  // Re-derive the log encryption key under the new PIN
  LOG_KEY = crypto.pbkdf2Sync(PIN_CODE, _logSalt, 100_000, 32, 'sha256');

  // Clear chain state cache — offsets were computed with the old key
  _chainState.clear();

  // Invalidate ALL active sessions — every connected client must re-authenticate
  validTokens.clear();

  console.log(`[PIN-Change] ✅ PIN changed (${oldPin} → ****) — all sessions invalidated`);

  res.json({
    ok:      true,
    message: 'PIN changed. All sessions have been logged out — please re-authenticate with your new PIN.',
    warning: 'Log files created before this change were encrypted with the previous PIN and cannot be viewed in the History tab until you revert to the old PIN.',
  });
});

// ─── Reset (demo convenience) ─────────────────────────────────────────────────
app.post('/api/reset', requireAuth, (_req, res) => {
  events.splice(0);
  attackers.clear();
  geoCache.clear();
  blockedIPs.clear();
  blockedFingerprints.clear();
  fingerprintIndex.clear();
  io.emit('reset');
  io.emit('blocked_update', []);
  io.emit('blocked_fp_update', []);
  console.log('[Reset] All data cleared');
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// AUDIT LOG — History API (auth required)
// ─────────────────────────────────────────────────────────────────────────────

// List all days that have log files, newest first
app.get('/api/history/dates', requireAuth, (_req, res) => {
  try {
    const dates = fs.readdirSync(LOG_DIR)
      .filter(f => /^\d{4}-\d{2}-\d{2}\.log$/.test(f))
      .map(f => f.replace('.log', ''))
      .sort()
      .reverse();
    res.json({ ok: true, dates });
  } catch (err) {
    res.json({ ok: false, error: err.message, dates: [] });
  }
});

// Verify HMAC chains across ALL log files — must come BEFORE /:date or Express
// will match the literal string "verify" as a date parameter.
app.get('/api/history/verify', requireAuth, (_req, res) => {
  try {
    const files   = fs.readdirSync(LOG_DIR)
      .filter(f => /^\d{4}-\d{2}-\d{2}\.log$/.test(f))
      .map(f => f.replace('.log', ''));
    const summary = files.map(date => {
      const { count, intact } = readLogFile(date);
      return { date, count, intact };
    });
    res.json({ ok: true, allIntact: summary.every(s => s.intact), files: summary });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

// Decrypt and return one day's events + chain-integrity flag
app.get('/api/history/:date', requireAuth, (req, res) => {
  const { date } = req.params;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date))
    return res.json({ ok: false, error: 'Invalid date — expected YYYY-MM-DD' });
  const result = readLogFile(date);
  res.json({ ok: true, date, ...result });
});

// ─── Socket.io ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log('[Dashboard] Client connected:', socket.id);
  // Send current state immediately
  socket.emit('init', {
    events:        events.slice(0, 50),
    attackers:     realAttackers(),
    blocked:       Array.from(blockedIPs),
    blockedFPs:    Array.from(blockedFingerprints),
    lastNexaChatAt,
  });
  socket.on('disconnect', () => console.log('[Dashboard] Client disconnected:', socket.id));
});

// ─── Start ────────────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  const logFileCount = fs.readdirSync(LOG_DIR).filter(f => f.endsWith('.log')).length;
  console.log(`\n🛡️  ShieldWatch Collector  →  http://localhost:${PORT}`);
  console.log(`    Dashboard              →  http://localhost:${PORT}/`);
  console.log(`    Events API             →  POST http://localhost:${PORT}/api/event`);
  console.log(`    Fingerprint API        →  POST http://localhost:${PORT}/api/fingerprint`);
  console.log(`    Audit Log              →  ./logs/  (AES-256-GCM · HMAC chain · ${logFileCount} day${logFileCount !== 1 ? 's' : ''} stored)\n`);
});
