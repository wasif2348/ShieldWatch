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

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

const PORT = process.env.SW_PORT || 3002;

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

  // Broadcast
  io.emit('new_event',       evt);
  io.emit('attackers_update', Array.from(attackers.values()));

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

  io.emit('attackers_update', Array.from(attackers.values()));
  res.json({ ok: true, fpId, vpnDetected });
});

// ─────────────────────────────────────────────────────────────────────────────
// REST — dashboard data
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/events',   (_req, res) => res.json(events.slice(0, 100)));
app.get('/api/attackers',(_req, res) => res.json(Array.from(attackers.values())));

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
    attackers: attackers.size,
    byType
  });
});

app.get('/ping', (_req, res) => {
  res.json({ status: 'online', app: 'shieldwatch-collector', events: events.length });
});

// ─────────────────────────────────────────────────────────────────────────────
// IP BLOCKING — dashboard-controlled blocklist
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/blocked', (_req, res) => {
  res.json(Array.from(blockedIPs));
});

app.get('/api/blocked-fp', (_req, res) => {
  res.json(Array.from(blockedFingerprints));
});

app.post('/api/block-fp', (req, res) => {
  const { fpId } = req.body;
  if (!fpId) return res.json({ ok: false, error: 'fpId required' });
  blockedFingerprints.add(fpId);
  console.log(`[Block-FP] 🔒 Fingerprint blocked: ${fpId.slice(0,12)}… | total: ${blockedFingerprints.size}`);
  io.emit('blocked_fp_update', Array.from(blockedFingerprints));
  res.json({ ok: true, blocked: fpId });
});

app.post('/api/unblock-fp', (req, res) => {
  const { fpId } = req.body;
  if (!fpId) return res.json({ ok: false, error: 'fpId required' });
  blockedFingerprints.delete(fpId);
  console.log(`[Unblock-FP] ✅ Fingerprint unblocked: ${fpId.slice(0,12)}…`);
  io.emit('blocked_fp_update', Array.from(blockedFingerprints));
  res.json({ ok: true, unblocked: fpId });
});

app.post('/api/block', (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.json({ ok: false, error: 'ip required' });
  const clean = ip.replace(/^::ffff:/, '').split(':')[0].trim();
  blockedIPs.add(clean);
  console.log(`[Block] 🚫 IP blocked: ${clean} | total blocked: ${blockedIPs.size}`);
  io.emit('blocked_update', Array.from(blockedIPs));
  res.json({ ok: true, blocked: clean, total: blockedIPs.size });
});

app.post('/api/unblock', (req, res) => {
  const { ip } = req.body;
  if (!ip) return res.json({ ok: false, error: 'ip required' });
  const clean = ip.replace(/^::ffff:/, '').split(':')[0].trim();
  blockedIPs.delete(clean);
  console.log(`[Unblock] ✅ IP unblocked: ${clean}`);
  io.emit('blocked_update', Array.from(blockedIPs));
  res.json({ ok: true, unblocked: clean });
});

// ─── Reset (demo convenience) ─────────────────────────────────────────────────
app.post('/api/reset', (_req, res) => {
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

// ─── Socket.io ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log('[Dashboard] Client connected:', socket.id);
  // Send current state immediately
  socket.emit('init', {
    events:      events.slice(0, 50),
    attackers:   Array.from(attackers.values()),
    blocked:     Array.from(blockedIPs),
    blockedFPs:  Array.from(blockedFingerprints),
  });
  socket.on('disconnect', () => console.log('[Dashboard] Client disconnected:', socket.id));
});

// ─── Start ────────────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🛡️  ShieldWatch Collector  →  http://localhost:${PORT}`);
  console.log(`    Dashboard              →  http://localhost:${PORT}/`);
  console.log(`    Events API             →  POST http://localhost:${PORT}/api/event`);
  console.log(`    Fingerprint API        →  POST http://localhost:${PORT}/api/fingerprint\n`);
});
