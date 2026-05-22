/**
 * ShieldWatch Sensor — Demo App
 *
 * This is a completely standalone Express app — works independently of any other project.
 * It shows how any developer can protect their own app with ShieldWatch in minutes.
 *
 * HOW TO RUN:
 *   cd /path/to/shieldwatch-sensor/demo
 *   npm init -y
 *   npm install express
 *   node app.js
 *
 * Then test it:
 *   curl http://localhost:4000/api/data
 *   curl "http://localhost:4000/api/search?q=' OR 1=1--"   ← SQLi attempt (gets blocked)
 *   curl "http://localhost:4000/api/search?q=<script>alert(1)</script>"  ← XSS (blocked)
 *   curl "http://localhost:4000/api/file?path=../../etc/passwd"           ← Path traversal (blocked)
 */

'use strict';

const express     = require('express');
const ShieldWatch = require('../index');            // In real usage: require('shieldwatch-sensor')

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── Mount ShieldWatch — this is the only security code you write ─────────────
const sw = ShieldWatch.create({
  collectorUrl: process.env.SW_CEREBRO_URL || 'http://localhost:3002',
  appId:        'demo-app',
  logOnly:      process.env.LOG_ONLY === 'true',   // set LOG_ONLY=true to detect without blocking

  // Protect the profile update endpoint from cross-site form submissions
  csrfProtectedPaths: ['/api/profile/update'],

  // Flag anyone who touches internal session manipulation routes
  sessionFixationPaths: ['/api/session/id', '/api/session/fix'],

  // Honeypots — probing these marks the IP as a scanner
  honeypotPaths: ['/admin', '/wp-admin', '/.env', '/.git/config', '/phpmyadmin'],

  // Custom IDOR logic: block if URL param :id doesn't match the logged-in user
  idorChecker: (req) => {
    const sessionUser = req.headers['x-user-id'];    // simplified — real apps use sessions
    const paramId     = req.params?.id;
    if (sessionUser && paramId && String(sessionUser) !== String(paramId)) {
      return { type: 'idor', matched: 'accessing another user resource', raw: `session=${sessionUser} param=${paramId}` };
    }
    return null;
  },

  // DDoS: block an IP that sends > 30 API requests in 10 seconds
  ddosThreshold: 30,
  ddosWindowMs:  10_000,

  // Brute force: block after 5 failed logins within 60 seconds
  bruteForceThreshold: 5,
});

app.use(sw.middleware);     // ← This one line protects EVERY route below

// ─── Your normal application routes — completely unchanged ────────────────────

app.get('/api/data', (req, res) => {
  res.json({ ok: true, data: 'This is protected data.', shieldwatch: 'active' });
});

// Vulnerable-looking search (on purpose — ShieldWatch catches the payload before it runs)
app.get('/api/search', (req, res) => {
  const query = req.query.q || '';
  // In a real app this might be: db.query(`SELECT * FROM items WHERE name LIKE '%${query}%'`)
  // ShieldWatch would have blocked SQLi/XSS BEFORE this line runs.
  res.json({ ok: true, results: [`Result for: ${query}`] });
});

// File endpoint — also intentionally vulnerable; ShieldWatch blocks path traversal
app.get('/api/file', (req, res) => {
  const filePath = req.query.path || '';
  res.json({ ok: true, requested: filePath, note: 'Path traversal would have been blocked.' });
});

// Login with brute-force tracking
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const DEMO_USER = { username: 'admin', password: 'password123' };

  if (username === DEMO_USER.username && password === DEMO_USER.password) {
    return res.json({ ok: true, message: 'Logged in!' });
  }

  // Tell ShieldWatch this login failed — it tracks the IP and auto-blocks at threshold
  const blocked = sw.trackLoginFailure(req);
  if (blocked) {
    return res.status(429).json({ ok: false, error: 'Too many failed attempts. Blocked by ShieldWatch.' });
  }

  return res.json({ ok: false, error: 'Invalid credentials.' });
});

// Profile update — CSRF-protected (form submissions from other origins are blocked)
app.post('/api/profile/update', (req, res) => {
  res.json({ ok: true, message: 'Profile updated (JSON requests only).' });
});

// User by ID — IDOR-protected via idorChecker above
app.get('/api/user/:id', (req, res) => {
  res.json({ ok: true, userId: req.params.id });
});

// Fingerprint endpoint — receives browser fingerprint from client-side beacon
app.post('/api/sw-fingerprint', (req, res) => {
  sw.submitFingerprint(req.body, req);
  res.json({ ok: true });
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`\n🚀 Demo app running on http://localhost:${PORT}`);
  console.log('   ShieldWatch is protecting every route above.\n');
  console.log('Try these attack payloads (they will be blocked):');
  console.log(`  curl "http://localhost:${PORT}/api/search?q=' OR 1=1--"`);
  console.log(`  curl "http://localhost:${PORT}/api/search?q=<script>alert(1)</script>"`);
  console.log(`  curl "http://localhost:${PORT}/api/file?path=../../etc/passwd"`);
  console.log(`  curl http://localhost:${PORT}/admin  ← honeypot\n`);
});
