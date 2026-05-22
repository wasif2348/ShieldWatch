# ShieldWatch Sensor

**Runtime Application Self-Protection (RASP) for Node.js / Express**

ShieldWatch Sensor is a plug-and-play security middleware that detects and blocks 11 categories of web attacks in real time. Drop it into any Express app in under a minute — no changes to your existing routes required.

All detected events are reported live to the **Cerebro dashboard**, ShieldWatch's real-time threat intelligence backend, showing the attacker's IP, browser fingerprint, exact payload, and block verdict.

> Works on any Node.js / Express application — Windows, macOS, Linux.

---

## Table of Contents

- [What It Protects Against](#what-it-protects-against)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Full Configuration](#full-configuration)
- [Environment Variables](#environment-variables)
- [Advanced Hooks](#advanced-hooks)
- [Adding to an Existing App](#adding-to-an-existing-app)
- [Compatibility](#compatibility)
- [Architecture](#architecture)
- [FAQ](#faq)

---

## What It Protects Against

| # | Threat | Detection Method |
|---|--------|-----------------|
| 1 | **SQL Injection** | Regex pattern scan on all query params, body fields, and URL params |
| 2 | **Cross-Site Scripting (XSS)** | Detects `<script>`, `onerror=`, `javascript:`, `eval()`, `document.cookie`, SVG events |
| 3 | **Path Traversal** | Catches `../`, `%2e%2e`, null-byte tricks, `/etc/passwd`, `/proc/self` |
| 4 | **Command Injection** | Detects shell metacharacters + dangerous binaries (`ls`, `cat`, `curl`, `bash`, `nc`) |
| 5 | **CSRF** | Blocks form-encoded POST/PUT/DELETE to your specified protected endpoints |
| 6 | **IDOR** | Pluggable ownership checker — you define the logic, sensor enforces it |
| 7 | **Session Fixation** | Blocks access to endpoints that expose or accept raw session IDs |
| 8 | **DDoS / Flood** | Sliding-window rate limiter per IP on API endpoints |
| 9 | **Brute Force** | Tracks failed logins per IP, auto-blocks at configurable threshold |
| 10 | **SSRF** | Detects internal IP ranges (`127.x`, `10.x`, `192.168.x`, `169.254.x`) and dangerous schemes |
| 11 | **CRLF Injection** | Catches `%0d%0a` and header injection attempts |

All pattern matching runs through **double URL-decode** and **SQL comment stripping** to catch encoded and obfuscated payloads.

---

## Quick Start

### Step 1 — Install

```bash
npm install shieldwatch-sensor
```

> **Local install from folder (offline / development):**
> ```bash
> npm install file:../shieldwatch-sensor
> ```

### Step 2 — Add 3 Lines to Your App

```javascript
const ShieldWatch = require('shieldwatch-sensor');
const sw = ShieldWatch.create({ collectorUrl: 'http://localhost:3002', appId: 'my-app' });
app.use(sw.middleware);
```

### Step 3 — Start Your App

```bash
node server.js
```

You will see:

```
[ShieldWatch] ✅ Sensor initialized — app: "my-app" | collector: http://localhost:3002 | mode: BLOCKING
```

That's it. Every route below `app.use(sw.middleware)` is now protected.

---

## How It Works

Every incoming HTTP request passes through the sensor **before it reaches any of your routes**. The sensor runs these checks in order:

```
Incoming HTTP Request
        │
        ▼
┌─────────────────────────────────────────────────────┐
│                 ShieldWatch Sensor                  │
│                                                     │
│  1.  Check blocked IP list    (synced from Cerebro) │
│  2.  Check blocked fingerprint list                 │
│  3.  IDOR check               (your custom logic)   │
│  4.  Session fixation path check                    │
│  5.  CSRF origin/content-type check                 │
│  6.  DDoS / flood rate limiter                      │
│  7.  Honeypot path detector                         │
│  8.  Pattern scan:                                  │
│        SQLi · XSS · Path Traversal                  │
│        Command Injection · SSRF · CRLF              │
└─────────────────────────────────────────────────────┘
        │                           │
   CLEAN ✅                    THREAT 🚨
        │                           │
        ▼                           ▼
  Pass to your route          Report to Cerebro
                              Return 403 / 429
```

**Fail-open design:** if the Cerebro dashboard is unreachable, the sensor still blocks attacks — it just can't report them. Your app never goes down because of ShieldWatch.

**Zero dependencies:** the sensor uses only Node.js built-in modules (`http`, `https`, `crypto`). No third-party packages required.

---

## Full Configuration

All options are **optional**. Calling `ShieldWatch.create()` with no arguments activates all protections immediately using safe defaults.

```javascript
const ShieldWatch = require('shieldwatch-sensor');

const sw = ShieldWatch.create({

  // ── Reporting ──────────────────────────────────────────────────────────────
  // Where to send attack events. Supports http://, https://, and ngrok URLs.
  collectorUrl: 'http://localhost:3002',

  // Label shown in Cerebro to identify this app (useful if protecting multiple apps)
  appId: 'my-app',

  // ── Mode ───────────────────────────────────────────────────────────────────
  // false (default) = blocking mode — threats get a 403/429 response
  // true            = log-only mode — threats are reported but the request is passed through
  logOnly: false,

  // ── CSRF Protection ────────────────────────────────────────────────────────
  // These endpoints will reject POST/PUT/DELETE if Content-Type is form-encoded.
  // JSON requests from your own frontend are always allowed.
  csrfProtectedPaths: [
    '/api/profile/update',
    '/api/settings/change-password',
  ],

  // ── Session Fixation ───────────────────────────────────────────────────────
  // Any access to these paths is blocked and reported as a session fixation attempt.
  sessionFixationPaths: [
    '/api/session/id',
    '/api/session/fix',
  ],

  // ── Honeypots ──────────────────────────────────────────────────────────────
  // Accessing these paths flags the IP as a scanner in Cerebro.
  // Omit this option to use the built-in list (15 common paths like /wp-admin, /.env, etc.)
  honeypotPaths: [
    '/admin',
    '/wp-admin',
    '/wp-login.php',
    '/.env',
    '/.git/config',
    '/phpmyadmin',
    '/api/admin',
    '/api/backup',
    '/api/debug',
  ],

  // ── IDOR ───────────────────────────────────────────────────────────────────
  // Pluggable function — return a threat object if IDOR is detected, null if clean.
  // Runs on every request. Keep it fast.
  idorChecker: (req) => {
    const sessionUserId = req.session?.userId;
    const paramId = parseInt(req.params?.id, 10);
    if (paramId && sessionUserId && paramId !== sessionUserId) {
      return {
        type: 'idor',
        matched: 'accessing another user resource',
        raw: `session=${sessionUserId} requested id=${paramId}`,
      };
    }
    return null;
  },

  // ── DDoS / Flood ───────────────────────────────────────────────────────────
  // Block an IP that sends more than `ddosThreshold` requests
  // to any `/api/*` path within `ddosWindowMs` milliseconds.
  ddosThreshold: 20,          // default: 20 requests
  ddosWindowMs: 10000,        // default: 10 seconds
  apiPathPrefix: '/api',      // only count requests under this prefix

  // ── Brute Force ────────────────────────────────────────────────────────────
  // After this many failed logins from the same IP within the window, block the IP.
  bruteForceThreshold: 5,     // default: 5 failures
  bruteForceWindowMs: 60000,  // default: 60 seconds

});

// Mount the middleware — protects everything below this line
app.use(sw.middleware);
```

---

## Environment Variables

You can configure ShieldWatch via environment variables instead of code — useful for Docker, CI, or cloud deployments.

| Variable | Equivalent Option | Example |
|----------|-------------------|---------|
| `SW_CEREBRO_URL` | `collectorUrl` | `https://abc123.ngrok-free.app` |
| `SW_APP_ID` | `appId` | `production-api` |
| `SW_LOG_ONLY` | `logOnly` | `true` |

Options passed directly to `ShieldWatch.create()` always take priority over environment variables.

**Example — enable from command line:**
```bash
SW_CEREBRO_URL=https://abc123.ngrok-free.app SW_APP_ID=my-app node server.js
```

**Example — ecosystem.config.js for PM2:**
```javascript
module.exports = {
  apps: [{
    name: 'my-app',
    script: 'server.js',
    env: {
      SW_CEREBRO_URL: 'https://abc123.ngrok-free.app',
      SW_APP_ID:      'my-app',
      SW_LOG_ONLY:    'false',
    }
  }]
};
```

---

## Advanced Hooks

The sensor instance returned by `ShieldWatch.create()` exposes several hooks beyond the core middleware.

### WebSocket Message Scanning

Call `inspectMessage` inside your Socket.io message handler to scan chat messages for XSS and SQLi before broadcasting them.

```javascript
const io = require('socket.io')(server);

io.on('connection', (socket) => {
  socket.on('chat_message', (msg) => {
    // Scan the message text before broadcasting
    const threat = sw.inspectMessage(msg, socket);
    if (threat) {
      socket.emit('message_blocked', { error: 'Message blocked by ShieldWatch.' });
      return;
    }
    // Message is clean — broadcast to room
    io.to(msg.room).emit('chat_message', msg);
  });
});
```

`inspectMessage` returns the threat object if blocked, `null` if clean. In `logOnly` mode it always returns `null` (logs the event but lets the message through).

### Brute Force Tracking

Call `trackLoginFailure` every time a login attempt fails. The sensor tracks the count per IP and returns `true` when the threshold is reached.

```javascript
app.post('/api/login', (req, res) => {
  const user = db.findUser(req.body.username, req.body.password);

  if (!user) {
    const blocked = sw.trackLoginFailure(req);
    if (blocked) {
      return res.status(429).json({
        ok: false,
        error: 'Too many failed attempts. Your IP has been blocked.',
      });
    }
    return res.json({ ok: false, error: 'Invalid credentials.' });
  }

  res.json({ ok: true, user });
});
```

### Browser Fingerprint Submission

ShieldWatch can track attackers by device fingerprint, not just IP address. This means a blocked attacker cannot bypass the block by switching to a VPN or mobile data.

Add this endpoint to receive fingerprint data from the client-side beacon:

```javascript
app.post('/api/sw-fingerprint', (req, res) => {
  sw.submitFingerprint(req.body, req);
  req.session.fpId = req.body.fpId;   // store fingerprint ID in session
  res.json({ ok: true });
});
```

The Cerebro dashboard provides a `sw-beacon.js` script that collects canvas, WebGL, GPU, screen, timezone, and font data and posts it to this endpoint automatically.

### Manual Honeypot

Trigger a honeypot event manually from any route:

```javascript
app.get('/api/admin/users', (req, res) => {
  sw.honeypotHit('/api/admin/users', req);  // flag this access in Cerebro
  res.json({ users: [] });                  // return fake data
});
```

### Standalone Threat Scanner

The core pattern scanner is exported separately — use it anywhere without mounting the full middleware:

```javascript
const { detectThreats } = require('shieldwatch-sensor');

const input = "' OR 1=1--";
const threat = detectThreats(input);

if (threat) {
  console.log(threat.type);    // 'sqli'
  console.log(threat.matched); // the regex that caught it
  console.log(threat.raw);     // the input value (truncated to 200 chars)
}
```

---

## Adding to an Existing App

If you already have an Express application, the integration is three lines and zero changes to your existing routes.

**Before:**
```javascript
const express = require('express');
const app = express();
app.use(express.json());

app.post('/api/login', loginHandler);
app.get('/api/data', dataHandler);
app.listen(3000);
```

**After:**
```javascript
const express     = require('express');
const ShieldWatch = require('shieldwatch-sensor');        // ← add
const app = express();
app.use(express.json());

const sw = ShieldWatch.create({ appId: 'my-app' });      // ← add
app.use(sw.middleware);                                   // ← add

app.post('/api/login', loginHandler);   // unchanged
app.get('/api/data', dataHandler);      // unchanged
app.listen(3000);
```

Every route below `app.use(sw.middleware)` is now protected. Routes above it are not — this lets you exclude health checks or public paths from scanning if needed.

---

## Compatibility

| | Support |
|--|---------|
| **Windows** | ✅ Full |
| **macOS** | ✅ Full |
| **Linux** | ✅ Full |
| **Node.js** | ≥ 16.0.0 |
| **Express** | 4.x, 5.x |
| **Production dependencies** | None |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Your Web Application                      │
│                                                              │
│   app.use(sw.middleware)  ←─────────────────────────────┐   │
│                                                          │   │
│   POST /api/login                                        │   │
│   GET  /api/data                                         │   │
│   ...all your routes                                     │   │
└──────────────────────────────────────────────────────────┘   │
                                                               │
                  ┌────────────────────────────────────────────┘
                  │
         ┌────────▼────────────────────────────────┐
         │          ShieldWatch Sensor              │
         │                                         │
         │  • Blocked IP/FP list (30s sync)        │
         │  • IDOR custom check                    │
         │  • Session fixation path check          │
         │  • CSRF content-type check              │
         │  • DDoS sliding-window counter          │
         │  • Honeypot path matcher                │
         │  • Multi-decode pattern scanner         │
         │    (SQLi · XSS · Path Traversal         │
         │     CMDi · SSRF · CRLF)                 │
         └──────────────────┬──────────────────────┘
                            │
              ┌─────────────▼──────────────┐
              │    Cerebro Dashboard       │
              │    (ShieldWatch backend)   │
              │                           │
              │  • Live threat feed       │
              │  • Attacker profiles      │
              │  • Fingerprint tracking   │
              │  • IP block management    │
              │  • Attack statistics      │
              └───────────────────────────┘
```

The sensor and Cerebro communicate over HTTP. When Cerebro is on a remote server, you can use [ngrok](https://ngrok.com) to tunnel the connection — no firewall rules required.

```
[Your App on EC2 / Render / Fly]
        │
        │  HTTP POST /api/event
        ▼
[ngrok tunnel]
        │
        ▼
[Cerebro on your laptop — localhost:3002]
```

---

## FAQ

**Does ShieldWatch slow down my app?**
No measurable impact for typical traffic. The pattern scan is pure JavaScript regex — no I/O, no blocking. The Cerebro report is sent asynchronously after the response is already returned.

**What happens if Cerebro is offline?**
The sensor keeps blocking attacks — it just can't report them. The `report()` function fails silently and the app continues normally. This is by design (fail-open).

**Can I use it without Cerebro at all?**
Yes. If you just want local blocking without any reporting, omit `collectorUrl` or point it at a URL that doesn't exist. All attacks will still be blocked and logged to your console.

**Does it work with HTTPS / ngrok URLs?**
Yes. Pass the full URL including protocol: `collectorUrl: 'https://abc123.ngrok-free.app'`. The sensor automatically selects `http` or `https` based on the URL scheme.

**What does `logOnly: true` do?**
Passive monitoring mode. Every threat is detected and reported to Cerebro, but the request is passed through to your route instead of being blocked. Useful for auditing a live app without disrupting users.

**Can I protect multiple apps with one Cerebro instance?**
Yes. Give each app a different `appId`. Cerebro groups events by app so you can see attacks per application separately.

**Does it block legitimate users?**
Only if they send payloads that match attack patterns. Normal users browsing your app, submitting forms, or using your API will never be affected. The DDoS threshold (20 requests / 10 seconds per IP to `/api/*`) is generous enough for normal human usage.

---

## License

MIT © ShieldWatch
