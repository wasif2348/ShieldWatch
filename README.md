# ShieldWatch — UADR Security Platform

**Unified Attack Detection & Response — Real-time threat monitoring for any web application.**

ShieldWatch is a complete Runtime Application Self-Protection (RASP) platform. It detects and blocks 11 categories of web attacks in real time, tracks attackers by browser fingerprint, and displays everything on a live threat intelligence dashboard.

This repository contains two components:

| Component | Folder | What it does |
|-----------|--------|--------------|
| **ShieldWatch Sensor** | [`/shieldwatch-sensor`](./shieldwatch-sensor) | Middleware that goes inside any Express app and blocks attacks |
| **ShieldWatch Dashboard** | root | The command center — receives events, builds attacker profiles, shows live feed |

---

## How It Works

```
Any Web Application  (yours, anyone's)
        │
        │  3 lines of code — ShieldWatch Sensor installed
        ▼
Attacks intercepted and blocked before reaching your routes
        │
        │  Attack events sent to Dashboard
        ▼
ShieldWatch Dashboard — live feed, attacker profiles, block controls
```

---

## Part 1 — The Sensor

> **The sensor goes into any Express/Node.js app. Not just one specific app. Any app.**

See the full sensor documentation here: **[shieldwatch-sensor/README.md](./shieldwatch-sensor/README.md)**

### Quick install into any app

```bash
# Copy the sensor folder into your project
cp -r shieldwatch-sensor/ your-project/

# Or install directly (if published to npm)
npm install shieldwatch-sensor
```

### Add 3 lines to your server.js

```javascript
const ShieldWatch = require('./shieldwatch-sensor');
const sw = ShieldWatch.create({ collectorUrl: 'http://your-dashboard:3002' });
app.use(sw.middleware);
```

That's it. Every route below that line is now protected against:

- SQL Injection · XSS · Path Traversal · Command Injection
- CSRF · IDOR · Session Fixation · DDoS · Brute Force · SSRF · CRLF

---

## Part 2 — The Dashboard

The dashboard receives events from the sensor, enriches them with geolocation and browser fingerprint data, and shows everything live.

### Run it

```bash
git clone https://github.com/wasif2348/ShieldWatch.git
cd ShieldWatch
npm install
node collector.js
```

Open `http://localhost:3002` — PIN: **2348**

### What it shows

- Live attack feed — every blocked request appears within milliseconds
- Attacker profiles — device fingerprint, browser, OS, screen, GPU, timezone
- IP geolocation — country, city, ISP
- Block controls — ban an IP or device fingerprint with one click
- Attack statistics — counters per threat type

---

## Connecting Sensor → Dashboard

The sensor reports to the dashboard over HTTP. Set `collectorUrl` in your app to wherever the dashboard is running.

**If both are on the same machine:**
```javascript
ShieldWatch.create({ collectorUrl: 'http://localhost:3002' })
```

**If your app is on a remote server (EC2, VPS, etc.) and dashboard is on your laptop:**
You need a tunnel so the server can reach your laptop. Start the dashboard, open a tunnel to port 3002, then set the tunnel URL as `collectorUrl` in your app's config.

**If both are on the same remote server:**
```javascript
ShieldWatch.create({ collectorUrl: 'http://localhost:3002' })
```
No tunnel needed.

---

## Configuration

### Dashboard
| Variable | Default | Description |
|----------|---------|-------------|
| `SW_PIN` | `2348` | Dashboard access PIN |
| `SW_PORT` | `3002` | Port to listen on |

### Sensor
See full config options in [shieldwatch-sensor/README.md](./shieldwatch-sensor/README.md)

| Variable | Default | Description |
|----------|---------|-------------|
| `SW_CEREBRO_URL` | `http://localhost:3002` | Dashboard URL |
| `SW_APP_ID` | `app` | Label for this app in dashboard |
| `SW_LOG_ONLY` | `false` | Detect but never block (passive mode) |

---

## Project Structure

```
ShieldWatch/
│
├── shieldwatch-sensor/        ← The sensor — install this in any app
│   ├── index.js               Main sensor code (factory pattern)
│   ├── README.md              Full sensor documentation
│   ├── package.json
│   └── demo/
│       └── app.js             Standalone demo showing sensor on a fresh Express app
│
├── collector.js               Dashboard backend — receives events, builds profiles
├── public/                    Dashboard frontend (HTML + CSS + JS)
├── package.json
└── README.md
```

---

## License

MIT
