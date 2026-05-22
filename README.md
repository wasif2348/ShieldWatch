# ShieldWatch — UADR Intelligence Dashboard

**Unified Attack Detection & Response — Real-time threat monitoring dashboard for the ShieldWatch RASP platform.**

ShieldWatch is the command center. It receives live attack events from the ShieldWatch Sensor running inside any protected web application, enriches them with IP geolocation and browser fingerprinting data, builds attacker profiles, and displays everything on a real-time red dashboard.

> CS-471 Final Project — Air University Islamabad
> Companion to [NexaChat](https://github.com/wasif2348/nexachat) — a deliberately vulnerable chat app used as the demo target.

---

## What It Does

- **Receives attack events** from the ShieldWatch Sensor in real time
- **Enriches events** with IP geolocation (country, city, ISP)
- **Browser fingerprinting** — tracks attackers by device (canvas, WebGL, GPU, screen, timezone), not just IP. Survives VPN switches.
- **Builds attacker profiles** — groups all activity from the same device into one profile with threat score, attack history, and browser details
- **PIN-protected dashboard** — secure access gate before any data is visible
- **Block/unblock IPs** — one click in the dashboard pushes the block to the sensor on the protected app
- **Block by fingerprint** — blocks the device even if the attacker changes IP
- **Live feed** — every attack appears within milliseconds via Socket.io
- **Attack statistics** — counters per threat type, blocked vs logged verdicts

---

## Architecture

```
[Attacker]
    │
    ▼
[NexaChat on EC2]  ←── ShieldWatch Sensor intercepts every request
    │
    │  POST /api/event  (attack detected)
    │  POST /api/fingerprint  (browser fingerprint)
    ▼
[Tunnel — e.g. ngrok http 3002]
    │
    ▼
[ShieldWatch Dashboard — your laptop, port 3002]
    │
    ├── Enriches with geolocation
    ├── Builds attacker profile
    ├── Shows on live dashboard
    └── Can push IP/fingerprint blocks back to sensor
```

---

## Quick Start

### Requirements
- Node.js 18+
- The ShieldWatch Sensor must be running inside a target app (e.g. NexaChat)
- A tunnel to expose port 3002 to the internet (so EC2 can reach your laptop)

### Install & Run

```bash
git clone https://github.com/wasif2348/ShieldWatch.git
cd ShieldWatch
npm install
node collector.js
```

Open `http://localhost:3002` in your browser.

You will see a PIN gate. Default PIN: **2348**

---

## Configuration

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `SW_PIN` | `2348` | Dashboard access PIN |
| `SW_PORT` | `3002` | Port to listen on |

```bash
SW_PIN=9999 SW_PORT=3002 node collector.js
```

---

## Connecting to a Protected App (EC2 Demo Setup)

The dashboard runs on your **laptop**. The protected app runs on **EC2**. You need a tunnel so EC2 can reach your laptop.

### Step 1 — Start the dashboard
```bash
node collector.js
# Running on http://localhost:3002
```

### Step 2 — Open a tunnel
```bash
ngrok http 3002
# Gives you: https://abc123.ngrok-free.app
```

### Step 3 — Set the tunnel URL on EC2
SSH into EC2, open `~/nexachat/ecosystem.config.js`, set:
```javascript
SW_CEREBRO_URL: 'https://abc123.ngrok-free.app',
SW_ENABLED: 'true',
```
Then restart:
```bash
pm2 restart nexachat
```

### Step 4 — Open the dashboard
```
http://localhost:3002
```
Enter PIN `2348`. You will see "Waiting for NexaChat…" until the first attack event arrives.

---

## Demo Attacks (live in class)

Once connected, trigger these from a browser pointed at NexaChat:

| Attack | How to trigger |
|--------|----------------|
| SQL Injection | Login with username `admin'--` |
| XSS | Search for `<img src=x onerror=alert(1)>` |
| Path Traversal | DevTools console: `fetch('/api/file?path=../../private/db_config.txt')` |
| Honeypot | `fetch('/admin')` or `fetch('/.env')` |
| DDoS | Run `node ddos-flood.js` in the NexaChat folder |
| Brute Force | Run `node brute-force.js` in the NexaChat folder |

Every attack appears on the dashboard within milliseconds.

---

## Project Structure

```
ShieldWatch/
├── collector.js      Event receiver, geolocation enrichment, attacker profiling
├── package.json
└── public/           Dashboard frontend (HTML + CSS + JS)
```

---

## License

MIT
