# ShieldWatch

**Add real-time attack protection to any Node.js web app in under 5 minutes.**

ShieldWatch watches every request coming into your app and automatically blocks hackers before they can do damage — SQL injection, XSS, DDoS floods, brute force, and 7 more attack types. When an attack happens, it shows up live on the ShieldWatch Dashboard with the attacker's location, device, and exact payload.

You do not need to be a security expert to use it.

---

## What's in this repo

```
ShieldWatch/
├── shieldwatch-sensor/   ← This goes INSIDE your app (protects it)
└── collector.js          ← This is the dashboard (you watch attacks here)
```

Think of it like a security camera system:
- The **sensor** is the camera — it goes in your app and watches for attacks
- The **dashboard** is the monitor — it shows you what the camera caught

---

## Part 1 — Protect your app (the Sensor)

### Step 1 — Copy the sensor into your project

```bash
cp -r shieldwatch-sensor/ /path/to/your/project/
```

Or if you have this repo cloned already, just copy the `shieldwatch-sensor` folder into your project folder.

### Step 2 — Add 3 lines to your server.js

Open your `server.js` (or `app.js` or whatever your main file is) and add these 3 lines:

```javascript
// Line 1 — load ShieldWatch
const ShieldWatch = require('./shieldwatch-sensor');

// Line 2 — turn it on
const sw = ShieldWatch.create({ collectorUrl: 'http://localhost:3002' });

// Line 3 — plug it in (add this BEFORE your routes)
app.use(sw.middleware);
```

### Step 3 — Start your app normally

```bash
node server.js
```

You will see this in the terminal:
```
[ShieldWatch] ✅ Sensor initialized — mode: BLOCKING
```

Your app is now protected. Every route below `app.use(sw.middleware)` is automatically defended.

> Full sensor documentation: [shieldwatch-sensor/README.md](./shieldwatch-sensor/README.md)

---

## Part 2 — Watch attacks live (the Dashboard)

The dashboard is where you see attacks happening in real time.

### Step 1 — Install and run

```bash
git clone https://github.com/wasif2348/ShieldWatch.git
cd ShieldWatch
npm install
node collector.js
```

### Step 2 — Open in your browser

```
http://localhost:3002
```

Enter the PIN: **2348**

You will see the live dashboard. It starts empty — attacks appear the moment someone tries one on your app.

---

## Part 3 — Encrypted Attack History

Every attack is automatically saved to an encrypted log on the same machine as the dashboard. The data survives restarts and is protected against tampering.

### How it works

| | What happens |
|--|--|
| **Storage** | One file per day — `logs/2024-11-15.log` |
| **Encryption** | AES-256-GCM — each entry has its own random key IV |
| **Key** | Derived from your PIN using PBKDF2 (100,000 iterations) |
| **Tamper detection** | HMAC-SHA256 chain — editing any past entry breaks every entry after it |

### Viewing history

1. Open the dashboard and enter your PIN
2. Click the **History** button in the top-right of the header
3. Click any date tab to decrypt and load that day's attacks
4. Use the filters to narrow down by attack type, IP address, or verdict (Blocked / Logged / Decoy)
5. Click **Export PDF** to generate a printable audit report

The dashboard shows a green **✓ CHAIN INTACT** badge when the log is clean. If anyone has modified the log file, it shows **⚠ TAMPERED** in red.

### Important files

| File | What it is |
|------|-----------|
| `logs/YYYY-MM-DD.log` | Encrypted attack records for that day |
| `logs/.salt` | The salt used to derive the encryption key — **do not delete this** |

> If `logs/.salt` is deleted, all existing log files become unreadable. The salt is tied to your PIN — if you change the PIN, old logs cannot be decrypted with the new one.

---

## Seeing it in action — quick test

Once your app is running with the sensor and the dashboard is open, try this in your browser's address bar:

```
http://localhost:YOUR_APP_PORT/anything?q=' OR 1=1--
```

Switch to the dashboard — you will see a **BLOCKED | SQL INJECTION** event appear immediately with the attacker's details.

---

## If your app is on a server (not your laptop)

The dashboard runs on your laptop. Your app runs on the server. For your app to send events to the dashboard, the server needs to be able to reach your laptop.

The easiest way is to use [ngrok](https://ngrok.com) (free):

```bash
# On your laptop — start the dashboard
node collector.js

# On your laptop — open a tunnel in a new terminal
ngrok http 3002
# It gives you a URL like: https://abc123.ngrok-free.app
```

Then in your app's ShieldWatch setup, use that URL:

```javascript
const sw = ShieldWatch.create({ collectorUrl: 'https://abc123.ngrok-free.app' });
```

Restart your app. Events will now reach your laptop dashboard from anywhere.

---

## What attacks does it block?

| Attack | Example |
|--------|---------|
| SQL Injection | `' OR 1=1--` in a login field |
| XSS | `<script>alert(1)</script>` in any input |
| Path Traversal | `../../etc/passwd` in a file path |
| Command Injection | `; cat /etc/passwd` in any field |
| DDoS / Flood | More than 20 API requests per 10 seconds from one IP |
| Brute Force | Too many failed login attempts from one IP |
| CSRF | Cross-site form submissions to protected endpoints |
| IDOR | Accessing another user's data via URL parameter |
| Session Fixation | Exploiting session ID endpoints |
| SSRF | Internal IP addresses in request parameters |
| CRLF Injection | Header injection attempts |

---

## Configuration

### Dashboard settings

| Setting | Default | How to change |
|---------|---------|---------------|
| PIN code | `2348` | `SW_PIN=9999 node collector.js` |
| Port | `3002` | `SW_PORT=4000 node collector.js` |

> **Note:** The PIN is used to derive the encryption key for the audit log. If you change the PIN after logs already exist, the old log files will not be readable. Set your PIN once and keep it.

### Sensor settings

| Setting | Default | What it does |
|---------|---------|--------------|
| `collectorUrl` | `http://localhost:3002` | Where to send attack events |
| `appId` | `app` | Name shown in dashboard for this app |
| `logOnly` | `false` | `true` = detect but don't block (safe mode) |

---

## Project structure

```
ShieldWatch/
│
├── shieldwatch-sensor/        ← Copy this into any app to protect it
│   ├── index.js               The sensor code
│   ├── README.md              Sensor-specific documentation
│   └── demo/
│       └── app.js             A working example app with sensor already added
│
├── collector.js               Dashboard server
├── public/                    Dashboard UI files
├── logs/                      Encrypted audit log (auto-created on first run)
│   ├── .salt                  Encryption key salt — never delete or commit this
│   └── YYYY-MM-DD.log         One encrypted log file per day
├── package.json
└── README.md                  This file
```

> The `logs/` folder is excluded from git (it is in `.gitignore`). The encrypted log files and the `.salt` file stay on your machine only.

---

## License

MIT
