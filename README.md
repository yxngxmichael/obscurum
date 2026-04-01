# Obscurum — Setup Guide

## Credentials
- Username: `Willow`
- Password: `Blxxdyy900`

---

## Backend Setup (Linux / macOS / WSL)

### 1. Install Node.js dependencies
```bash
npm install
```

### 2. Install system tools
**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install -y nmap whois dnsutils openssl curl iputils-ping traceroute
```

**macOS (Homebrew):**
```bash
brew install nmap whois bind openssl curl
```

### 3. Start the backend
```bash
node server.js
```
Server runs at `http://localhost:3000`

### 4. Open the frontend
Open `index.html` in your browser, or serve it:
```bash
npx serve .
```

---

## API Endpoints

| Method | Endpoint | Body |
|--------|----------|------|
| GET | `/health` | — |
| POST | `/run/nmap` | `{ target, type, timing }` |
| POST | `/run/whois` | `{ target }` |
| POST | `/run/dns` | `{ domain, type }` |
| POST | `/run/ssl` | `{ host, port }` |
| POST | `/run/ping` | `{ target, mode }` |
| POST | `/run/headers` | `{ url, method }` |
| POST | `/run/unifi` | `{ host, port, op }` |

All tool endpoints return **Server-Sent Events (SSE)** streaming output line by line.

---

## UniFi Operations

| Operation | Command |
|-----------|---------|
| `discover` | nmap -sV on UniFi ports |
| `portcheck` | nmap port scan |
| `sysinfo` | curl /status |
| `devlist` | curl /api/s/default/stat/device |
| `firmware` | parse device JSON for versions |
| `sslcheck` | openssl + TLS 1.0/1.1 weak cipher test |
| `sshcheck` | ssh -v banner grab |
| `apicheck` | probe all API endpoints for HTTP status |

---

## Security Notes

- Only scan systems and networks you own or have **explicit written permission** to test.
- The backend runs on localhost only by default — do not expose port 3000 publicly.
- Input sanitisation is applied to all targets to prevent shell injection.
- All commands time out automatically (15–120 seconds depending on tool).

---

## Demo Mode

If the backend is not running, the frontend falls back to **demo/simulated mode** automatically, indicated in the terminal output.
