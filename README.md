<div align="center">

# 🔐 MiniBurp — AI-Powered Web Vulnerability Scanner

**A Burp Suite–inspired interception proxy and automated vulnerability scanner with AI-assisted analysis**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)](https://nodejs.org)
[![React](https://img.shields.io/badge/React-18-blue)](https://react.dev)

</div>

---

## ✨ Features

| Module | Description |
|---|---|
| **🕵️ Proxy** | HTTP/HTTPS interception proxy on `127.0.0.1:8080` with live request queue |
| **📋 HTTP History** | Full request/response log with search, filter, and send-to-Repeater |
| **🔁 Repeater** | Modify and replay any captured HTTP request, view raw response |
| **⚔️ Intruder** | Payload fuzzing with SQLi, XSS, and custom wordlists |
| **🤖 Scanner** | Automated BFS crawler + vulnerability detection (XSS, SQLi, missing headers, IDOR) |
| **🎯 Findings** | Severity-tagged findings with evidence, CVSS score, and fix recommendations |
| **📄 Reports** | Export findings as Markdown, JSON, or PDF |

---

## 🏗 Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | React 18 + Vite, vanilla CSS |
| **Backend** | Node.js + Express + Socket.IO |
| **Database** | SQLite via `better-sqlite3` |
| **Proxy Core** | Node.js `net`/`http`/`https` with MITM TLS (custom Root CA) |
| **AI Integration** | Ollama (local LLM) for passive request analysis |

---

## 🚀 Setup & Run

### Prerequisites

- Node.js 18+
- (Optional) [Ollama](https://ollama.com) running locally for AI features

### Start the Server

```bash
cd backend
npm install
node server.js
```

- **App UI:** http://localhost:3000
- **Proxy:** `127.0.0.1:8080`

### Configure Your Browser

Set your browser's HTTP proxy to:
```
Host: 127.0.0.1
Port: 8080
```

For **HTTPS interception**, install the generated Root CA:
```
C:\Users\<you>\.miniburp\ca.crt
```

---

## 🎬 Demo Walkthrough (6 Steps)

1. **Open** http://localhost:3000 — verify green "Connected · :8080" status
2. **Proxy Tab** → Enable Intercept → browse any HTTP site → capture, edit, forward a request
3. **HTTP History** → browse the captured request log, click a row → send to Repeater
4. **Repeater** → modify the request → click Send → inspect raw response
5. **Scanner** → enter target URL → click "Start Full Scan" → watch live crawl + finding detection
6. **Findings** → click a finding → view severity / evidence / fix recommendation → Export Markdown

---

## 🔒 HTTPS & TLS Notes

- On first run, a Root CA is auto-generated at `~/.miniburp/ca.crt`
- Install it as a **Trusted Root Certificate Authority** in your OS/browser to intercept HTTPS
- For a zero-setup demo, use HTTP targets only

---

## 📁 Project Structure

```
mini-burp-ai-scanner/
├── backend/
│   ├── server.js          ← Express + Socket.IO entry point
│   ├── database.js        ← SQLite schema & queries
│   ├── proxy-core/        ← MITM proxy + TLS CA manager
│   ├── intercept/         ← Request interception queue
│   ├── core/              ← Repeater, Intruder, Session
│   ├── scanner/           ← BFS crawler + detection engine
│   └── ai/                ← Passive analyzer, report generator, Ollama client
└── frontend/
    └── src/
        ├── App.jsx
        ├── StoreContext.jsx
        └── components/
            ├── ProxyTab.jsx
            ├── HistoryTab.jsx
            ├── RepeaterTab.jsx
            ├── IntruderTab.jsx
            └── ScannerTab.jsx
```

---

## ⚠️ Disclaimer

> This tool is built for **educational purposes and authorized security testing only**.
> Do not use it against systems you do not own or have explicit permission to test.
> The author is not responsible for any misuse of this software.

---

## 👤 Author

**Milan Dhiman**
- GitHub: [@Milan0912](https://github.com/Milan0912)

---

<div align="center">
<sub>Built as a portfolio project demonstrating full-stack development, network programming, and security tooling.</sub>
</div>
