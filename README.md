# Recon AI 🔐
> Network security that actually makes sense — for everyone, not just the people who already know what a CVE is.

Recon AI scans your network, finds vulnerabilities, reads your system logs, and explains what it found in plain English. No jargon. No degree required. No API key required.

---

## Why I Built This

Most security tools assume you already know what you're doing. They're powerful — and completely useless if you don't already speak the language.

Meanwhile, the people who actually need security help the most — small businesses, schools, clinics, solo IT admins — have nothing built for them.

Recon AI is my attempt to fix that. Scan your network, get a score, understand what's wrong, know exactly what to do about it.

---

## One Thing Worth Knowing Before Anything Else

You don't need an API key to use Recon AI.

There's a built-in knowledge base that explains every finding it surfaces — what the open port is, why it matters, who could exploit it, and exactly how to fix it. Step by step. No data sent anywhere. No account needed. Nothing.

The AI analysis (powered by Claude) is there when you want a deeper, more personalized breakdown. But the assistant that walks you through your results? That's built in and it's free.

---

## How It Works

```
Open Recon AI in your browser
         ↓
Pick your tools — port scanner, network mapper, log analyzer, vuln reporter
         ↓
Enter your IP and run the scan
         ↓
Get a health score from 0–100
         ↓
Every finding explained in plain English with step-by-step fix instructions
         ↓
Optional: send findings to Claude AI for a deeper breakdown
         ↓
Download the full report as a .txt file
         ↓
Explore Network Intelligence — understand your interfaces, ARP table, active connections, and routes in plain English
```

---

## What Makes This Different

You could paste a security report into ChatGPT or Claude and ask it to explain things. That works. But they can't ping your subnet. They can't open a socket and check what's actually running on your router right now. They can't read your local system logs. They can't tell you if someone installed an AI tool on a device you didn't authorize.

Recon AI runs locally on your machine — which means it has access to things no external tool ever could. The AI analysis is just the explanation layer on top of real local data that only you can collect.

---

## The Tools

| Tool | What It Does | Status |
|---|---|---|
| **Port Scanner** | Scans ports 1–1024 (simple) or all 65,535 (deep). Finds every open door and identifies what's running behind it. | ✅ Complete |
| **Network Mapper** | Discovers every live device on your subnet. MAC vendor lookup via IEEE OUI database. Unknown device alerts. | ✅ Complete |
| **Log Analyzer** | Reads system logs and flags 30+ threat patterns — brute force, ransomware indicators, privilege escalation, crypto mining. | ✅ Complete |
| **Vulnerability Reporter** | Maps open ports to known vulnerabilities with severity ratings and plain English fix instructions. | ✅ Complete |
| **AI Security Assistant** | Three modes — Standard (Claude API), Private (local Ollama, zero data leaves), Offline (built-in, always free). EXPLAIN→RISK→FIX→VERIFY for every finding. | ✅ Complete |
| **Network Intelligence** | Interfaces, ARP table, active connections, and traceroute — all explained in plain English. Always free, never gated. | ✅ Complete |
| **System Inspector** | Scans running processes and startup items. Exact binary name matching — no false positives. Cross-platform. | ✅ Complete |
| **Credential Risk Assessment** | Checks every discovered device for weak auth, default credentials, and missing MFA. | ✅ Complete |
| **Shadow AI Discovery** | Detects unauthorized AI tools running across your local network — by port, banner signature, and API fingerprint. SSL cert checking on HTTPS services. | ✅ Complete |
| **NIST & OWASP Mapping** | Every finding automatically mapped to the NIST Cybersecurity Framework and OWASP Top 10. Plain English compliance summary. | ✅ Complete |
| **Zero Trust Verification** | Detects implicit device trust, new devices by MAC address, and guest devices with internal access. | ✅ Complete |
| **Prompt Injection Hardening** | Four-layer sanitizer protects Recon AI's own AI layer from adversarial inputs embedded in scan results. | ✅ Complete |
| **Multi-Agent AI** | Adversary Agent challenges every finding before you see it. Risk Prioritizer identifies your single most important action. Standard and Private modes only. | ✅ Complete |

---

## What's Actually In Here

- 🌐 **Runs in your browser** — Flask web interface, no command line needed after setup
- 📖 **Built-in assistant, no API key needed** — explains every finding offline, zero data sent anywhere
- 🧠 **Optional AI analysis** — Claude gives a deeper, more personalized breakdown when you want it
- 🔒 **Three AI modes** — Standard (Claude API), Private (local Ollama, zero data leaves your machine), Offline (built-in knowledge base, always free)
- 🤖 **Multi-agent adversarial review** — findings are challenged by an Adversary Agent before you see them. A Risk Prioritizer tells you the one most important action to take.
- 📊 **Network Health Score** — 0–100 score so you know at a glance how your network looks
- 🛡️ **Prompt injection protection** — four-layer sanitizer prevents adversarial inputs in device names or log files from manipulating the AI
- 🏛️ **NIST & OWASP compliance mapping** — every finding mapped automatically, explained in plain English
- 🔍 **Zero Trust verification** — detects implicit device trust and unknown devices by MAC address
- 🚨 **Port change alerting** — alerts when a known device opens a new port since your last scan
- 🔥 **Firewall status check** — tells you if your local firewall is on or off in plain English
- 🔐 **ARP poisoning detection** — flags when a device's MAC address changes between scans
- 📜 **SSL certificate checker** — checks HTTPS services for expired or expiring certificates
- 📄 **Downloadable reports** — every scan saved as a .txt file
- 🛡️ **Security hardened** — SSRF protection, rate limiting, HTTP security headers, SQLite WAL mode
- 🖥️ **macOS, Windows, Linux** — cross-platform

---

## Stack

| | |
|---|---|
| Python 3 | All scanning tools |
| Flask | Web interface |
| Flask-Talisman | HTTP security headers |
| Flask-Limiter | Rate limiting |
| Claude API | AI analysis (optional) |
| Ollama | Local AI inference for Private Mode |
| SQLite | Scan history and device tracking |
| python-dotenv | API key management |
| Standard library | `socket`, `subprocess`, `re`, `ipaddress`, `ssl`, `platform`, `pathlib` |

---

## Getting Started

### Option 1 — Download (Recommended)

No Python, no setup, no terminal. Just download and double-click.

| Platform | Download |
|---|---|
| **Windows** | [ReconAI-Windows.exe](https://github.com/PRXSM/recon-ai/releases/latest) |
| **macOS** | [ReconAI-macOS.zip](https://github.com/PRXSM/recon-ai/releases/latest) — unzip and double-click ReconAI |

**Windows:** Windows Defender may show a "Windows protected your PC" warning. Click "More info" → "Run anyway." This is expected for unsigned applications.

**macOS:** If macOS blocks the app, go to System Settings → Privacy & Security → click "Open Anyway."

### Option 2 — Run from Source (Developers)

You need Python 3.11+. An Anthropic API key is optional — only needed for AI analysis.

```bash
# Clone
git clone https://github.com/PRXSM/recon-ai.git
cd recon-ai

# Virtual environment
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
venv\Scripts\activate           # Windows

# Dependencies
pip install -r requirements.txt

# API key — only needed for AI analysis
cp .env.example .env
# Open .env and add your Anthropic API key

# Run
python3 app.py
# → http://localhost:5000
```

---

## Project Structure

```
recon-ai/
├── app.py                     # Flask routes, validation, security hardening
├── engine.py                  # Risk scoring, scan summary, report builder
├── port_scanner.py            # TCP port scanner (simple 1–1024, deep 65,535)
├── network_mapper.py          # Ping-based host discovery, MAC vendor lookup
├── log_analyzer.py            # 30+ threat pattern detection
├── vulnerability_reporter.py  # Port → vulnerability database
├── ai_assistant.py            # Claude API integration, three AI modes
├── ai_agents.py               # Adversary Agent + Risk Prioritizer
├── plain_english.py           # Offline knowledge base
├── network_intel.py           # Network Intelligence engine
├── system_inspector.py        # Suspicious process and startup item scanner
├── credential_scanner.py      # Credential risk assessment
├── shadow_ai.py               # Shadow AI discovery + SSL cert checker
├── nist_owasp.py              # NIST & OWASP compliance mapping
├── zero_trust.py              # Zero Trust verification
├── prompt_injection.py        # Four-layer prompt injection sanitizer
├── firewall_check.py          # Local firewall status check
├── scan_memory.py             # Scan history, port change alerting, ARP poisoning detection
├── device_fingerprint.py      # MAC vendor lookup via IEEE OUI database
├── templates/
│   ├── index.html             # Scan form
│   ├── results.html           # Results display
│   ├── shadow_ai.html         # Shadow AI findings display
│   ├── network_intel.html     # Network Intelligence dashboard
│   ├── arp_table.html         # ARP table explained
│   ├── netstat.html           # Active connections explained
│   └── traceroute.html        # Route tracing explained
├── oui.csv                    # IEEE OUI database for MAC vendor lookup
├── .env.example               # API key template
├── requirements.txt
└── README.md
```

---

## The Score

Every scan produces a health score from 0–100. It's not perfect — no single number ever is — but it gives you a starting point.

| Score | Label | What it means |
|---|---|---|
| 80–100 | 🟢 GOOD | Looking solid. Stay on top of updates. |
| 60–79 | 🟡 MODERATE | Some things worth looking at. Not urgent, but don't ignore it. |
| 40–59 | 🟠 AT RISK | Real issues here. Worth addressing soon. |
| 0–39 | 🔴 CRITICAL | Something needs attention now. |

Deductions: -2 per open port, up to -20 per critical vulnerability, up to -10 per log finding.

---

## Where Things Stand

| | | |
|---|---|---|
| ✅ | Phase 1 — 5 core scanning tools | Complete |
| ✅ | Phase 2 — Unified engine, risk scoring, OS detection, IP redaction | Complete |
| ✅ | Phase 3 — Flask web interface, browser UI, AI opt-in, offline mode | Complete |
| ✅ | Phase 4 — 30+ threat patterns, cross-tool correlation, downloadable reports | Complete |
| ✅ | Phase 5 — Network Intelligence, interfaces, ARP, netstat, traceroute | Complete |
| ✅ | Phase 6 — Guardian Update, scan memory, unknown device alerts, three AI modes | Complete |
| ✅ | Phase 7 — Deep Scan Mode, full 65,535 port scanning, device fingerprinting | Complete |
| ✅ | Phase 8 — System Inspector, process scanner, startup item analyzer | Complete |
| ✅ | Phase 9 — Credential Risk Assessment, default creds, missing MFA detection | Complete |
| ✅ | Phase 10 — Shadow AI Discovery, unauthorized AI tool detection by port and banner | Complete |
| ✅ | Phase 11 — NIST & OWASP Mapping, automatic compliance correlation | Complete |
| ✅ | Phase 12 — Zero Trust Verification, never trust always verify | Complete |
| ✅ | Phase 13 — Prompt Injection Hardening, four-layer AI sanitizer | Complete |
| ✅ | Phase 13b — Multi-Agent AI, Adversary Agent + Risk Prioritizer | Complete |
| ✅ | Phase 14 — App Complete Milestone, full security audit and hardening | Complete |
| ✅ | Phase 14b — Post-audit hardening, four targeted security fixes | Complete |
| 📋 | Phase 15 — UI Redesign | Planned |
| 📋 | Phase 16 — Deploy Online | Planned |
| 📋 | Phase 17 — Business Model | Planned |

---

## Privacy

- Your IP is never sent anywhere — redacted before any AI call is made
- AI analysis is opt-in — there's a checkbox, it's off by default
- Private Mode sends nothing at all — local Ollama inference only
- Offline Mode requires zero API calls and zero data sharing
- Everything runs locally — no accounts, no server, no data collection
- Your API key lives in `.env` and never gets uploaded

---

## Legal

> Scan networks you own or have explicit permission to scan. Unauthorized scanning is illegal under the CFAA and equivalent laws worldwide. Recon AI asks for authorization confirmation before every scan. This is a defensive tool — built to help you understand your own network.

---

## The Person I'm Building This For

There's a school IT admin somewhere managing 200 devices alone, no security budget, no security training, no time. Every Monday morning they just need to know: is everything okay?

Green, yellow, or red. That's it.

That's who every decision in this project is built around.

---

## Built By

**Asama Azim** — IT & Cybersecurity | CompTIA Network+ Certified | Security+ in progress

[GitHub](https://github.com/PRXSM) | [LinkedIn](https://linkedin.com/in/asama-azim-38a0b391)
