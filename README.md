# Recon AI 🔐
> AI-powered network security for everyone — not just the experts.

Recon AI scans your network, detects vulnerabilities, analyzes system logs,
and explains every finding in plain English. With or without an AI connection.
No technical knowledge required.

---

## The Problem Recon AI Solves

Most security tools are built for experts. Nmap, Wireshark, Splunk —
powerful but completely inaccessible to the people who need security most.

Small businesses. Schools. Clinics. Home users. They have real networks,
real risks, and zero tools that speak their language.

Recon AI fills that gap. One scan. Plain English results. Know exactly what to fix.

---

## How It Works

```
Open Recon AI in your browser
         ↓
Choose your tools (port scanner, network mapper, log analyzer, vuln reporter)
         ↓
Enter your IP address and run the scan
         ↓
Get a network health score (0–100) with risk label
         ↓
Every finding explained in plain English — with exact fix instructions
         ↓
Optional: AI analysis powered by Claude for deeper explanations
         ↓
Download your full report as a .txt file anytime
```

---

## The 5 Tools

| Tool | What It Does | Status |
|---|---|---|
| **Port Scanner** | Scans ports 1–1024. Finds every open door on your network and identifies what's running. | ✅ Complete |
| **Network Mapper** | Discovers all live devices on a subnet. Answers: what's on my network — and should it be there? | ✅ Complete |
| **Log Analyzer** | Reads system logs and detects 30+ threat patterns: brute force, privilege escalation, ransomware indicators, crypto mining, and more. | ✅ Complete |
| **Vulnerability Reporter** | Maps open ports to known security risks with severity ratings. Correlates findings across all tools for smarter analysis. | ✅ Complete |
| **AI Security Assistant** | Explains everything in plain English using Claude AI. Every finding gets: EXPLAIN → RISK → FIX → VERIFY. | ✅ Complete |

---

## Key Features

- 🌐 **Flask Web Interface** — clean browser UI, no command line needed
- 🧠 **AI-Powered Analysis** — optional Claude integration for deep plain-English explanations
- 📖 **Offline Mode** — built-in knowledge base explains common findings without any API key
- 📊 **Network Health Score** — 0 to 100 risk score with GOOD / MODERATE / AT RISK / CRITICAL labels
- 📄 **Downloadable Reports** — every scan generates a full .txt report you can save and keep
- 🔒 **Privacy First** — your IP address is never sent to any external service. AI analysis is opt-in only.
- 🔗 **Cross-Tool Correlation** — log findings escalate port severity automatically (e.g. brute force detected + SSH open = higher risk rating)
- 🖥️ **Cross-Platform** — macOS, Windows, Linux

---

## Tech Stack

| Technology | Role |
|---|---|
| Python 3 | Core scanning engine and all 5 tools |
| Flask | Web interface and routing |
| Claude API (Anthropic) | AI analysis and plain English explanations |
| python-dotenv | Secure API key management |
| Standard Library | `socket`, `subprocess`, `re`, `ipaddress`, `platform`, `pathlib` |

---

## Local Setup

### Requirements
- Python 3.9+
- An Anthropic API key (only needed for AI analysis — everything else works without it)

### Installation

```bash
# 1. Clone the repo
git clone https://github.com/PRXSM/recon-ai.git
cd recon-ai

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate        # macOS/Linux
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Add your API key (only needed for AI analysis)
cp .env.example .env
# Open .env and paste your Anthropic API key

# 5. Run
python3 app.py
# → Open http://localhost:5000 in your browser
```

---

## Project Structure

```
recon-ai/
├── app.py                     # Flask routes and web interface
├── engine.py                  # Risk scoring, scan summary, report builder
├── port_scanner.py            # TCP port scanner (ports 1–1024)
├── network_mapper.py          # Ping-based host discovery
├── log_analyzer.py            # 30+ threat pattern detection
├── vulnerability_reporter.py  # Port → vulnerability database + cross-tool correlation
├── ai_assistant.py            # Claude API integration
├── plain_english.py           # Offline knowledge base for common port findings
├── templates/
│   ├── index.html             # Scan form
│   └── results.html           # Results display
├── .env.example               # API key template
├── requirements.txt           # Dependencies
└── README.md
```

---

## Risk Scoring

Every scan produces a **Network Health Score** from 0–100.

| Score | Label | Meaning |
|---|---|---|
| 80–100 | 🟢 GOOD | Looking solid. Keep it maintained. |
| 60–79 | 🟡 MODERATE | Some findings worth addressing. |
| 40–59 | 🟠 AT RISK | Real vulnerabilities present. Act soon. |
| 0–39 | 🔴 CRITICAL | Immediate attention required. |

Score deductions: open ports (-2 each), vulnerabilities (CRITICAL -20, HIGH -10, MEDIUM -5, LOW -2), log findings (up to -10 each).

---

## Privacy Architecture

- **Your IP never leaves your machine** — redacted from all AI submissions
- **AI analysis is opt-in** — checkbox in the scan form, disabled by default
- **Offline mode available** — full plain-English explanations with zero API calls
- **No data stored on any server** — everything runs locally
- **Your API key stays local** — stored in `.env`, never uploaded

---

## Current Development Status

| Phase | Description | Status |
|---|---|---|
| Phase 1 | 5 Core Tools | ✅ Complete |
| Phase 2 | Unified Engine — risk scoring, OS detection, IP redaction | ✅ Complete |
| Phase 3 | Flask Web Interface — browser UI, AI opt-in, offline mode | ✅ Complete |
| Phase 4 | 30+ threat patterns, cross-tool correlation, markdown rendering, downloadable reports | ✅ Complete |
| Phase 5 | UI redesign — single page dashboard, mobile friendly | 🔨 In Progress |
| Phase 6 | Network Intelligence — ARP, netstat, packet capture explained | 📋 Planned |
| Phase 7 | Deploy Online — HTTPS, rate limiting, GDPR compliance | 📋 Planned |
| Phase 8 | Monetization — scheduled scans, premium features | 📋 Planned |

---

## Legal & Ethics

> **Only scan networks you own or have explicit written permission to scan.**
> Unauthorized network scanning is illegal under the Computer Fraud and Abuse Act (CFAA)
> and equivalent laws worldwide. Recon AI requires authorization confirmation before every scan.
> This tool is built FOR defenders — not pointed AT others.

---

## Vision

> *"The school IT admin in rural Virginia. One person managing 200 devices,
> no security budget, no security training. Every Monday morning Recon AI
> sends them a simple email — green, yellow, or red. That's it."*

Every decision in this project is built with that person in mind.

---

## Built By

**Asama Azim** — IT & Cybersecurity | Network+ Certified | Security+ in progress

Built as an intensive self-directed learning project. Every concept — networking,
Python, Flask, cybersecurity — learned from scratch and applied immediately.

[GitHub](https://github.com/PRXSM) | [LinkedIn](https://linkedin.com/in/asama-azim-38a0b391)
