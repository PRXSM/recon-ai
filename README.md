# Recon AI 🔐
> Network security that actually makes sense — for everyone, not just the people who already know what a CVE is.

Recon AI scans your network, finds vulnerabilities, reads your system logs, and explains what it found in plain English. No jargon. No degree required. Works offline too.

---

## Why I Built This

Most security tools assume you already know what you're doing. They're powerful — and completely useless if you don't already speak the language.

Meanwhile, the people who actually need security help the most — small businesses, schools, clinics, solo IT admins — have nothing built for them.

Recon AI is my attempt to fix that. Scan your network, get a score, understand what's wrong, know exactly what to do about it.

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
```

---

## The 5 Tools

| Tool | What It Does | Status |
|---|---|---|
| **Port Scanner** | Scans ports 1–1024. Finds every open door on your network and identifies what's running behind it. | ✅ Complete |
| **Network Mapper** | Discovers every live device on your subnet. Useful question: is everything on this list supposed to be here? | ✅ Complete |
| **Log Analyzer** | Reads your system logs and flags 30+ threat patterns — brute force attempts, privilege escalation, ransomware indicators, crypto mining, and more. | ✅ Complete |
| **Vulnerability Reporter** | Takes the open ports and cross-references them against known risks. Also factors in what the log analyzer found. | ✅ Complete |
| **AI Security Assistant** | Sends your findings to Claude and gets back a plain-English breakdown — every finding gets EXPLAIN → RISK → FIX → VERIFY. | ✅ Complete |

---

## What's Actually In Here

- 🌐 **Runs in your browser** — Flask web interface, no command line needed
- 🧠 **AI analysis is optional** — useful when you want a deeper explanation, not required for basic scans
- 📖 **Works offline** — built-in knowledge base explains common findings with zero API calls
- 📊 **Network health score** — a 0–100 score so you know at a glance how things look
- 📄 **Downloadable reports** — every scan can be saved as a .txt file
- 🔒 **Your IP never leaves your machine** — redacted before anything gets sent to Claude
- 🔗 **Cross-tool logic** — if the log analyzer finds brute force attempts and the port scanner finds SSH open, the vulnerability reporter escalates the severity automatically
- 🖥️ **macOS, Windows, Linux** — runs on all three

---

## Stack

| | |
|---|---|
| Python 3 | All 5 scanning tools |
| Flask | Web interface |
| Claude API | AI analysis (optional) |
| python-dotenv | API key management |
| Standard library | `socket`, `subprocess`, `re`, `ipaddress`, `platform`, `pathlib` |

---

## Running It Locally

You need Python 3.9+ and optionally an Anthropic API key (only if you want the AI analysis — everything else works without it).

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

## Privacy

- Your IP is never sent anywhere — redacted before any AI call is made
- AI analysis is opt-in — there's a checkbox, it's off by default
- The offline mode sends nothing at all
- Everything runs locally — no accounts, no server, no data collection
- Your API key lives in `.env` and never gets uploaded

---

## Where Things Stand

| | | |
|---|---|---|
| ✅ | 5 core scanning tools | Done |
| ✅ | Unified engine — risk scoring, OS detection, IP redaction | Done |
| ✅ | Flask web interface — browser UI, AI opt-in, offline mode | Done |
| ✅ | 30+ threat patterns, cross-tool correlation, downloadable reports | Done |
| 🔨 | Network intelligence — ARP, netstat, and more explained in plain English | In progress |
| 📋 | UI redesign | Planned |
| 📋 | More coming | — |

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

**Asama Azim** — IT & Cybersecurity | Network+ Certified | Security+ in progress

Built over a few days as a self-directed learning project — networking, Python, Flask, and cybersecurity all learned from scratch and applied immediately. Still building.

[GitHub](https://github.com/PRXSM) | [LinkedIn](https://linkedin.com/in/asama-azim-38a0b391)
