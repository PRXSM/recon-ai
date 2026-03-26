# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Recon AI** is a network security scanning platform built for non-technical users. It provides a Flask web interface for running network scans, detecting vulnerabilities, and analyzing system logs, with optional AI-powered explanations via the Claude API.

## Running the App

```bash
# Activate virtual environment
source venv/bin/activate

# Start the Flask web server
python3 app.py
# → Runs at http://localhost:5000
```

## Running Individual Tools (CLI)

Each tool can be run standalone from the project root:

```bash
python3 port_scanner.py        # Scan TCP ports 1-1024 on a target IP
python3 network_mapper.py      # Discover live hosts in a subnet (CIDR)
python3 log_analyzer.py        # Analyze system logs for threats
python3 vulnerability_reporter.py  # Map open ports to known vulnerabilities
python3 ai_assistant.py        # Send scan results to Claude for explanation
python3 engine.py              # Interactive CLI menu for full scans
```

## Dependencies

No `requirements.txt` — dependencies are managed in `venv/`. Key packages:
- `flask` — web framework
- `anthropic` — Claude API client
- `python-dotenv` — loads `ANTHROPIC_API_KEY` from `.env`
- Standard library: `socket`, `subprocess`, `re`, `ipaddress`, `platform`, `pathlib`

The `.env` file (gitignored) must contain `ANTHROPIC_API_KEY`.

## Architecture

```
User → index.html (form)
         ↓
    POST /scan → app.py: input validation → run_scan()
    ├── quick_scan()     → port_scanner.py
    ├── network_scan()   → network_mapper.py + port_scanner.py
    ├── full_recon()     → all 5 tools
    └── log_analysis()   → log_analyzer.py
         ↓
    engine.py:
    ├── calculate_risk_score()       # 0–100 score; deducts per finding
    ├── build_scan_summary()         # redacts IPs before AI submission
    └── analyze_with_ai() (optional) # calls Claude API
         ↓
    results.html (displays findings, risk score, AI analysis)
```

### Key Files

| File | Role |
|---|---|
| `app.py` | Flask routes; scan mode dispatch; input validation |
| `engine.py` | Risk scoring, scan summary builder, report saving |
| `ai_assistant.py` | Claude API integration; EXPLAIN→RISK→FIX→VERIFY prompt structure |
| `port_scanner.py` | TCP connect scan, service identification |
| `network_mapper.py` | Ping-based host discovery, CIDR input |
| `log_analyzer.py` | 30+ regex threat patterns, cross-platform log discovery |
| `vulnerability_reporter.py` | Hardcoded port→vulnerability database with severity levels |

### Risk Scoring (`engine.py`)
Score starts at 100 and deducts:
- 2 pts per open port
- 20/10/5/2/3 pts per CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN vulnerability
- Up to 10 pts per log finding

Labels: **GOOD** (80–100) / **MODERATE** (60–79) / **AT RISK** (40–59) / **CRITICAL** (0–39)

### Privacy Design
- All scanning runs locally on the user's machine
- IP addresses are redacted from scan summaries before sending to Claude API
- AI analysis is opt-in (checkbox in the form)
- Users provide their own `ANTHROPIC_API_KEY`

### Subdirectories
`ai-security-assistant/`, `log-analyzer/`, `network-mapper/`, `port-scanner/`, `vulnerability-reporter/` each mirror their root-level counterpart with their own README and sample output. They are standalone copies, not imported by the main app — the root-level `.py` files are what `app.py` actually uses.

## Current Development Phase

Phase 4 (active): threat pattern expansion, grouped log findings, risk scoring UI. Templates (`index.html`, `results.html`) have uncommitted modifications.
