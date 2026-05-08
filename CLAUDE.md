# CLAUDE.md

## Co-Author Rule — Non-Negotiable
Claude Code assists with development but is never a co-author of this project. All commits are authored by Asama Azim only. Claude Code must NEVER add Co-Authored-By lines to any commit message under any circumstance — not automatically, not as a suggestion, not as a default. Commit messages contain only the description of the change. Nothing else.

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

Dependencies are in `requirements.txt` and managed in `venv/`. Key packages:
- `flask` — web framework
- `anthropic` — Claude API client
- `python-dotenv` — loads `ANTHROPIC_API_KEY` from `.env`
- `requests` — HTTP client for network intel and external lookups
- `nmap` (optional) — extended port scanning
- Standard library: `socket`, `subprocess`, `re`, `ipaddress`, `platform`, `pathlib`

The `.env` file (gitignored) must contain `ANTHROPIC_API_KEY`.

## Architecture

```
User → index.html (form)
         ↓
    POST /scan → app.py: input validation → tool dispatch
    ├── port_scanner.py          → TCP connect scan
    ├── network_mapper.py        → subnet discovery + device_fingerprint.py
    ├── log_analyzer.py          → 30+ threat patterns
    ├── vulnerability_reporter.py → port→CVE mapping
    ├── system_inspector.py      → process + startup item scan
    ├── credential_scanner.py    → auth weakness detection
    └── shadow_ai.py             → unauthorized AI tool detection
         ↓
    engine.py:
    ├── calculate_risk_score()       # 0–100 score; deducts per finding
    ├── build_scan_summary()         # redacts IPs before AI submission
    └── nist_owasp.py:
        ├── map_findings()           # enriches findings with NIST + OWASP context
        └── generate_compliance_summary()  # plain English compliance summary
         ↓
    scan_memory.py                   # stores scan to local DB, detects new devices
         ↓
    ai_assistant.py (optional)       # calls Claude API
         ↓
    results.html (displays findings, risk score, compliance mapping, AI analysis)
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
| `system_inspector.py` | System Inspector — suspicious process and startup item scanner |
| `credential_scanner.py` | Credential Risk Assessment — weak auth and default credential detection |
| `shadow_ai.py` | Shadow AI Discovery — unauthorized AI tool detection across the network |
| `nist_owasp.py` | NIST and OWASP compliance mapping layer |
| `device_fingerprint.py` | MAC vendor lookup and device classification |
| `scan_memory.py` | Local scan history and unknown device tracking |
| `network_intel.py` | Network Intelligence engine — interfaces, ARP, netstat, traceroute |
| `plain_english.py` | Offline knowledge base — port explanations without AI |

### Risk Scoring (`engine.py`)
Score starts at 100 and deducts:
- 2 pts per open port
- 20/10/5/2/3 pts per CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN vulnerability
- Up to 10 pts per log finding
- Up to 10 pts per Shadow AI finding (MEDIUM=5, HIGH=10, capped at 20)
- Up to 5 pts per NIST Detect finding, 10 per Respond (capped at 15)

Labels: **GOOD** (80–100) / **MODERATE** (60–79) / **AT RISK** (40–59) / **CRITICAL** (0–39)

### Privacy Design
- All scanning runs locally on the user's machine
- IP addresses are redacted from scan summaries before sending to Claude API
- AI analysis is opt-in (checkbox in the form)
- Users provide their own `ANTHROPIC_API_KEY`

### Subdirectories
`ai-security-assistant/`, `log-analyzer/`, `network-mapper/`, `port-scanner/`, `vulnerability-reporter/` each mirror their root-level counterpart with their own README and sample output. They are standalone copies, not imported by the main app — the root-level `.py` files are what `app.py` actually uses.

## Current Development Phase

Phase 12 (next): Zero Trust Verification. Phases 1–11 complete. See roadmap for full phase history.

## Brand Voice — Recon AI speaks in first person

Recon AI is a single entity with a personality. All user-facing copy must follow these rules:

- Never use "we" — Recon AI is one person, not a company or team
- Always use "I", "I'll", "I found", "I checked", "I got you"
- Tone: confident, friendly, honest. Like a knowledgeable older sibling.
- Never corporate. Never robotic.
- Never scary — but never dishonest about real risks.

Examples:
❌ "We found 3 vulnerabilities"
✅ "I found 3 vulnerabilities"

❌ "We're scanning your network"
✅ "I'm scanning your network"

❌ "Your results are shown below"
✅ "Here's what I found"

❌ "We didn't send anything anywhere"
✅ "I didn't send anything anywhere. This all ran locally on your machine."

This applies to ALL templates, messages, buttons, and any user-facing text going forward.

## Standing Rules — Non-Negotiable
- The word "target" is banned from all user-facing copy and variable names. This tool is FOR the user, never pointed AT others.
- Recon AI observes and reports only. It NEVER modifies, deletes, or acts on any system. Every tool is read-only.
- Exact binary name matching only for process scanning — no partial string matching. Partial matching causes false positives.
- All new scanner modules follow this pattern: one main entry point function, returns a structured dict, includes a `__main__` block for CLI testing, has a docstring header.
- `oui.csv` and `scans.db` are gitignored — never commit them.
- Business model details are never included in public documentation.
