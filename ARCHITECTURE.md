# Recon AI — Architecture Document

## Project Structure

recon-ai/
├── app.py                 # Flask app — all routes and request handling
├── engine.py              # Unified brain — risk scoring, scan summary, report builder
├── port_scanner.py        # TCP connect scan, ports 1–1024
├── network_mapper.py      # Ping-based host discovery, CIDR support
├── log_analyzer.py        # 30+ threat pattern detection via regex
├── vulnerability_reporter.py  # Port → vulnerability database, cross-tool correlation
├── ai_assistant.py        # Claude API integration, system prompt, analyze_with_ai()
├── plain_english.py       # Offline knowledge base — 14 ports, EXPLAIN/RISK/FIX/VERIFY/DIG DEEPER
├── network_intel.py       # Network Intelligence engine — interfaces, ARP, netstat, traceroute
├── templates/
│   ├── index.html         # Scan form — tool selector, IP input, intensity, legal checkbox
│   ├── results.html       # Results page — risk score, findings, AI analysis, offline explanations
│   ├── network_intel.html # Interfaces dashboard
│   ├── arp_table.html     # ARP table — devices on network
│   ├── netstat.html       # Active connections
│   └── traceroute.html    # Route tracing
├── .env                   # API key — never committed, never in frontend
├── .env.example           # Template for new users
├── requirements.txt       # Dependencies
├── CLAUDE.md              # AI rules — non-negotiables for Claude Code
├── PRD.md                 # Product requirements — what Recon AI is and is not
├── ARCHITECTURE.md        # This file
├── RECON_AI_Roadmap.md    # Full roadmap and vision
└── README.md              # Public-facing project documentation

## Data Flow

User enters IP in browser
        ↓
app.py validates input (is_valid_ip)
        ↓
Selected tools run in sequence:
  port_scanner.py → open ports list
  network_mapper.py → live devices list
  log_analyzer.py → threat findings list
  vulnerability_reporter.py → vuln list
        ↓
engine.py calculates risk score (0-100)
        ↓
If AI selected:
  engine.py builds scan summary
  IP address REDACTED from summary
  User sees preview of what will be sent
  User confirms → ai_assistant.py sends
  to Claude API → markdown rendered
If offline:
  plain_english.py explains each port
        ↓
results.html renders everything
        ↓
User can download full .txt report

## Key Design Rules
- All scanning happens locally on the user's machine
- IP address is redacted before any data reaches Claude API
- AI analysis is opt-in only
- No data is stored between sessions (Phase 6 adds local-only scan memory)
- Flask runs in production mode (debug=False always)
- User input is validated before any tool runs

## Phase 6 Additions (coming next)
- SQLite local database for scan history
- Unknown device detection via MAC address comparison
- Three AI mode selector in settings
- Scan comparison — current vs previous

## Environment Variables
ANTHROPIC_API_KEY — required for Standard Mode AI analysis only.
All other features work without it.
Stored in root .env file only.
Never in subfolder .env files.
Never committed to GitHub.
