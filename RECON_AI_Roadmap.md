# ⚡ RECON AI
**Vision, Roadmap & Product Strategy**  
Built by Asama Azim | [github.com/PRXSM/recon-ai](https://github.com/PRXSM/recon-ai)  
March 2026 — Present

---

## 1. The Mission

Recon AI is an AI-powered network security platform designed for everyone — not just security professionals. The goal is simple: take every complex, overwhelming security tool that exists today and translate it into plain English that any human being can understand and act on.

Most security tools are built for experts. Recon AI is built for everyone else — and for experts who want to work faster.

The north star vision: Recon AI becomes the silent defender against his own kind — a tool that protects everyday people from real threats, including AI-powered attacks, explained entirely in plain English. Not just a scanner you run once. A guardian that watches, remembers, and protects quietly in the background.

### The North Star

Every decision, every feature, every line of code is built with one person in mind:

> "The school IT admin in rural Virginia. One person managing 200 devices, no security budget, no security training. Every Monday morning Recon AI sends them a simple email — green, yellow, or red. That's it."

---

## 2. Core Principles

### Privacy First — Always
- Your IP address never leaves your machine
- Only anonymized findings are sent for AI analysis — and only if you choose to
- Offline mode available — nothing sent anywhere
- Think of it as a mirror, not a microscope pointed at others
- This tool is FOR you, not pointed AT you

### Accessibility Over Complexity
- Every technical finding explained in plain English
- Non-technical users get answers, not jargon
- Technical users get speed and depth
- Both audiences served by the same tool

### Guided Remediation — Not Just Diagnosis
- Every finding includes: EXPLAIN, RISK, FIX, VERIFY
- Never leave someone with a problem and no solution
- Step-by-step fix instructions specific to their OS
- Verification steps so they know it worked

### Legal & Ethical Foundation
- Authorization confirmation required before every scan
- Clear terms of service — only scan networks you own
- CFAA compliant disclaimer built into the product
- Transparent about what data is used and how

### Privacy as Amanah (Trustworthiness)
- User data is treated as a sacred trust
- Nothing is sent anywhere without explicit user consent and a preview of exactly what will be shared
- Three AI modes give users full control over their data at all times
- Standard Mode: anonymized findings sent to Claude API, consent required
- Private Mode: fully local AI, zero data leaves the machine, ever
- Offline Mode: no AI, built-in knowledge base only, always free
- The word 'target' is banned from all user-facing copy — this tool is FOR the user, never pointed AT others

---

## 3. Who Recon AI Is For

| User Type | What Recon AI Does For Them |
|---|---|
| Small Business Owner | Tells them if their network is safe in plain English — no IT degree required |
| School IT Admin | Weekly digest — green, yellow, or red. Simple. Actionable. |
| Healthcare Clinic | Confirms patient data is protected without needing a security team |
| Home User | Tells them if an unknown device is on their WiFi |
| Junior IT Professional | Explains findings they don't fully understand yet — builds their knowledge |
| Security Professional | Faster workflow — AI explains and summarizes, they focus on decisions |
| Freelance IT Consultant | Professional reports generated in minutes, not hours |

---

## 4. What Recon AI Does

Recon AI is built on 5 core tools that work independently or together.

### The 5 Core Tools

| Tool | Description |
|---|---|
| **Port Scanner** | Scans ports 1–1024. Finds every open door on the network. Identifies services running on each port. |
| **Network Mapper** | Discovers all live devices on a subnet. Answers: what's on my network and should it be there? |
| **Log Analyzer** | Reads system log files and detects 30+ threat patterns including brute force, ransomware indicators, privilege escalation, and crypto mining. |
| **Vulnerability Reporter** | Maps open ports to known vulnerabilities. Explains the risk and recommends fixes. |
| **AI Assistant** | Takes all findings from all tools and explains everything in plain English using Claude AI. Follows EXPLAIN → RISK → FIX → VERIFY structure for every finding. |

### The Architecture

| File | Role |
|---|---|
| `engine.py` | Unified brain connecting all 5 tools. Calculates network health score (0–100). |
| `app.py` | Flask web interface. Handles routes, validation, error handling. |
| `index.html` | Clean scan form with privacy notices and legal authorization. |
| `results.html` | Results display with risk score, grouped findings, and AI analysis. |

### AI Analysis Structure

Every finding is explained using a consistent 4-part structure:

- **EXPLAIN** — What is this in plain English?
- **RISK** — Why does it matter? Who could exploit it and how?
- **FIX** — Exact step-by-step instructions for their specific OS
- **VERIFY** — How do they confirm the fix worked?

---

## 5. Privacy Architecture

Privacy is not a feature in Recon AI — it is the foundation.

- IP addresses are REDACTED before any data reaches Claude API
- The scan runs locally on the user's machine
- AI analysis is optional — user explicitly opts in
- Offline mode available — zero data leaves the machine
- No scan data is stored on any server
- User's API key used for local version — data goes to their Anthropic account, not ours

For enterprise users (hospitals, banks, government): Recon AI can run in fully offline mode with built-in plain English explanations requiring zero API calls. This makes it suitable for high-compliance environments.

---

## 6. Full Roadmap

| Phase | Description | Status |
|---|---|---|
| **Phase 1** | 5 Core Tools — Port Scanner, Network Mapper, Log Analyzer, Vulnerability Reporter, AI Assistant | ✅ COMPLETE |
| **Phase 2** | Unified Engine — All 5 tools connected, risk score, OS detection, IP redaction | ✅ COMPLETE |
| **Phase 3** | Flask Web Interface — Browser UI, privacy messaging, legal checkbox, AI opt-in, offline mode | ✅ COMPLETE |
| **Phase 4** | Make It Smarter — 30+ threat patterns, cross-tool correlation, EXPLAIN/RISK/FIX/VERIFY, markdown rendering, downloadable reports | ✅ COMPLETE |
| **Phase 5** | Network Intelligence — interfaces, ARP table, netstat, traceroute, accordion UI, CIDR validation, verdict banners, simplified AI prompt, offline VERIFY + Dig Deeper | ✅ COMPLETE |
| **Phase 6** | The Guardian Update — scan memory, unknown device alerts, three AI mode selector (Standard/Private/Offline) | 🔨 NEXT |
| **Phase 7** | Deep Scan Mode — full 65,535 port scanning with threading, Simple vs Deep scan profiles | 📋 PLANNED |
| **Phase 8** | System Inspector — suspicious process detector, startup item analyzer, two scan profiles | 📋 PLANNED |
| **Phase 9** | App Complete Milestone — full audit, security hardening, Jawad code review | 📋 PLANNED |
| **Phase 10** | UI Redesign — Aroosha designs and executes full interface overhaul, single page dashboard, mobile responsive | 📋 PLANNED |
| **Phase 11** | Deploy Online — HTTPS, rate limiting, GDPR compliance, weekly digest email, plain English threat feed | 📋 PLANNED |
| **Phase 12** | Business Model — freemium launch, premium Private Mode (local Ollama AI), scheduled scans, organizational accounts, multi-language | 📋 PLANNED |

---

## 7. The Guardian Features
These are the features that transform Recon AI from a scanner into a guardian.

### Phase 6 — The Guardian Update
- **Scan Memory** — local database stores every scan. Returning users see what changed since last time. New ports, fixed issues, new devices — all tracked.
- **Unknown Device Alert** — when a new MAC address appears on the network that wasn't there before, Recon AI flags it immediately in plain English: "New device found — do you recognize it?"
- **Three AI Mode Selector** — user chooses once at setup:
  - Standard Mode: Claude API, consent preview shown before sending
  - Private Mode: local Ollama model, zero data leaves the machine (premium)
  - Offline Mode: built-in knowledge base, always free, zero API calls

### Phase 7 — Deep Scan
- Full 65,535 port scanning using threading
- Simple profile: ports 1-1024, fast
- Deep profile: all ports, thorough
- Progress indicator during long scans

### Phase 8 — System Inspector
- Suspicious process detector
- Startup item analyzer
- Not a full antivirus — smart flagging only
- Two scan profiles: Simple and Deep

### Phase 9 — App Complete
- Full security audit using hardening prompts
- Jawad professional code review
- Performance optimization
- Bug fixes and edge case handling
- Documentation complete

### Phase 10 — UI Redesign (Aroosha)
- Single page dashboard — everything visible at once
- Real-time scan progress with loading states
- Results appear section by section as scan completes
- Mobile responsive design
- Trust Score displayed prominently
- Clean, friendly, non-scary visual design

### Phase 11 — Deploy Online
- reconai.io hosted version
- HTTPS enforced
- Rate limiting on all endpoints
- GDPR compliance
- Weekly digest email — Monday morning, green/yellow/red, three sentences
- Plain English Threat Feed — weekly real-world threat briefing cross-referenced against the user's actual network

### Phase 12 — Business Model
- Freemium model — core tools always free
- Premium tier: Private Mode (local Ollama AI), scheduled automated scans, organizational accounts, priority support
- Open source on GitHub
- Product Hunt launch
- Multi-language: Arabic, Spanish, French

---

## 8. Security Standards

These are non-negotiable for Recon AI before any public release:

- API keys stored in environment variables only — never in frontend code, never committed to GitHub
- All user input validated and sanitized — IP addresses, log paths, traceroute hosts
- Rate limiting on all public endpoints before Phase 11 launch
- Authentication via Clerk, Firebase, or Supabase — never built from scratch
- HTTPS enforced on all deployed versions
- Full security audit pass before launch using hardening prompts
- No data stored on any server without explicit user consent

---

## 9. The Market Opportunity

The cybersecurity tools market splits into two groups with a massive gap in between:

| Category | Description |
|---|---|
| **Enterprise tools** (Splunk, CrowdStrike, Palo Alto) | Cost thousands per month. Built for Fortune 500 companies with dedicated security teams. |
| **DIY tools** (Nmap, Wireshark, Metasploit) | Free but require deep expertise. Built for technical professionals. |

**The gap in the middle** — small businesses, schools, clinics, non-profits, home users — tens of millions of people worldwide who need simple, affordable, plain-English network security. Nobody is serving them well.

**Recon AI lives in that gap.**

---

## 10. Technology Stack

| Technology | Role |
|---|---|
| **Python** | Core scanning engine and all 5 tools |
| **Flask** | Web interface and routing |
| **Claude API (Anthropic)** | AI analysis and plain English explanations |
| **HTML/CSS** | Frontend interface |
| **Git/GitHub** | Version control at github.com/PRXSM/recon-ai |
| **Virtual Environment (venv)** | Dependency isolation |

---

## 11. Legal Considerations

### Before Local Release
- LICENSE file — open source terms
- Disclaimer in README — authorized use only
- Terms of use in app — authorization checkbox
- Privacy policy — what is/isn't collected

### Before Web Launch
- Privacy Policy page — legally required
- Terms of Service page
- GDPR compliance for European users
- Rate limiting to prevent abuse
- User accounts for legal accountability
- HTTPS — encrypted connections required
- Abuse reporting contact
- Tech lawyer review — one hour consultation recommended

> **Important:** The Computer Fraud and Abuse Act (CFAA) makes unauthorized network scanning illegal. Recon AI's authorization checkbox is our first line of legal protection. This must be enforced at every entry point.

---

## 12. The Vision — In One Paragraph

*Recon AI will become the silent defender against his own kind. A tool that protects everyday people from real threats — including AI-powered attacks — explained entirely in plain English. Not just a scanner. A guardian that watches, remembers, and speaks only when it needs to. For the small business with no IT team. For the clinic protecting patient data. For the parent who wants to know if a stranger is on their WiFi. For the school IT admin in rural Virginia who just needs green, yellow, or red every Monday morning. They all deserve to feel safe. Recon AI is built to make that happen — for everyone, everywhere, in sha Allah.*

**Still building. 🚀**

[github.com/PRXSM/recon-ai](https://github.com/PRXSM/recon-ai)
