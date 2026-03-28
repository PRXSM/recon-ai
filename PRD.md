# Recon AI — Product Requirements Document

## What Recon AI IS
- A local-first network security platform for non-technical users
- A plain English explainer for every security finding
- A guardian that remembers, watches, and alerts — quietly
- A privacy-first tool where the user controls everything
- A defensive tool built FOR the user, never pointed AT others

## What Recon AI IS NOT
- Not an offensive security tool
- Not a hacking tool or penetration testing framework
- Not a replacement for enterprise security solutions
- Not a tool that stores user data on any external server
- Not a tool that takes any action on the user's system — it advises, the user decides
- Not built for scanning networks you don't own

## Core User Promise
Every person who opens Recon AI should be able to:
1. Run a scan in under 60 seconds
2. Understand every finding without any technical background
3. Know exactly what to do next
4. Trust that their data is safe

## What Success Looks Like
A non-technical user opens Recon AI, runs a scan, reads the results, fixes one thing, and feels confident — not overwhelmed. They come back next week because they trust it.

## Scope Boundaries
These features are explicitly OUT OF SCOPE until Phase 9+:
- User accounts and authentication
- Cloud storage of any scan data
- Real-time continuous monitoring daemon
- Mobile app (iOS/Android)
- Browser extension
- Packet capture / deep packet inspection
- CVE database integration
- VirusTotal / AbuseIPDB integration

These are good ideas. They have a phase. They don't get built early.

## Non-Negotiables (can never change)
- The word "target" is banned from all user-facing copy
- AI analysis is always opt-in, never automatic
- User always sees a preview of what will be sent to AI before it is sent
- No action is ever taken on the user's system without their explicit choice
- Offline mode is always free, forever
- Privacy is never traded for convenience
