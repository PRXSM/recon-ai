"""
nist_owasp.py — Phase 11
NIST / OWASP Compliance Mapping.
Translates findings from Recon AI scanners into compliance framework context.

Two mapping tables:
1. PORT_MAPPINGS        — keyed by port number (int)
2. FINDING_TYPE_MAPPINGS — keyed by finding type string (snake_case)

Three functions:
- map_finding(finding)              — enrich a single finding dict
- map_findings(findings)            — enrich a list of findings
- generate_compliance_summary()     — produce nist_counts, owasp_entries, and summary

This module NEVER scans, connects to, or modifies anything.
It reads finding dicts and returns enriched dicts.
Recon AI observes and reports only. The user decides what to do.
"""

import logging

logger = logging.getLogger(__name__)

# ── Port-based mappings ────────────────────────────────────────────────────────
# Each entry must not contradict what vulnerability_reporter.py or
# credential_scanner.py already says about the same port — this layer
# adds framework context, not a different risk opinion.

PORT_MAPPINGS = {
    23: {
        "nist_categories": ["Protect"],
        "nist_explanation": (
            "Telnet gives anyone on the network a clear view of everything sent — "
            "including passwords. The NIST Protect function covers data in transit: "
            "if there's no encryption, there's no protection. I flag this so you can "
            "replace it with SSH before someone else finds it first."
        ),
        "owasp_id": "A02",
        "owasp_name": "Cryptographic Failures",
        "owasp_explanation": (
            "Telnet has no cryptography at all. Credentials and commands travel in "
            "plain text across the network. This is the definition of A02 — a failure "
            "to protect data in transit using encryption."
        ),
    },
    21: {
        "nist_categories": ["Protect"],
        "nist_explanation": (
            "FTP sends your username, password, and every file transferred in plain text. "
            "The NIST Protect function requires securing data in transit. "
            "FTP fails that requirement entirely — SFTP or FTPS are the replacements."
        ),
        "owasp_id": "A02",
        "owasp_name": "Cryptographic Failures",
        "owasp_explanation": (
            "FTP transmits credentials and file contents without any encryption. "
            "This is a direct A02 failure — sensitive data is exposed on the wire "
            "to anyone who can intercept network traffic."
        ),
    },
    80: {
        "nist_categories": ["Protect"],
        "nist_explanation": (
            "Unencrypted web traffic means anything sent to or from this service "
            "travels in plain text. If there's a login form here, credentials are exposed. "
            "NIST Protect requires securing data in transit — HTTP doesn't do that."
        ),
        "owasp_id": "A02",
        "owasp_name": "Cryptographic Failures",
        "owasp_explanation": (
            "HTTP transmits data without encryption. Login credentials, session tokens, "
            "and any sensitive data sent over this connection are visible to anyone on "
            "the network. A02 covers exactly this — failing to protect data in transit."
        ),
    },
    22: {
        "nist_categories": ["Protect", "Detect"],
        "nist_explanation": (
            "SSH is the right tool for encrypted remote access — but it needs to be "
            "configured correctly to deliver on that promise. Password authentication "
            "instead of key-based auth is a common misconfiguration that opens it to "
            "brute force. NIST covers this under both Protect (locking down the service) "
            "and Detect (monitoring for failed login attempts that signal an active attack)."
        ),
        "owasp_id": "A05",
        "owasp_name": "Security Misconfiguration",
        "owasp_explanation": (
            "SSH itself is secure. The risk is misconfiguration — password authentication "
            "left enabled, default settings unchanged, or older protocol versions still "
            "supported. A05 covers services that are fundamentally sound but poorly configured."
        ),
    },
    3389: {
        "nist_categories": ["Protect"],
        "nist_explanation": (
            "RDP exposed directly to the network — rather than behind a VPN — is a "
            "misconfiguration that attackers actively scan for. NIST Protect requires "
            "access control and authentication to be correctly implemented. "
            "Direct RDP exposure bypasses both."
        ),
        "owasp_id": "A05",
        "owasp_name": "Security Misconfiguration",
        "owasp_explanation": (
            "Exposing RDP directly to the network without requiring a VPN first is a "
            "security misconfiguration. It's the equivalent of leaving a door open that "
            "should be behind a locked gate. A05 covers exactly this type of configuration failure."
        ),
    },
    5900: {
        "nist_categories": ["Protect"],
        "nist_explanation": (
            "VNC gives full graphical control of a device. Exposing it directly on the "
            "network — even with a password — is a misconfiguration that gives attackers "
            "a high-value entry point. NIST Protect requires that remote access services "
            "not be directly reachable from untrusted networks."
        ),
        "owasp_id": "A05",
        "owasp_name": "Security Misconfiguration",
        "owasp_explanation": (
            "VNC exposed directly on the network is a security misconfiguration. "
            "It should only ever be accessible through an SSH tunnel, not bound "
            "to an address reachable from the broader network. A05 covers this failure."
        ),
    },
    161: {
        "nist_categories": ["Protect"],
        "nist_explanation": (
            "SNMP with default community strings is one of the most common network "
            "misconfigurations I find. It hands anyone who asks a full read of your "
            "device's configuration. NIST Protect covers access control and authentication "
            "— SNMPv1 and v2c with default strings provide neither."
        ),
        "owasp_id": "A05",
        "owasp_name": "Security Misconfiguration",
        "owasp_explanation": (
            "SNMP running with default community strings ('public', 'private') is a "
            "textbook A05 misconfiguration. The service exists for legitimate purposes "
            "but is deployed with factory defaults that are publicly known. "
            "SNMPv3 with proper authentication is the correct configuration."
        ),
    },
    445: {
        "nist_categories": ["Protect", "Respond"],
        "nist_explanation": (
            "SMB has been at the center of the most destructive network attacks in "
            "recent history — WannaCry, NotPetya, EternalBlue. NIST covers this under "
            "both Protect (patch SMBv1, restrict access with firewall rules) and Respond "
            "— because if this port is reachable from untrusted networks, an active "
            "incident is already a realistic scenario that needs a response plan."
        ),
        "owasp_id": "A06",
        "owasp_name": "Vulnerable and Outdated Components",
        "owasp_explanation": (
            "SMBv1 is a vulnerable and outdated component with well-documented, "
            "actively exploited vulnerabilities. EternalBlue — the exploit behind WannaCry "
            "— targets SMBv1 specifically. A06 covers exactly this: components with known "
            "vulnerabilities that should be disabled or replaced."
        ),
    },
    3306: {
        "nist_categories": ["Protect"],
        "nist_explanation": (
            "A database exposed directly to the network is a misconfiguration. "
            "MySQL should accept connections from localhost or a trusted application "
            "server only — never from the open network. NIST Protect covers this under "
            "access control: who can reach the data, and from where."
        ),
        "owasp_id": "A05",
        "owasp_name": "Security Misconfiguration",
        "owasp_explanation": (
            "MySQL listening on a network-accessible interface is an A05 misconfiguration. "
            "Databases should be bound to localhost. Exposing the database port directly "
            "removes every layer of protection between an attacker and your data."
        ),
    },
    27017: {
        "nist_categories": ["Protect"],
        "nist_explanation": (
            "MongoDB ran with no authentication enabled by default for years. "
            "Thousands of databases were exposed and wiped as a result. I flag this port "
            "because having it open on the network is a clear protection failure — the "
            "data inside should be behind authentication and not reachable from the "
            "open network."
        ),
        "owasp_id": "A05",
        "owasp_name": "Security Misconfiguration",
        "owasp_explanation": (
            "MongoDB exposed on the network without authentication enabled is a severe "
            "A05 misconfiguration. The default configuration was historically "
            "unauthenticated, and this has led to some of the largest public data "
            "exposure incidents of the past decade."
        ),
    },
}

# ── Finding-type mappings ──────────────────────────────────────────────────────
# Keys are the snake_case form of a finding's "name" field.
# map_finding() normalizes name → lowercase → spaces replaced with underscores.

FINDING_TYPE_MAPPINGS = {
    "brute_force": {
        "nist_categories": ["Detect"],
        "nist_explanation": (
            "Brute force activity means someone is systematically trying passwords "
            "against a service on your network. This is a detection event — something "
            "is actively happening. NIST Detect is about identifying exactly these kinds "
            "of anomalous events before they turn into a full compromise."
        ),
        "owasp_id": "A07",
        "owasp_name": "Identification and Authentication Failures",
        "owasp_explanation": (
            "Brute force attacks exploit weak authentication — either a service allows "
            "unlimited login attempts, or the password is weak enough to guess. "
            "A07 covers both: the failure to implement protections like account lockout, "
            "rate limiting, and strong credential requirements."
        ),
    },
    "default_credentials": {
        "nist_categories": ["Protect"],
        "nist_explanation": (
            "Default credentials are a protection failure. The device shipped with a "
            "known username and password — and it was never changed. NIST Protect "
            "requires that access controls be correctly implemented from the start. "
            "Leaving factory defaults in place is the opposite of that."
        ),
        "owasp_id": "A07",
        "owasp_name": "Identification and Authentication Failures",
        "owasp_explanation": (
            "Default credentials are a direct A07 failure. The authentication mechanism "
            "exists but is trivially bypassed because the credentials are publicly known. "
            "This is one of the most common and most preventable authentication failures "
            "I find on networks."
        ),
    },
    "unknown_device": {
        "nist_categories": ["Identify"],
        "nist_explanation": (
            "I found a device on your network that I don't recognize. The NIST Identify "
            "function starts here — you can't protect what you don't know about. "
            "Before this device can be secured, you need to know what it is, "
            "who put it there, and whether it belongs."
        ),
        "owasp_id": None,
        "owasp_name": None,
        "owasp_explanation": None,
    },
    "shadow_ai_found": {
        "nist_categories": ["Identify", "Protect"],
        "nist_explanation": (
            "An AI tool running on your network outside of your normal setup is both "
            "an asset visibility gap and a data protection concern. NIST Identify covers "
            "knowing what's on your network. NIST Protect covers knowing what data "
            "those tools are processing — and where it might be going."
        ),
        "owasp_id": None,
        "owasp_name": None,
        "owasp_explanation": None,
    },
    "malware_indicator": {
        "nist_categories": ["Respond"],
        "nist_explanation": (
            "A malware indicator means something has already gone wrong. "
            "This moves past prevention into response. NIST Respond covers containment, "
            "analysis, and mitigation of an active security event. "
            "Isolate the affected device, preserve evidence, and investigate."
        ),
        "owasp_id": None,
        "owasp_name": None,
        "owasp_explanation": None,
    },
    "ransomware_pattern": {
        "nist_categories": ["Respond", "Recover"],
        "nist_explanation": (
            "Ransomware patterns mean an active attack is likely in progress or recently "
            "occurred. NIST Respond covers stopping the spread and containing the damage. "
            "NIST Recover covers what comes next — restoring from backup, rebuilding "
            "affected systems, and returning to normal operations."
        ),
        "owasp_id": None,
        "owasp_name": None,
        "owasp_explanation": None,
    },
    "suspicious_process": {
        "nist_categories": ["Detect"],
        "nist_explanation": (
            "A process I don't recognize running on a device is a detection signal. "
            "It might be legitimate software — or it might not. NIST Detect is about "
            "identifying exactly these kinds of anomalies: something running that "
            "doesn't match what you'd expect to see."
        ),
        "owasp_id": None,
        "owasp_name": None,
        "owasp_explanation": None,
    },
    "missing_mfa": {
        "nist_categories": ["Protect"],
        "nist_explanation": (
            "Missing multi-factor authentication is a protection gap. "
            "If an attacker gets a password — through phishing, a data breach, "
            "or a weak credential — MFA is the last line of defense. "
            "NIST Protect requires layered access controls. Without MFA, "
            "one stolen password is all it takes."
        ),
        "owasp_id": "A07",
        "owasp_name": "Identification and Authentication Failures",
        "owasp_explanation": (
            "Missing MFA is a direct A07 failure. Modern authentication requires more "
            "than a password — credentials get stolen, guessed, and reused across "
            "services constantly. A07 explicitly calls out the absence of effective "
            "multi-factor authentication as an authentication failure."
        ),
    },
}

_DEFAULT_MAPPING = {
    "nist_categories": ["Identify"],
    "nist_explanation": (
        "I found something on your network that I haven't seen before. "
        "The first step is always to understand what it is."
    ),
    "owasp_id": None,
    "owasp_name": None,
    "owasp_explanation": None,
}


def map_finding(finding):
    """
    Enrich a single finding dict with NIST and OWASP context.

    Lookup order:
    1. PORT_MAPPINGS   — by finding["port"] when it is an int
    2. FINDING_TYPE_MAPPINGS — by finding["name"] normalized to snake_case
    3. Default fallback — nist_categories: ["Identify"] with a generic explanation

    Returns the finding dict extended with nist_categories (always a list),
    nist_explanation, owasp_id, owasp_name, owasp_explanation.
    """
    enriched = dict(finding)

    # Port lookup
    port = finding.get("port")
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = None
    if port is not None and port in PORT_MAPPINGS:
        enriched.update(PORT_MAPPINGS[port])
        return enriched

    # Finding-type lookup via normalized name
    name = finding.get("name", "")
    if name:
        key = name.lower().replace(" ", "_")
        if key in FINDING_TYPE_MAPPINGS:
            enriched.update(FINDING_TYPE_MAPPINGS[key])
            return enriched

    enriched.update(_DEFAULT_MAPPING)
    return enriched


def map_findings(findings):
    """
    Enrich a list of finding dicts. Returns the enriched list.
    """
    return [map_finding(f) for f in findings]


def generate_compliance_summary(findings):
    """
    Takes a list of enriched findings and returns a compliance summary dict.

    Returns:
        dict with:
          nist_counts   — count per NIST category (all five always present)
          owasp_entries — list of unique OWASP entries found, sorted by ID
          summary       — plain English paragraph in Recon AI first person voice
    """
    nist_counts = {
        "Identify": 0,
        "Protect": 0,
        "Detect": 0,
        "Respond": 0,
        "Recover": 0,
    }
    seen_owasp = {}

    for finding in findings:
        for category in finding.get("nist_categories", []):
            if category in nist_counts:
                nist_counts[category] += 1

        owasp_id = finding.get("owasp_id")
        if owasp_id and owasp_id not in seen_owasp:
            seen_owasp[owasp_id] = finding.get("owasp_name", "")

    owasp_entries = [
        {"id": oid, "name": name}
        for oid, name in sorted(seen_owasp.items())
    ]

    total = len(findings)

    if total == 0:
        summary = (
            "I didn't find any findings to map. Run a scan first and "
            "pass the results through here for compliance context."
        )
    else:
        active_nist = [k for k, v in nist_counts.items() if v > 0]
        nist_str = ", ".join(active_nist) if active_nist else "none"
        owasp_str = (
            ", ".join(f"{e['id']} ({e['name']})" for e in owasp_entries)
            if owasp_entries else "none"
        )

        respond_count = nist_counts["Respond"]
        protect_count = nist_counts["Protect"]
        detect_count  = nist_counts["Detect"]

        if respond_count > 0:
            lead = (
                f"I found {respond_count} finding(s) in the Respond category — "
                "these indicate active or recent security events that need immediate attention. "
            )
        elif protect_count > 0:
            lead = (
                f"Most of what I found ({protect_count} finding(s)) falls under Protect — "
                "gaps in your defenses that haven't been exploited yet, but need to be closed. "
            )
        elif detect_count > 0:
            lead = (
                f"I found {detect_count} finding(s) in the Detect category — "
                "anomalies that need investigation to rule out active compromise. "
            )
        else:
            lead = f"I mapped {total} finding(s) to NIST and OWASP frameworks. "

        summary = (
            f"{lead}"
            f"NIST functions covered: {nist_str}. "
            f"OWASP Top 10 entries referenced: {owasp_str}."
        )

    logger.info(
        f"Compliance summary: {total} finding(s), "
        f"NIST counts={nist_counts}, OWASP entries={[e['id'] for e in owasp_entries]}"
    )

    return {
        "nist_counts": nist_counts,
        "owasp_entries": owasp_entries,
        "summary": summary,
    }


if __name__ == "__main__":
    import json

    test_findings = [
        {"port": 23,    "name": "Telnet",         "service": "Telnet", "risk": "CRITICAL"},
        {"port": 445,   "name": "SMB",             "service": "SMB",    "risk": "CRITICAL"},
        {"port": 22,    "name": "SSH",             "service": "SSH",    "risk": "LOW"},
        {"port": 3306,  "name": "MySQL",           "service": "MySQL",  "risk": "CRITICAL"},
        {"port": 27017, "name": "MongoDB",         "service": "MongoDB","risk": "CRITICAL"},
        {"name": "Brute Force",          "risk": "HIGH"},
        {"name": "Default Credentials",  "risk": "CRITICAL"},
        {"name": "Missing MFA",          "risk": "MEDIUM"},
        {"name": "Unknown Device",       "risk": "LOW"},
        {"name": "Shadow AI Found",      "risk": "MEDIUM"},
        {"name": "Ransomware Pattern",   "risk": "CRITICAL"},
        {"name": "Something Brand New",  "risk": "LOW"},
    ]

    enriched = map_findings(test_findings)
    compliance = generate_compliance_summary(enriched)

    print(json.dumps({"findings": enriched, "compliance": compliance}, indent=2))
