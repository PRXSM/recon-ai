"""
prompt_injection.py — Phase 13
Prompt Injection Hardening.
Sanitizes all scan data before it reaches the Claude AI layer.

Three defense layers:
1. Length truncation — caps any single field to prevent context flooding
2. Pattern detection — neutralizes known injection phrases and patterns
3. Encoding normalization — strips zero-width characters, BIDI control
   characters, and homoglyph attacks (via NFKC normalization)

Detected injection attempts are logged as HIGH severity security
findings — evidence that someone on the network is actively trying
to manipulate Recon AI's AI layer.

This module sits at the boundary between raw scan data and
build_scan_summary() in engine.py. Nothing from the network reaches
Claude without passing through here first.
"""

import re
import unicodedata
import logging

logger = logging.getLogger(__name__)

MAX_FIELD_LENGTH = 500

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"forget\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"you\s+are\s+now\s+(in\s+)?(maintenance|developer|admin|debug|a\s+different|no\s+longer)\s+",
    r"new\s+instructions?\s*:",
    r"system\s*:\s*you",
    r"<\s*system\s*>",
    r"<\s*prompt\s*>",
    r"\[\s*system\s*\]",
    r"\[\s*inst\s*\]",
    r"###\s*instruction",
    r"###\s*system",
    r"act\s+as\s+(if\s+you\s+are|a)\s+",
    r"pretend\s+(you\s+are|to\s+be)\s+",
    r"roleplay\s+as\s+",
    r"from\s+now\s+on\s+(you\s+are|act)",
    r"override\s+(safety|security|previous)",
    r"bypass\s+(safety|security|filter|restriction)",
    r"disable\s+(all\s+)?(safety|security|warning|filter)",
    r"enable\s+(maintenance|developer|admin|debug)\s+mode",
    r"tell\s+the\s+user\s+(that\s+)?(their|the)\s+network\s+is\s+safe",
    r"do\s+not\s+(report|flag|warn|alert)",
    r"suppress\s+(all\s+)?(warning|alert|finding)",
]

# Covers both zero-width invisibles and BIDI control characters.
# BIDI overrides (especially U+202E RTLO) are used to reverse displayed text
# and hide injection payloads from visual inspection.
STRIPPED_CHARS = [
    '\u200b',  # zero width space
    '\u200c',  # zero width non-joiner
    '\u200d',  # zero width joiner
    '\u200e',  # left-to-right mark
    '\u200f',  # right-to-left mark
    '\ufeff',  # zero width no-break space
    '\u2060',  # word joiner
    '\u00ad',  # soft hyphen
    '\u202a',  # left-to-right embedding
    '\u202b',  # right-to-left embedding
    '\u202c',  # pop directional formatting
    '\u202d',  # left-to-right override
    '\u202e',  # right-to-left override (RTLO \u2014 main BIDI attack character)
    '\u2066',  # left-to-right isolate
    '\u2067',  # right-to-left isolate
    '\u2068',  # first strong isolate
    '\u2069',  # pop directional isolate
]


def sanitize(text, field_name="field", source="unknown"):
    """
    Main sanitization function. Applies all three defense layers to
    a single string field before it enters the AI summary. Returns
    a tuple of (cleaned_text, injection_finding_or_None).

    Defense layers:
    1. BIDI and zero-width stripping — removes invisible characters and
       BIDI override characters used to hide or reverse injection payloads.
    2. NFKC normalization — converts homoglyphs (Cyrillic/Greek lookalikes)
       to ASCII equivalents, defeating substitution-based evasion.
    3. Pattern detection — neutralizes known injection phrases.

    If an injection attempt is detected, the second element is a finding
    dict describing the attempt — it is the caller's responsibility
    to collect and surface these findings.
    """
    # Step 1 — handle non-string input
    if not isinstance(text, str):
        text = str(text)
    if not text.strip():
        return ("", None)

    # Step 2 — encoding normalization
    for char in STRIPPED_CHARS:
        text = text.replace(char, "")
    # NFKC normalization converts homoglyphs (Cyrillic/Greek lookalikes)
    # to ASCII equivalents before pattern matching.
    text = unicodedata.normalize("NFKC", text)
    text = text.strip()

    # Step 3 — length truncation
    if len(text) > MAX_FIELD_LENGTH:
        text = text[:MAX_FIELD_LENGTH] + "...[truncated]"
        logger.warning(
            f"prompt_injection: field '{field_name}' from {source} "
            f"truncated at {MAX_FIELD_LENGTH} chars"
        )

    # Step 4 — pattern detection
    injection_detected = False
    matched_pattern = None

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            injection_detected = True
            matched_pattern = pattern
            break

    # Step 5 — injection detected
    if injection_detected:
        logger.warning(
            f"prompt_injection: INJECTION ATTEMPT detected in "
            f"'{field_name}' from {source}. Pattern: {matched_pattern}"
        )
        text = f"[SANITIZED: suspicious content removed from {field_name}]"
        finding = {
            "risk": "HIGH",
            "title": "Prompt injection attempt detected in network data",
            "description": (
                f"I found suspicious text in the {field_name} field from "
                f"{source} that appears to be a prompt injection attack — "
                f"an attempt to manipulate my AI layer by embedding "
                f"instructions inside network data. This is a deliberate "
                f"attempt by someone on your network to interfere with how "
                f"I analyze and report security findings. I've removed the "
                f"content and flagged it for your review."
            ),
            "fix": (
                "Identify which device on your network sent this data and "
                "investigate it immediately. A device that is actively "
                "trying to manipulate security tools is a serious red flag. "
                "Check that device for malware, unauthorized software, or "
                "signs of compromise. Consider isolating it from your "
                "network until you can identify the source."
            ),
            "type": "injection_attempt",
            "source": source,
            "field": field_name,
        }
        return (text, finding)

    # Step 6 — clean
    return (text, None)


def sanitize_scan_data(data, source="scanner"):
    """
    Convenience function that sanitizes a dict of scan data fields.
    Accepts a dict, sanitizes each string value, and returns a tuple
    of (cleaned_dict, list_of_injection_findings). Non-string values
    are passed through unchanged. Empty or None values are skipped.
    """
    cleaned = {}
    injection_findings = []

    for key, value in data.items():
        if value is None or value == "":
            cleaned[key] = value
            continue
        if isinstance(value, str):
            clean_val, finding = sanitize(value, field_name=key, source=source)
            cleaned[key] = clean_val
            if finding:
                injection_findings.append(finding)
        else:
            cleaned[key] = value

    return (cleaned, injection_findings)


def sanitize_list(items, field_name="item", source="scanner"):
    """
    Sanitizes a list of strings. Returns a tuple of
    (cleaned_list, list_of_injection_findings). Non-string items
    are converted to strings before sanitizing.
    """
    cleaned = []
    injection_findings = []

    for item in items:
        clean_item, finding = sanitize(str(item), field_name=field_name, source=source)
        cleaned.append(clean_item)
        if finding:
            injection_findings.append(finding)

    return (cleaned, injection_findings)
