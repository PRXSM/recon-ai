"""
firewall_check.py — Phase 14
Firewall Status Check.
Checks whether the local machine's firewall is enabled.

This is one of the most impactful findings for non-technical users — a
disabled firewall means the machine has no barrier against incoming
connections from the local network.

This module is read-only. It runs OS commands to query firewall state
and reports the result. It never modifies any firewall configuration.
Recon AI observes and reports only.
"""

import platform
import subprocess
import logging

logger = logging.getLogger(__name__)


def run_firewall_check():
    """
    Checks whether the local machine's firewall is enabled.
    Detects the OS and runs the appropriate system command.

    Returns a dict with:
        enabled (bool or None): True if on, False if off, None if unknown
        os (str): the detected OS name
        status_text (str): first 200 chars of raw command output
        risk (str): "HIGH" if disabled, "LOW" if enabled, "UNKNOWN" if None
        summary (str): plain English first-person sentence

    macOS uses Application Layer Firewall via `defaults read` — no elevated
    privileges required.
    """
    os_name = platform.system()
    enabled = None
    status_text = ""

    try:
        if os_name == "Darwin":
            # Use Application Layer Firewall state via defaults — no sudo required.
            # Returns: 0 = off, 1 = on (specific services), 2 = stealth mode (on)
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout.strip()
            status_text = output[:200]
            if output in ("1", "2"):
                enabled = True
            elif output == "0":
                enabled = False
            else:
                enabled = None

        elif os_name == "Windows":
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout[:200]
            status_text = output
            enabled = "State                                 ON" in result.stdout

        elif os_name == "Linux":
            try:
                result = subprocess.run(
                    ["ufw", "status"],
                    capture_output=True, text=True, timeout=5
                )
                output = result.stdout[:200]
                status_text = output
                enabled = "Status: active" in output
            except FileNotFoundError:
                # ufw not available — fall back to iptables
                result = subprocess.run(
                    ["iptables", "-L", "-n"],
                    capture_output=True, text=True, timeout=5
                )
                output = result.stdout[:200]
                status_text = output
                # iptables returns something even when default ACCEPT — treat
                # as indeterminate since default policy needs deeper parsing
                enabled = None

        else:
            logger.info(f"firewall_check: unsupported OS: {os_name}")

    except FileNotFoundError:
        logger.info(f"firewall_check: firewall command not found on {os_name}")
    except subprocess.TimeoutExpired:
        logger.warning("firewall_check: command timed out")
    except Exception as e:
        logger.warning(f"firewall_check: unexpected error: {e}")

    if enabled is True:
        risk = "LOW"
        summary = "I checked your firewall and it's on. Good — it's filtering incoming connections."
    elif enabled is False:
        risk = "HIGH"
        summary = (
            "I found your firewall is turned off. This means your machine has no barrier "
            "against incoming connections from your network."
        )
    else:
        risk = "UNKNOWN"
        summary = "I wasn't able to check your firewall status on this system."

    return {
        "enabled": enabled,
        "os": os_name,
        "status_text": status_text,
        "risk": risk,
        "summary": summary,
    }


if __name__ == "__main__":
    import json
    result = run_firewall_check()
    print(json.dumps(result, indent=2, default=str))
