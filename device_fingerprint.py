"""
device_fingerprint.py — Phase 7+
Identifies devices on the network by:
1. Looking up MAC vendor from OUI database
2. Resolving hostname via reverse DNS
3. Assigning a device type emoji and label based on vendor name
"""

import csv
import socket
import os
import logging

logger = logging.getLogger(__name__)

OUI_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "oui.csv"
)

# Load OUI database into memory once
_oui_cache = {}

def load_oui_database():
    """
    Load the IEEE OUI CSV file into a dict: {prefix: vendor_name}
    Prefix format: "AA:BB:CC" uppercase
    Called once on first use.
    """
    global _oui_cache
    if _oui_cache:
        return _oui_cache
    if not os.path.exists(OUI_PATH):
        logger.warning("OUI database not found. Device vendor lookup disabled.")
        return {}
    try:
        with open(OUI_PATH, encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                assignment = row.get("Assignment", "").upper().strip()
                org = row.get("Organization Name", "Unknown").strip()
                if len(assignment) == 6:
                    prefix = (
                        assignment[0:2] + ":" +
                        assignment[2:4] + ":" +
                        assignment[4:6]
                    )
                    _oui_cache[prefix] = org
        logger.info(f"OUI database loaded: {len(_oui_cache)} vendors")
    except Exception as e:
        logger.error(f"Failed to load OUI database: {e}")
    return _oui_cache

def get_vendor(mac):
    """
    Look up the manufacturer of a device from its MAC address.
    Returns vendor name string or "Unknown" if not found.
    mac format: "aa:bb:cc:dd:ee:ff"
    """
    if not mac or mac == "(incomplete)":
        return "Unknown"
    try:
        prefix = mac.upper()[0:8]
        db = load_oui_database()
        return db.get(prefix, "Unknown")
    except Exception:
        return "Unknown"

def get_hostname(ip):
    """
    Try to resolve a hostname for an IP via reverse DNS.
    Returns hostname string or None if not resolvable.
    Times out quickly — never slows down the scan.
    """
    try:
        socket.setdefaulttimeout(1)
        hostname = socket.gethostbyaddr(str(ip))[0]
        if hostname and hostname != str(ip):
            return hostname
        return None
    except Exception:
        return None

def get_device_emoji(vendor):
    """
    Return an emoji and device type label based on vendor name.
    """
    if not vendor or vendor == "Unknown":
        return "🔌", "Unknown device"

    v = vendor.lower()

    if any(x in v for x in ["apple"]):
        return "🍎", "Apple device"
    if any(x in v for x in ["samsung"]):
        return "📱", "Samsung device"
    if any(x in v for x in ["google"]):
        return "🔵", "Google device"
    if any(x in v for x in ["amazon"]):
        return "📦", "Amazon device"
    if any(x in v for x in ["sony"]):
        return "🎮", "Sony device"
    if any(x in v for x in ["microsoft"]):
        return "🪟", "Microsoft device"
    if any(x in v for x in [
        "netgear", "tp-link", "tplink", "asus", "linksys",
        "ubiquiti", "cisco", "arris", "motorola", "eero", "orbi"
    ]):
        return "📡", "Router or network device"
    if any(x in v for x in ["nintendo"]):
        return "🎮", "Nintendo device"
    if any(x in v for x in [
        "intel", "realtek", "broadcom", "dell", "hp ",
        "hewlett", "lenovo", "acer"
    ]):
        return "💻", "Computer or laptop"
    if any(x in v for x in ["espressif", "raspberry", "arduino", "particle"]):
        return "⚙️", "IoT or smart device"

    return "🔌", f"Device by {vendor}"

def fingerprint_device(ip, mac=None):
    """
    Main function — given an IP and optional MAC address,
    return a complete device profile dict.

    Returns:
    {
        "ip": "10.0.0.22",
        "mac": "4e:21:69:a3:36:f9",
        "vendor": "Apple Inc",
        "hostname": "asamas-iphone.local",
        "emoji": "🍎",
        "label": "Apple device",
        "display": "🍎 Apple device",
    }
    """
    vendor = get_vendor(mac) if mac else "Unknown"
    hostname = get_hostname(ip)
    emoji, label = get_device_emoji(vendor)
    display_name = hostname or label

    return {
        "ip": str(ip),
        "mac": mac or "",
        "vendor": vendor,
        "hostname": hostname or "",
        "emoji": emoji,
        "label": label,
        "display": f"{emoji} {display_name}",
    }
