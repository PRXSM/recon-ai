"""
scan_memory.py — Phase 6
Local SQLite database for scan history and unknown device detection.
Database: scans.db (project root, never committed)
Retention: 90 days — old scans deleted automatically.
"""

import sqlite3
import json
import datetime
import os
import re

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scans.db")
RETENTION_DAYS = 90


def init_db():
    """Create scans.db and the scans table if they don't exist."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT NOT NULL,
                ip_scanned      TEXT NOT NULL,
                risk_score      INTEGER,
                score_label     TEXT,
                open_ports      TEXT,
                devices_found   TEXT,
                vulnerabilities TEXT,
                tools_used      TEXT
            )
        """)
        # WAL mode allows concurrent reads and writes — prevents locking
        # under Flask's threaded mode.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.commit()


def save_scan(report_data, ip, timestamp):
    """
    Save a scan result to the database.
    Extracts fields from report_data, converts lists/dicts to JSON strings.
    Calls cleanup_old_scans() after saving to enforce 90-day retention.
    """
    init_db()

    open_ports      = json.dumps(report_data.get("open_ports", []))
    devices_found   = json.dumps(report_data.get("live_hosts", []))
    vulnerabilities = json.dumps(report_data.get("vulnerabilities", []))
    tools_used      = json.dumps(report_data.get("tools_run", []))
    risk_score      = report_data.get("score")
    score_label     = report_data.get("score_label")

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO scans
                (timestamp, ip_scanned, risk_score, score_label,
                 open_ports, devices_found, vulnerabilities, tools_used)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, ip, risk_score, score_label,
            open_ports, devices_found, vulnerabilities, tools_used
        ))
        conn.commit()

    cleanup_old_scans()


def get_last_scan(ip):
    """
    Return the most recent scan for a given IP address as a dict.
    Returns None if no previous scan exists for this IP.
    JSON columns are parsed back to lists/dicts automatically.
    """
    init_db()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("""
            SELECT * FROM scans
            WHERE ip_scanned = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (ip,)).fetchone()

    if row is None:
        return None

    return _row_to_dict(row)


def get_scan_history(ip, limit=10):
    """
    Return the last N scans for a given IP address, most recent first.
    Returns a list of dicts. JSON columns parsed automatically.
    """
    init_db()

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT * FROM scans
            WHERE ip_scanned = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (ip, limit)).fetchall()

    return [_row_to_dict(row) for row in rows]


def cleanup_old_scans():
    """Delete scans older than 90 days to keep the database small forever."""
    cutoff = (
        datetime.datetime.now() - datetime.timedelta(days=RETENTION_DAYS)
    ).isoformat()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM scans WHERE timestamp < ?", (cutoff,))
        conn.commit()


def get_new_devices(current_devices, ip):
    """
    Compare current scan devices against the last scan for this IP.
    Returns a list of devices that are NEW — not seen in the previous scan.

    - Compares by MAC address when available (more reliable than IP).
    - Falls back to IP address comparison when MAC is absent.
    - Returns [] on the very first scan — no alert before a baseline exists.

    Accepts devices as either plain IP strings or dicts with 'ip'/'mac' keys
    (compatible with both network_mapper live_hosts and ARP table output).
    """
    last_scan = get_last_scan(ip)
    if last_scan is None:
        # No baseline yet — silently return empty, establish baseline on save
        return []

    previous_devices = last_scan.get("devices_found", [])

    # Build lookup sets from the previous scan
    prev_macs = set()
    prev_ips  = set()
    for device in previous_devices:
        if isinstance(device, dict):
            mac = device.get("mac")
            if mac:
                prev_macs.add(mac.lower())
            ip_addr = device.get("ip")
            if ip_addr:
                prev_ips.add(ip_addr)
        elif isinstance(device, str):
            prev_ips.add(device)

    new_devices = []
    for device in current_devices:
        if isinstance(device, dict):
            mac     = device.get("mac")
            ip_addr = device.get("ip")
            # Prefer MAC comparison — IPs can change (DHCP), MACs don't
            if mac and prev_macs:
                if mac.lower() not in prev_macs:
                    new_devices.append(device)
            elif ip_addr:
                if ip_addr not in prev_ips:
                    new_devices.append(device)
        elif isinstance(device, str):
            if device not in prev_ips:
                new_devices.append(device)

    return new_devices


def get_port_changes(current_ports, ip):
    """
    Diff open ports between the current scan and the last saved scan for
    this IP. Returns a list of dicts for ports that are NEW — present now
    but not in the previous scan. Returns [] if no baseline exists yet.

    Args:
        current_ports: list of port strings like "Port 80: OPEN (HTTP)"
        ip: the IP address that was scanned

    Returns:
        list of dicts with keys: port, description, risk, message
    """
    last_scan = get_last_scan(ip)
    if last_scan is None:
        return []

    previous_ports = last_scan.get("open_ports", [])

    def _extract_port(s):
        m = re.search(r"\d+", str(s))
        return int(m.group()) if m else None

    prev_port_nums = set()
    for entry in previous_ports:
        n = _extract_port(entry)
        if n is not None:
            prev_port_nums.add(n)

    critical_ports = {21, 22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 4444,
                      5432, 6379, 9200, 27017}
    high_ports = {8080, 8443, 5900, 2049, 8888}

    port_messages = {
        4444: "Port 4444 opened on this device since your last scan — this is the default port for remote access tools used by attackers.",
        3389: "Port 3389 (Remote Desktop) opened since your last scan — RDP is the top target for ransomware delivery.",
        22:   "Port 22 (SSH) opened since your last scan — a new remote login service appeared on this device.",
        23:   "Port 23 (Telnet) opened since your last scan — Telnet sends passwords in plain text and should not be open.",
        445:  "Port 445 (SMB) opened since your last scan — the file-sharing protocol exploited by WannaCry ransomware.",
        3306: "Port 3306 (MySQL) opened since your last scan — a database is now reachable from your network.",
        6379: "Port 6379 (Redis) opened since your last scan — Redis runs with no authentication by default.",
        9200: "Port 9200 (Elasticsearch) opened since your last scan — Elasticsearch has no authentication by default.",
        27017:"Port 27017 (MongoDB) opened since your last scan — MongoDB has no authentication by default.",
        5432: "Port 5432 (PostgreSQL) opened since your last scan — a database is now reachable from your network.",
    }

    new_ports = []
    for entry in current_ports:
        port_num = _extract_port(entry)
        if port_num is None:
            continue
        if port_num in prev_port_nums:
            continue
        if port_num in critical_ports:
            risk = "CRITICAL"
        elif port_num in high_ports:
            risk = "HIGH"
        else:
            risk = "LOW"
        message = port_messages.get(
            port_num,
            f"Port {port_num} opened on this device since your last scan."
        )
        new_ports.append({
            "port": port_num,
            "description": str(entry),
            "risk": risk,
            "message": message,
        })

    return new_ports


def check_arp_poisoning(current_devices, ip):
    """
    Compare MAC addresses of discovered devices against the last scan.
    Returns a list of finding dicts when a known IP has changed its MAC
    address — a potential ARP poisoning indicator.

    Special attention is paid to the gateway IP: if the gateway MAC
    changes, the finding is elevated to CRITICAL.

    Args:
        current_devices: list of dicts with 'ip' and 'mac' keys
        ip: the scanned subnet IP (used to fetch scan history)

    Returns:
        list of finding dicts (empty if clean)
    """
    last_scan = get_last_scan(ip)
    if last_scan is None:
        return []

    previous_devices = last_scan.get("devices_found", [])
    if not previous_devices:
        return []

    prev_mac_by_ip = {}
    for device in previous_devices:
        if isinstance(device, dict):
            dev_ip  = device.get("ip")
            dev_mac = device.get("mac", "").lower().strip()
            if dev_ip and dev_mac:
                prev_mac_by_ip[dev_ip] = dev_mac

    if not prev_mac_by_ip:
        return []

    # Infer gateway as the .1 address of the scanned subnet
    gateway_ip = ip.rsplit(".", 1)[0] + ".1" if "." in ip else None

    findings = []
    for device in current_devices:
        if not isinstance(device, dict):
            continue
        dev_ip  = device.get("ip")
        dev_mac = device.get("mac", "").lower().strip()
        if not dev_ip or not dev_mac:
            continue
        prev_mac = prev_mac_by_ip.get(dev_ip)
        if prev_mac is None:
            continue
        if prev_mac == dev_mac:
            continue

        is_gateway = (dev_ip == gateway_ip)
        risk = "CRITICAL" if is_gateway else "HIGH"
        description = (
            f"I found that the MAC address of {dev_ip} changed since your last scan "
            f"(was {prev_mac}, now {dev_mac}). "
        )
        if is_gateway:
            description += (
                "This is your network gateway — a gateway MAC change is a strong "
                "indicator of ARP poisoning, where an attacker is impersonating your "
                "router to intercept all your network traffic."
            )
        else:
            description += (
                "This could indicate ARP poisoning — an attacker impersonating a "
                "device on your network to intercept its traffic."
            )

        findings.append({
            "ip": dev_ip,
            "previous_mac": prev_mac,
            "current_mac": dev_mac,
            "risk": risk,
            "title": f"MAC address change detected on {dev_ip}",
            "description": description,
            "fix": (
                "If you didn't replace this device, investigate immediately. "
                "Disconnect any suspicious device from your network. Change your "
                "WiFi password. If this is your gateway, contact your router "
                "manufacturer and consider a factory reset."
            ),
        })

    return findings


# ── internal helper ────────────────────────────────────────────────────────────

def _row_to_dict(row):
    """Convert a sqlite3.Row to a plain dict, parsing all JSON columns."""
    d = dict(row)
    for col in ("open_ports", "devices_found", "vulnerabilities", "tools_used"):
        if d.get(col):
            try:
                d[col] = json.loads(d[col])
            except (json.JSONDecodeError, TypeError):
                d[col] = []
        else:
            d[col] = []
    return d
