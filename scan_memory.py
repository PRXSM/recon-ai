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
