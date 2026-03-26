"""
network_intel.py — Phase 5
Network interface translator, ARP table reader,
active connections explainer, traceroute parser.
"""

import platform
import subprocess
import re


# ── helpers ───────────────────────────────────────────────────────────────────

def _hex_mask_to_dotted(hex_mask):
    """Convert 0xffffff00 → 255.255.255.0"""
    val = int(hex_mask, 16)
    return ".".join(str((val >> (8 * i)) & 0xFF) for i in reversed(range(4)))


def _get_default_gateway_unix():
    system = platform.system()
    try:
        if system == "Darwin":
            r = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, timeout=5
            )
            for line in r.stdout.splitlines():
                if "gateway:" in line:
                    return line.split("gateway:")[-1].strip()
        elif system == "Linux":
            r = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            m = re.search(r"default via (\S+)", r.stdout)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def _get_dns_unix():
    try:
        with open("/etc/resolv.conf") as f:
            servers = []
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
            return servers
    except Exception:
        pass
    return []


# ── network interfaces ────────────────────────────────────────────────────────

def get_network_interfaces():
    """
    Run ifconfig (Mac/Linux) or ipconfig /all (Windows) and parse each
    interface into a structured dict.

    Returns:
        dict keyed by interface name, each value:
        { name, mac_address, ipv4, ipv6, subnet_mask, gateway, dns_servers }
    """
    return _parse_unix() if platform.system() != "Windows" else _parse_windows()


def _empty_iface(name):
    return {
        "name": name,
        "mac_address": None,
        "ipv4": None,
        "ipv6": None,
        "subnet_mask": None,
        "gateway": None,
        "dns_servers": [],
    }


def _parse_unix():
    try:
        result = subprocess.run(
            ["ifconfig"], capture_output=True, text=True, timeout=10
        )
        raw = result.stdout
    except Exception as e:
        return {"error": {**_empty_iface("error"), "_parse_error": str(e)}}

    interfaces = {}
    current = None

    for line in raw.splitlines():
        iface_match = re.match(r"^(\S+?):\s", line)
        if iface_match:
            name = iface_match.group(1)
            current = name
            interfaces[current] = _empty_iface(name)
            continue

        if current is None:
            continue

        mac_m = re.search(r"\bether ([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b", line)
        if mac_m:
            interfaces[current]["mac_address"] = mac_m.group(1)

        inet_m = re.search(
            r"\binet (\d+\.\d+\.\d+\.\d+)\s+netmask (0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)",
            line
        )
        if inet_m:
            interfaces[current]["ipv4"] = inet_m.group(1)
            mask = inet_m.group(2)
            interfaces[current]["subnet_mask"] = (
                _hex_mask_to_dotted(mask) if mask.startswith("0x") else mask
            )

        inet6_m = re.search(r"\binet6 ([0-9a-fA-F:]+(?:%\S+)?)", line)
        if inet6_m and interfaces[current]["ipv6"] is None:
            interfaces[current]["ipv6"] = inet6_m.group(1)

    gateway = _get_default_gateway_unix()
    dns = _get_dns_unix()
    for iface in interfaces.values():
        iface["gateway"] = gateway
        iface["dns_servers"] = dns

    return interfaces


def _parse_windows():
    try:
        result = subprocess.run(
            ["ipconfig", "/all"], capture_output=True, text=True, timeout=10
        )
        raw = result.stdout
    except Exception:
        return {"error": _empty_iface("error")}

    interfaces = {}
    current = None
    collecting_dns = False

    for line in raw.splitlines():
        adapter_m = re.match(r"^(\S[^:]+):$", line.rstrip())
        if adapter_m:
            name = adapter_m.group(1).strip()
            current = name
            interfaces[current] = _empty_iface(name)
            collecting_dns = False
            continue

        if current is None:
            continue

        stripped = line.strip()

        if re.search(r"Physical Address", line, re.I):
            m = re.search(r"([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})", line)
            if m:
                interfaces[current]["mac_address"] = m.group(1).replace("-", ":")
            collecting_dns = False
        elif re.search(r"IPv4 Address", line, re.I):
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                interfaces[current]["ipv4"] = m.group(1)
            collecting_dns = False
        elif re.search(r"IPv6 Address", line, re.I):
            m = re.search(r"([0-9a-fA-F:]+(?:%\S+)?)", stripped.split(":")[-1])
            if m and interfaces[current]["ipv6"] is None:
                interfaces[current]["ipv6"] = m.group(1).strip()
            collecting_dns = False
        elif re.search(r"Subnet Mask", line, re.I):
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                interfaces[current]["subnet_mask"] = m.group(1)
            collecting_dns = False
        elif re.search(r"Default Gateway", line, re.I):
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                interfaces[current]["gateway"] = m.group(1)
            collecting_dns = False
        elif re.search(r"DNS Servers", line, re.I):
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                interfaces[current]["dns_servers"].append(m.group(1))
            collecting_dns = True
        elif collecting_dns:
            m = re.match(r"^\s+(\d+\.\d+\.\d+\.\d+)\s*$", line)
            if m:
                interfaces[current]["dns_servers"].append(m.group(1))
            elif stripped and not stripped[0].isdigit():
                collecting_dns = False

    return interfaces


# ── interface grouping ────────────────────────────────────────────────────────

# These prefixes are grouped when multiple numbered instances appear
_GROUPABLE = {'utun', 'gif', 'stf', 'ipsec', 'pktap', 'llw', 'anpi'}

_PREFIX_LABEL = {
    'utun':  'VPN / system tunnel interfaces',
    'gif':   'Generic IPv6-in-IPv4 tunnel interfaces',
    'stf':   'IPv6-to-IPv4 transition interfaces',
    'ipsec': 'IPsec encrypted tunnel interfaces',
    'pktap': 'Packet-capture tap interfaces',
    'llw':   'Low-latency WLAN interfaces',
    'anpi':  'Apple NCM network interfaces',
}


def group_interfaces(interfaces):
    """
    Group same-prefix virtual/tunnel interfaces into single accordion rows.
    Returns ordered list where each item is either:
      {'grouped': False, 'name': str, 'iface': dict}
      {'grouped': True,  'prefix': str, 'label': str, 'count': int,
       'ip': str|None, 'members': [{'name': str, 'iface': dict}]}
    """
    prefix_order = []
    prefix_map = {}
    for name, iface in interfaces.items():
        prefix = name.rstrip('0123456789')
        if prefix not in prefix_map:
            prefix_map[prefix] = []
            prefix_order.append(prefix)
        prefix_map[prefix].append((name, iface))

    result = []
    for prefix in prefix_order:
        members = prefix_map[prefix]
        if prefix in _GROUPABLE and len(members) > 1:
            ips = [iface.get('ipv4') for _, iface in members if iface.get('ipv4')]
            result.append({
                'grouped': True,
                'prefix': prefix,
                'label': _PREFIX_LABEL.get(prefix, f'{prefix} interfaces'),
                'count': len(members),
                'ip': ips[0] if ips else None,
                'members': [{'name': n, 'iface': i} for n, i in members],
            })
        else:
            for name, iface in members:
                result.append({'grouped': False, 'name': name, 'iface': iface})

    return result


# ── interface explainer ───────────────────────────────────────────────────────

_KNOWN_DNS = {
    "8.8.8.8":       "Google Public DNS",
    "8.8.4.4":       "Google Public DNS (secondary)",
    "1.1.1.1":       "Cloudflare DNS",
    "1.0.0.1":       "Cloudflare DNS (secondary)",
    "9.9.9.9":       "Quad9 DNS",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS (secondary)",
}

_PRIVATE_RANGES = [
    (re.compile(r"^10\."),                          "private (Class A — large home/corp networks)"),
    (re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),    "private (Class B — mid-size networks)"),
    (re.compile(r"^192\.168\."),                    "private (Class C — typical home networks)"),
    (re.compile(r"^127\."),                         "loopback (your own machine)"),
    (re.compile(r"^169\.254\."),                    "APIPA / link-local (no DHCP server reached)"),
]


def _classify_ipv4(ip):
    if not ip:
        return None
    for pattern, label in _PRIVATE_RANGES:
        if pattern.match(ip):
            return label
    return "public (routable on the internet)"


def explain_interface(data):
    """
    Returns a parallel dict of plain-English field explanations.
    Each field: { "what": str, "why": str, "bad_value": str }
    """
    explanations = {}

    for name, iface in data.items():
        ipv4      = iface.get("ipv4")
        ipv4_cls  = _classify_ipv4(ipv4)
        mac       = iface.get("mac_address")
        mask      = iface.get("subnet_mask")
        gw        = iface.get("gateway")
        dns       = iface.get("dns_servers") or []
        ipv6      = iface.get("ipv6")

        if name.startswith("lo"):
            name_what = f'"{name}" is your loopback interface — a virtual device that loops traffic back to your own machine.'
        elif name.startswith(("en", "eth")):
            name_what = f'"{name}" is a physical network adapter (Ethernet or Wi-Fi).'
        elif name.startswith(("utun", "tun")):
            name_what = f'"{name}" is a tunnel interface — typically created by a VPN.'
        elif name.startswith(("bridge", "br")):
            name_what = f'"{name}" is a network bridge — it connects multiple network segments.'
        else:
            name_what = f'"{name}" is a network interface on your machine.'

        if mac:
            mac_what = f"Hardware address: {mac}. Every network-capable device has one — assigned by the manufacturer."
            mac_why  = "Your router uses this to identify your device on the local network. MACs don't travel beyond your router."
            mac_bad  = "All zeros or all f's on a physical adapter is a red flag. Normal for virtual/tunnel interfaces."
        else:
            mac_what = "No hardware address — typical for virtual or tunnel interfaces."
            mac_why  = "Virtual adapters don't need a MAC since they don't connect to physical hardware."
            mac_bad  = "N/A"

        if ipv4:
            ipv4_what = f"Your IP on this interface: {ipv4} — classified as {ipv4_cls}."
            if "APIPA" in (ipv4_cls or ""):
                ipv4_why = "169.254.x.x means DHCP failed — your device couldn't reach the router to get a real address."
                ipv4_bad = "169.254.x.x on Wi-Fi/Ethernet means something is wrong with your DHCP or cable."
            elif "loopback" in (ipv4_cls or ""):
                ipv4_why = "127.0.0.1 is internal-only. Apps use it to talk to other processes on the same machine."
                ipv4_bad = "If this is your only IP, you have no network connectivity."
            elif "public" in (ipv4_cls or ""):
                ipv4_why = "A public IP is directly reachable from the internet — any open ports are globally visible."
                ipv4_bad = "An unexpected public IP on your device means you may not be behind a NAT/router. Check your network setup."
            else:
                ipv4_why = "Private IPs stay inside your home/office network — they're not visible on the internet."
                ipv4_bad = "An IP range that doesn't match your router's scheme (e.g. 10.x when you expected 192.168.x) could mean you're on a different or unexpected network."
        else:
            ipv4_what = "No IPv4 address on this interface."
            ipv4_why  = "This interface is either disabled, unplugged, or hasn't received a DHCP lease yet."
            ipv4_bad  = "Expected an IP here but seeing none? Check the cable or Wi-Fi connection."

        if ipv6:
            if ipv6.startswith("fe80"):
                ipv6_what = f"IPv6 link-local: {ipv6} — auto-assigned, only visible on your local segment."
                ipv6_why  = "Used for local discovery (mDNS, NDP). Doesn't route to the internet."
                ipv6_bad  = "Link-local only is perfectly normal on most home networks."
            else:
                ipv6_what = f"IPv6 address: {ipv6}."
                ipv6_why  = "Global IPv6 addresses are internet-routable — open ports on this interface may be reachable from anywhere, even if IPv4 is behind NAT."
                ipv6_bad  = "An unexpected global IPv6 address could mean your device is directly internet-exposed on IPv6."
        else:
            ipv6_what = "No IPv6 address on this interface."
            ipv6_why  = "Most home networks still run IPv4 only — no IPv6 is completely normal."
            ipv6_bad  = "Not having IPv6 is fine."

        if mask:
            try:
                cidr = sum(bin(int(o)).count("1") for o in mask.split("."))
                cidr_str = f" (/{cidr})"
            except Exception:
                cidr_str = ""
            mask_what = f"Subnet mask: {mask}{cidr_str} — defines the size of your local network."
            mask_why  = "Tells your device which addresses it can reach directly vs which ones need to go through the gateway."
            mask_bad  = "0.0.0.0 or a mismatched mask means your device can't route properly. Standard home networks use 255.255.255.0 (/24)."
        else:
            mask_what = "No subnet mask — this interface isn't fully configured."
            mask_why  = "Without a mask, your device doesn't know what's 'local' vs 'remote'."
            mask_bad  = "Missing on an active interface means no network connectivity."

        if gw:
            gw_what = f"Default gateway: {gw} — your router's IP address."
            gw_why  = "All traffic destined for the internet leaves your machine through this address."
            gw_bad  = "A gateway that doesn't match your expected router IP (e.g. 192.168.1.1) could mean DHCP was spoofed."
        else:
            gw_what = "No default gateway detected."
            gw_why  = "Without a gateway you can reach local devices but not the internet."
            gw_bad  = "Missing on an active interface means no internet access."

        if dns:
            labeled = []
            for s in dns:
                lb = _KNOWN_DNS.get(s)
                labeled.append(f"{s} ({lb})" if lb else s)
            dns_what = "DNS servers: " + ", ".join(labeled) + ". They translate domain names into IP addresses."
            dns_why  = "Every website visit starts with a DNS lookup. A rogue DNS server can silently redirect you to fake sites."
            dns_bad  = "An unrecognised DNS server — especially one that's not your ISP's or a known public provider — is worth investigating."
        else:
            dns_what = "No DNS servers on this interface."
            dns_why  = "Without DNS, domain names won't resolve and websites won't load."
            dns_bad  = "Missing on an active interface means you can't browse the web by name."

        explanations[name] = {
            "name":        {"what": name_what, "why": "Interface names tell you what kind of connection this is.",
                            "bad_value": "An unfamiliar extra interface (e.g. a new 'en3' you didn't add) could be a virtual adapter worth investigating."},
            "mac_address": {"what": mac_what,  "why": mac_why,  "bad_value": mac_bad},
            "ipv4":        {"what": ipv4_what, "why": ipv4_why, "bad_value": ipv4_bad},
            "ipv6":        {"what": ipv6_what, "why": ipv6_why, "bad_value": ipv6_bad},
            "subnet_mask": {"what": mask_what, "why": mask_why, "bad_value": mask_bad},
            "gateway":     {"what": gw_what,   "why": gw_why,   "bad_value": gw_bad},
            "dns_servers": {"what": dns_what,  "why": dns_why,  "bad_value": dns_bad},
        }

    return explanations


# ── ARP table ─────────────────────────────────────────────────────────────────

def _normalize_mac(mac):
    """Pad single-digit hex segments: 0:e0:4c → 00:e0:4c"""
    if not mac:
        return None
    parts = re.split(r'[:\-]', mac)
    if len(parts) == 6:
        return ':'.join(p.zfill(2) for p in parts)
    return mac


def get_arp_table():
    """
    Run 'arp -a' and parse into list of dicts:
    { ip, mac, interface, type }
    type is 'dynamic', 'static', or 'incomplete'
    """
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
        raw = result.stdout
    except Exception:
        return []

    entries = []
    system = platform.system()

    if system == 'Windows':
        current_iface = None
        for line in raw.splitlines():
            iface_m = re.match(r'Interface:\s+(\S+)', line)
            if iface_m:
                current_iface = iface_m.group(1)
                continue
            m = re.match(r'\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)', line)
            if m:
                entries.append({
                    'ip': m.group(1),
                    'mac': _normalize_mac(m.group(2)),
                    'interface': current_iface,
                    'type': m.group(3).lower(),
                })
    else:
        for line in raw.splitlines():
            # ? (IP) at MAC on IFACE ...
            m = re.match(
                r'\S+\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+(?:\s+\(incomplete\))?)'
                r'(?:.*?\bon\s+(\S+))?',
                line
            )
            if m:
                raw_mac = m.group(2).strip()
                is_incomplete = raw_mac.startswith('(') or raw_mac == '(incomplete)'
                entries.append({
                    'ip': m.group(1),
                    'mac': None if is_incomplete else _normalize_mac(raw_mac),
                    'interface': m.group(3),
                    'type': 'incomplete' if is_incomplete else 'dynamic',
                })

    return entries


def explain_arp_entry(entry, gateway=None):
    """Plain-English description of a single ARP table entry."""
    ip    = entry.get('ip', '')
    mac   = entry.get('mac')
    etype = entry.get('type', 'dynamic')

    last_octet = ip.split('.')[-1] if '.' in ip else ''

    if ip == gateway:
        device_guess = "Your router / default gateway"
    elif last_octet in ('1', '254'):
        device_guess = "Likely your router or a network gateway"
    elif ip.endswith('.255') or last_octet == '255':
        device_guess = "Network broadcast address — not a real device"
    elif ip.startswith('169.254.'):
        device_guess = "APIPA address — this device couldn't get a DHCP lease"
    elif ip.startswith('224.') or ip.startswith('239.'):
        device_guess = "Multicast address — used for group traffic (mDNS, UPnP)"
    else:
        device_guess = "A device on your local network"

    flag = None

    if not mac or etype == 'incomplete':
        mac_note = "No MAC recorded — this entry is incomplete. The device may have gone offline before ARP resolved it."
        flag = "Incomplete entries are usually harmless. Persistent incompleteness on an IP you expect to be active is worth checking."
    else:
        try:
            first_byte = int(mac.split(':')[0], 16)
        except (ValueError, IndexError):
            first_byte = 0

        is_multicast    = bool(first_byte & 0x01)
        is_local_admin  = bool(first_byte & 0x02)

        if mac == 'ff:ff:ff:ff:ff:ff':
            mac_note = "Broadcast MAC — normal for network-wide broadcast traffic."
        elif is_multicast:
            mac_note = f"Multicast MAC ({mac}) — normal for mDNS, UPnP, and other discovery services."
        elif is_local_admin:
            mac_note = (
                f"Locally-administered MAC ({mac}) — this address was assigned by software, not a manufacturer. "
                "Common in virtual machines, Docker containers, and USB Ethernet adapters."
            )
        else:
            mac_note = f"Standard hardware MAC ({mac}), assigned by the device manufacturer."

    return {
        'device_guess': device_guess,
        'mac_note': mac_note,
        'flag': flag,
    }


# ── Active connections ────────────────────────────────────────────────────────

def _split_addr_port_unix(addr_str):
    """Split Mac/Linux netstat 'addr.port' notation into (addr, port)."""
    if addr_str in ('*.*', '*'):
        return '*', '*'
    last = addr_str.rfind('.')
    if last == -1:
        return addr_str, '*'
    return addr_str[:last], addr_str[last + 1:]


def _split_addr_port_windows(addr_str):
    """Split Windows netstat 'addr:port' notation into (addr, port)."""
    if addr_str in ('*:*', '*'):
        return '*', '*'
    m = re.match(r'\[([^\]]+)\]:(\d+|\*)', addr_str)
    if m:
        return m.group(1), m.group(2)
    m = re.match(r'(.+):(\d+|\*)', addr_str)
    if m:
        return m.group(1), m.group(2)
    return addr_str, '*'


def get_active_connections():
    """
    Run 'netstat -an' and return list of TCP/UDP connections:
    { protocol, local_addr, local_port, remote_addr, remote_port, state }
    """
    try:
        result = subprocess.run(
            ['netstat', '-an'], capture_output=True, text=True, timeout=15
        )
        raw = result.stdout
    except Exception:
        return []

    connections = []
    system = platform.system()

    if system == 'Windows':
        for line in raw.splitlines():
            m = re.match(r'\s+(TCP|UDP)\s+(\S+)\s+(\S+)\s*(\S*)', line, re.I)
            if m:
                proto = m.group(1).upper()
                la, lp = _split_addr_port_windows(m.group(2))
                ra, rp = _split_addr_port_windows(m.group(3))
                state = m.group(4).upper() if m.group(4) else ('LISTEN' if proto == 'TCP' else '')
                connections.append({
                    'protocol': proto,
                    'local_addr': la, 'local_port': lp,
                    'remote_addr': ra, 'remote_port': rp,
                    'state': state,
                })
    else:
        for line in raw.splitlines():
            if re.search(r'\bUNIX\b', line, re.I):
                break
            m = re.match(
                r'(tcp\S*|udp\S*)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s*(\S*)',
                line, re.I
            )
            if m:
                proto = 'TCP' if m.group(1).lower().startswith('tcp') else 'UDP'
                la, lp = _split_addr_port_unix(m.group(2))
                ra, rp = _split_addr_port_unix(m.group(3))
                state  = m.group(4).upper() if m.group(4) else ''
                connections.append({
                    'protocol': proto,
                    'local_addr': la, 'local_port': lp,
                    'remote_addr': ra, 'remote_port': rp,
                    'state': state,
                })

    return connections


def group_connections(connections):
    """
    Group connections by normalised state.
    Returns dict: { state_label: [conn, ...] }
    in display order.
    """
    buckets = {}
    order   = ['LISTEN', 'ESTABLISHED', 'CLOSE_WAIT', 'TIME_WAIT', 'OTHER']

    for conn in connections:
        state = conn.get('state', '').upper()
        if state in ('LISTEN', 'LISTENING'):
            key = 'LISTEN'
        elif state == 'ESTABLISHED':
            key = 'ESTABLISHED'
        elif state == 'CLOSE_WAIT':
            key = 'CLOSE_WAIT'
        elif state == 'TIME_WAIT':
            key = 'TIME_WAIT'
        else:
            key = 'OTHER'
        buckets.setdefault(key, []).append(conn)

    return [(s, buckets[s]) for s in order if s in buckets]


_RISKY_LISTEN = {
    21:    ('FTP',        'high',   'Transfers files in plain text — anyone on the network can read passwords and data.'),
    23:    ('Telnet',     'high',   'Remote shell with zero encryption — every keystroke is visible in plain text.'),
    25:    ('SMTP',       'medium', 'Mail server port — only expected if you intentionally run a mail server.'),
    135:   ('RPC',        'medium', 'Windows Remote Procedure Call — frequently targeted by malware.'),
    139:   ('NetBIOS',    'medium', 'Windows file sharing (old style) — should never be reachable from the internet.'),
    445:   ('SMB',        'high',   'Windows file sharing — exploited by EternalBlue / WannaCry ransomware. Keep off the internet.'),
    1433:  ('MSSQL',      'high',   'SQL Server — databases should never be directly internet-facing.'),
    3306:  ('MySQL',      'high',   'MySQL database — a common source of breaches when exposed externally.'),
    3389:  ('RDP',        'high',   'Windows Remote Desktop — a top target for brute-force and ransomware delivery.'),
    5432:  ('PostgreSQL', 'high',   'Postgres — database servers should only accept local connections.'),
    5900:  ('VNC',        'high',   'Remote desktop with weak encryption — high-value attack target.'),
    6379:  ('Redis',      'high',   'Redis cache — frequently misconfigured with no authentication, leading to full server compromise.'),
    27017: ('MongoDB',    'high',   'MongoDB — many high-profile data breaches stem from internet-exposed instances.'),
}

_KNOWN_REMOTE_PORTS = {80, 443, 8080, 8443, 22, 587, 465, 993, 995, 143, 110, 53, 123, 5228}


def explain_connection(conn):
    """Plain-English description of a single connection."""
    proto = conn.get('protocol', 'TCP')
    la    = conn.get('local_addr', '*')
    lp    = conn.get('local_port', '*')
    ra    = conn.get('remote_addr', '*')
    rp    = conn.get('remote_port', '*')
    state = conn.get('state', '')

    try:
        lport = int(lp) if lp not in ('*', '') else None
    except (ValueError, TypeError):
        lport = None
    try:
        rport = int(rp) if rp not in ('*', '') else None
    except (ValueError, TypeError):
        rport = None

    flag = None
    risk = 'none'

    if state in ('LISTEN', 'LISTENING'):
        risky = _RISKY_LISTEN.get(lport) if lport else None
        if risky:
            svc, risk, note = risky
            what = f"Your machine is accepting {svc} connections on port {lport}."
            flag = note
        elif lport and lport < 1024:
            what = f"A system service is listening on privileged port {lport}."
        elif lport:
            what = f"Something on your machine is waiting for connections on port {lport}."
        else:
            what = "A service is waiting for incoming connections."

    elif state == 'ESTABLISHED':
        if rport == 443:
            what = f"Active HTTPS connection to {ra} — encrypted."
        elif rport in (80, 8080):
            what = f"Active HTTP (unencrypted) connection to {ra}."
            flag = "Unencrypted — visible to others on your network."
            risk = 'low'
        elif rport == 22:
            what = f"Active SSH session to {ra}."
        elif rport == 53:
            what = f"DNS query to {ra}."
        elif rport:
            what = f"{proto} connection to {ra} on port {rport}."
            if rport not in _KNOWN_REMOTE_PORTS:
                flag = f"Port {rport} isn't a standard service port — make sure you recognise this connection."
                risk = 'low'
        else:
            what = f"Active connection to {ra}."

    elif state == 'TIME_WAIT':
        what = f"Connection to {ra}:{rp} is wrapping up — waiting for any stray packets before fully closing."

    elif state == 'CLOSE_WAIT':
        what = f"The remote side ({ra}) has closed the connection but your application hasn't released it."
        flag = "Many CLOSE_WAIT entries indicate an application isn't cleaning up connections."
        risk = 'low'

    else:
        what = f"{proto} {state} — {la}:{lp} ↔ {ra}:{rp}"

    return {'what': what, 'flag': flag, 'risk': risk}


# ── Traceroute ────────────────────────────────────────────────────────────────

def run_traceroute(host='8.8.8.8'):
    """
    Run traceroute/tracert to host.
    Returns (hops_list, error_str|None).
    Each hop: { hop, ip, hostname, latencies, timeout }
    """
    system = platform.system()
    if system == 'Windows':
        cmd = ['tracert', '-d', '-h', '15', '-w', '1000', host]
    else:
        cmd = ['traceroute', '-m', '15', '-w', '2', host]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return _parse_traceroute(result.stdout, system), None
    except subprocess.TimeoutExpired:
        return [], 'Traceroute timed out — the destination may be unreachable.'
    except FileNotFoundError:
        return [], 'traceroute not found. On macOS: brew install traceroute'
    except Exception as e:
        return [], str(e)


def _parse_traceroute(raw, system):
    hops = []

    if system == 'Windows':
        for line in raw.splitlines():
            if re.match(r'\s*\d+\s+\*\s+\*\s+\*', line):
                m = re.match(r'\s*(\d+)', line)
                if m:
                    hops.append({'hop': int(m.group(1)), 'ip': None, 'hostname': None,
                                 'latencies': [], 'timeout': True})
                continue
            m = re.match(r'\s*(\d+)(?:\s+(?:\d+\s+ms|\*))+\s+(\S+)', line)
            if m:
                hop_num = int(m.group(1))
                times   = [float(x) for x in re.findall(r'(\d+)\s+ms', line)]
                host_str = m.group(2)
                ip_m = re.search(r'(\d+\.\d+\.\d+\.\d+)', host_str)
                ip   = ip_m.group(1) if ip_m else host_str
                hops.append({'hop': hop_num, 'ip': ip, 'hostname': None,
                             'latencies': times, 'timeout': False})
    else:
        for line in raw.splitlines():
            if re.match(r'\s*\d+\s+\*\s+\*\s+\*\s*$', line):
                m = re.match(r'\s*(\d+)', line)
                if m:
                    hops.append({'hop': int(m.group(1)), 'ip': None, 'hostname': None,
                                 'latencies': [], 'timeout': True})
                continue
            # " 1  hostname (1.2.3.4)  2.3 ms ..."
            m = re.match(r'\s*(\d+)\s+(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+(.*)', line)
            if m:
                hop_num  = int(m.group(1))
                hostname = m.group(2)
                ip       = m.group(3)
                lats     = [float(x) for x in re.findall(r'([\d.]+)\s+ms', m.group(4))]
                hops.append({'hop': hop_num, 'ip': ip,
                             'hostname': hostname if hostname != ip else None,
                             'latencies': lats, 'timeout': False})
                continue
            # " 1  1.2.3.4  2.3 ms ..." (no hostname)
            m = re.match(r'\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(.*)', line)
            if m:
                hop_num = int(m.group(1))
                ip      = m.group(2)
                lats    = [float(x) for x in re.findall(r'([\d.]+)\s+ms', m.group(3))]
                hops.append({'hop': hop_num, 'ip': ip, 'hostname': None,
                             'latencies': lats, 'timeout': False})

    return hops


def explain_hop(hop):
    """Plain-English description of a single traceroute hop."""
    ip        = hop.get('ip')
    latencies = hop.get('latencies', [])
    timeout   = hop.get('timeout', False)
    n         = hop.get('hop', 0)
    avg_ms    = round(sum(latencies) / len(latencies), 1) if latencies else None

    if timeout:
        return {
            'what': "This hop didn't respond to the probe.",
            'note': "Timeouts (* * *) are common — many routers silently drop traceroute packets. It doesn't necessarily mean there's a problem.",
            'flag': None,
            'latency_str': None,
        }

    flag = None
    if n == 1:
        what = f"Your router ({ip}) — the first stop for all your traffic."
        if avg_ms and avg_ms > 15:
            flag = f"Your router is responding slowly ({avg_ms}ms). Normally under 5ms on wired, under 10ms on Wi-Fi."
    elif ip and (ip.startswith('10.') or ip.startswith('192.168.') or
                 re.match(r'^172\.(1[6-9]|2\d|3[01])\.', ip)):
        what = f"{ip} — a private address, likely inside your ISP's infrastructure."
    elif avg_ms and avg_ms > 200:
        what = f"{ip} — a distant server, possibly on another continent."
        flag = f"High latency ({avg_ms}ms) — expected for intercontinental hops but can slow browsing."
    elif avg_ms and avg_ms > 80:
        what = f"{ip} — probably a regional network or ISP backbone router."
    elif ip:
        what = f"{ip} — a router along the path to the internet."
    else:
        what = "Unknown hop."

    return {
        'what': what,
        'note': None,
        'flag': flag,
        'latency_str': f"{avg_ms}ms avg" if avg_ms else None,
    }
