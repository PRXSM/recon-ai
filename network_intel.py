"""
network_intel.py — Phase 5, Tool 1
Parses local network interface data into structured dicts with plain-English explanations.
"""

import platform
import subprocess
import re


# ── helpers ──────────────────────────────────────────────────────────────────

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


# ── main parser ───────────────────────────────────────────────────────────────

def get_network_interfaces():
    """
    Run ifconfig (Mac/Linux) or ipconfig /all (Windows) and parse each
    interface into a structured dict.

    Returns:
        dict keyed by interface name, each value:
        {
            name, mac_address, ipv4, ipv6,
            subnet_mask, gateway, dns_servers (list)
        }
    """
    system = platform.system()

    if system == "Windows":
        return _parse_windows()
    else:
        return _parse_unix()


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
        return {"error": {"name": "error", "mac_address": None, "ipv4": None,
                          "ipv6": None, "subnet_mask": None, "gateway": None,
                          "dns_servers": [], "_parse_error": str(e)}}

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

        # MAC address
        mac_m = re.search(r"\bether ([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b", line)
        if mac_m:
            interfaces[current]["mac_address"] = mac_m.group(1)

        # IPv4 + netmask
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

        # IPv6 (take first non-link-local if possible, else first one)
        inet6_m = re.search(r"\binet6 ([0-9a-fA-F:]+(?:%\S+)?)", line)
        if inet6_m and interfaces[current]["ipv6"] is None:
            interfaces[current]["ipv6"] = inet6_m.group(1)

    # Gateway and DNS are system-wide; attach to every interface
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
    except Exception as e:
        return {"error": _empty_iface("error")}

    interfaces = {}
    current = None
    collecting_dns = False

    for line in raw.splitlines():
        # New adapter block — line doesn't start with whitespace, ends with ":"
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
            # Continuation lines for DNS (indent-only, IP address)
            m = re.match(r"^\s+(\d+\.\d+\.\d+\.\d+)\s*$", line)
            if m:
                interfaces[current]["dns_servers"].append(m.group(1))
            elif stripped and not stripped[0].isdigit():
                collecting_dns = False

    return interfaces


# ── explainer ────────────────────────────────────────────────────────────────

_KNOWN_DNS = {
    "8.8.8.8":   "Google Public DNS",
    "8.8.4.4":   "Google Public DNS (secondary)",
    "1.1.1.1":   "Cloudflare DNS",
    "1.0.0.1":   "Cloudflare DNS (secondary)",
    "9.9.9.9":   "Quad9 DNS",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS (secondary)",
}

_PRIVATE_RANGES = [
    (re.compile(r"^10\."), "private (Class A — large home/corp networks)"),
    (re.compile(r"^172\.(1[6-9]|2\d|3[01])\."), "private (Class B — mid-size networks)"),
    (re.compile(r"^192\.168\."), "private (Class C — typical home networks)"),
    (re.compile(r"^127\."), "loopback (your own machine)"),
    (re.compile(r"^169\.254\."), "APIPA / link-local (no DHCP server reached)"),
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
    Takes the dict returned by get_network_interfaces() and returns
    a parallel dict of plain-English explanations for each interface field.

    Each field explanation is:
        { "what": str, "why": str, "bad_value": str }
    """
    explanations = {}

    for name, iface in data.items():
        ipv4 = iface.get("ipv4")
        ipv4_class = _classify_ipv4(ipv4)
        mac = iface.get("mac_address")
        mask = iface.get("subnet_mask")
        gw = iface.get("gateway")
        dns = iface.get("dns_servers") or []
        ipv6 = iface.get("ipv6")

        # ── name ──
        if name.startswith("lo"):
            name_what = f'"{name}" is your loopback interface — a virtual device that loops traffic back to your own machine.'
        elif name.startswith("en") or name.startswith("eth"):
            name_what = f'"{name}" is a physical network adapter (Ethernet or Wi-Fi).'
        elif name.startswith("utun") or name.startswith("tun"):
            name_what = f'"{name}" is a tunnel interface — typically created by a VPN.'
        elif name.startswith("bridge") or name.startswith("br"):
            name_what = f'"{name}" is a network bridge — it connects multiple network segments.'
        else:
            name_what = f'"{name}" is a network interface on your machine.'

        # ── MAC ──
        if mac:
            mac_what = f"Your hardware address is {mac}. Every device that touches a network has one — it's burned into the chip at the factory."
            mac_why = "MACs identify you on the local network (your router uses it). They don't travel beyond your router."
            mac_bad = "All zeros (00:00:00:00:00:00) or all f's (ff:ff:ff:ff:ff:ff) means the interface has no real hardware address — normal for virtual adapters, a concern on physical ones."
        else:
            mac_what = "No hardware address detected for this interface."
            mac_why = "Virtual or tunnel interfaces often don't have MAC addresses."
            mac_bad = "N/A"

        # ── IPv4 ──
        if ipv4:
            ipv4_what = f"Your IP address on this interface is {ipv4} — classified as {ipv4_class}."
            if "APIPA" in (ipv4_class or ""):
                ipv4_why = "A 169.254.x.x address means your device failed to get an address from DHCP. You have no working internet on this interface."
                ipv4_bad = "169.254.x.x is always bad on a Wi-Fi or Ethernet interface — it means no DHCP server replied."
            elif "loopback" in (ipv4_class or ""):
                ipv4_why = "127.0.0.1 only talks to yourself. Software uses it for internal communication."
                ipv4_bad = "If your only IP is 127.0.0.1, you have no network connectivity."
            elif "public" in (ipv4_class or ""):
                ipv4_why = "A public IP is directly reachable from the internet. Open ports on this interface are visible globally."
                ipv4_bad = "Any unexpected public IP is a red flag — your device may be directly internet-exposed."
            else:
                ipv4_why = "Private IPs are safe — they're only visible inside your home/office network, not on the internet."
                ipv4_bad = "An unexpected IP range (not matching your router's scheme) could mean you're on a rogue network."
        else:
            ipv4_what = "No IPv4 address assigned to this interface."
            ipv4_why = "This interface may be disabled, unplugged, or still negotiating with DHCP."
            ipv4_bad = "Expected to have an IP but showing none? Check the cable or Wi-Fi connection."

        # ── IPv6 ──
        if ipv6:
            if ipv6.startswith("fe80"):
                ipv6_what = f"IPv6 link-local address: {ipv6}. Only visible on your local network segment."
                ipv6_why = "Link-local addresses are auto-assigned and used for local discovery. They don't route to the internet."
                ipv6_bad = "A link-local address as your only IPv6 address is normal — it means no global IPv6 routing is configured."
            else:
                ipv6_what = f"IPv6 address: {ipv6}. This is the next-generation internet addressing system."
                ipv6_why = "IPv6 addresses can be globally routable. If this is a global address (not starting with fe80::), your device is reachable via IPv6 from the internet."
                ipv6_bad = "An unexpected global IPv6 address means your device may be directly internet-accessible on IPv6, even if IPv4 is NATted."
        else:
            ipv6_what = "No IPv6 address on this interface."
            ipv6_why = "IPv6 is the future of internet addressing but many home networks still use IPv4 only."
            ipv6_bad = "No IPv6 is normal on most home networks — not a concern."

        # ── subnet mask ──
        if mask:
            # Count set bits for CIDR notation
            try:
                cidr = sum(bin(int(octet)).count("1") for octet in mask.split("."))
                cidr_str = f"/{cidr}"
            except Exception:
                cidr_str = ""
            mask_what = f"Subnet mask {mask} ({cidr_str}) defines the size of your local network."
            mask_why = "It tells your device which addresses are 'local' (talk directly) vs 'remote' (go via gateway). Wrong mask = can't reach other devices."
            mask_bad = "0.0.0.0 or an unusual mask (e.g. 255.255.255.254) is a misconfiguration. Standard home networks use 255.255.255.0 (/24)."
        else:
            mask_what = "No subnet mask — this interface isn't fully configured."
            mask_why = "Without a subnet mask, your device doesn't know which addresses are local."
            mask_bad = "Missing mask on an active interface means no network connectivity."

        # ── gateway ──
        if gw:
            gw_what = f"Your default gateway is {gw} — typically your router's IP address."
            gw_why = "All traffic destined for the internet flows through this address. If your gateway is wrong or unreachable, you have no internet."
            gw_bad = "If the gateway IP doesn't match your expected router (e.g. 192.168.1.1), you may be on a rogue network or DHCP was spoofed."
        else:
            gw_what = "No default gateway detected."
            gw_why = "Without a gateway, your device can reach local devices but not the internet."
            gw_bad = "Missing gateway on an active network interface means no internet access."

        # ── DNS ──
        if dns:
            labeled = []
            for s in dns:
                label = _KNOWN_DNS.get(s)
                labeled.append(f"{s} ({label})" if label else s)
            dns_what = "DNS servers translate domain names (google.com) into IP addresses. Your current servers: " + ", ".join(labeled) + "."
            dns_why = "Every website visit starts with a DNS lookup. A malicious DNS server can silently redirect you to fake sites."
            dns_bad = "An unknown or unexpected DNS server — especially one that's not from your ISP or a trusted public provider — could be intercepting your browsing. Run a DNS leak test if unsure."
        else:
            dns_what = "No DNS servers detected for this interface."
            dns_why = "Without DNS, you can access IPs directly but domain names (like google.com) won't resolve."
            dns_bad = "No DNS on an active interface means websites won't load by name."

        explanations[name] = {
            "name":        {"what": name_what,   "why": "Interface names tell you what kind of connection this is.", "bad_value": "A name you don't recognise (e.g. an extra 'en2' you didn't add) could be a virtual adapter created by malware."},
            "mac_address": {"what": mac_what,    "why": mac_why,    "bad_value": mac_bad},
            "ipv4":        {"what": ipv4_what,   "why": ipv4_why,   "bad_value": ipv4_bad},
            "ipv6":        {"what": ipv6_what,   "why": ipv6_why,   "bad_value": ipv6_bad},
            "subnet_mask": {"what": mask_what,   "why": mask_why,   "bad_value": mask_bad},
            "gateway":     {"what": gw_what,     "why": gw_why,     "bad_value": gw_bad},
            "dns_servers": {"what": dns_what,    "why": dns_why,    "bad_value": dns_bad},
        }

    return explanations
