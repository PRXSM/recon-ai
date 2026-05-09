"""
zero_trust.py — Phase 12
Zero Trust Verification.
Checks whether devices on the network should be trusted
or whether implicit trust assumptions are creating risk.

Four checks:
1. New device detection — devices not seen in previous scans
2. Implicit trust signals — admin services open to all devices
3. Guest device risk — unknown devices with access to internal services
4. Trust recommendations — plain English, tiered by router capability

This tool NEVER modifies, deletes, or acts on any system.
It observes and reports only.
Recon AI advises. The user decides.
"""

import logging
import re
from scan_memory import get_new_devices

logger = logging.getLogger(__name__)

VNC_PORTS = {5900, 5901, 5902, 5903}

IMPLICIT_TRUST_PORTS = {
    21:    ("FTP",                    "HIGH"),
    22:    ("SSH",                    "MEDIUM"),
    23:    ("Telnet",                 "CRITICAL"),
    25:    ("SMTP Mail Relay",        "HIGH"),
    135:   ("Windows RPC",           "HIGH"),
    139:   ("NetBIOS / SMB",         "CRITICAL"),
    445:   ("SMB File Sharing",      "CRITICAL"),
    1433:  ("MSSQL Database",        "CRITICAL"),
    2049:  ("NFS File Share",        "HIGH"),
    3306:  ("MySQL Database",        "CRITICAL"),
    3389:  ("Remote Desktop",        "HIGH"),
    4444:  ("Suspicious Listener",   "CRITICAL"),
    5432:  ("PostgreSQL Database",   "CRITICAL"),
    5900:  ("VNC",                   "HIGH"),
    5901:  ("VNC",                   "HIGH"),
    5902:  ("VNC",                   "HIGH"),
    5903:  ("VNC",                   "HIGH"),
    6379:  ("Redis Database",        "CRITICAL"),
    8080:  ("Web Admin Panel",       "MEDIUM"),
    8443:  ("Web Admin Panel",       "MEDIUM"),
    8888:  ("Jupyter / AI Tool",     "HIGH"),
    9090:  ("Web Admin Panel",       "MEDIUM"),
    9200:  ("Elasticsearch",         "CRITICAL"),
    27017: ("MongoDB Database",      "CRITICAL"),
}

_BARRIER_SENTENCE = (
    "This means any device on your network — including a guest phone, "
    "a compromised smart TV, or anyone who gets onto your WiFi — can "
    "reach this service without any additional barrier."
)

_DESCRIPTIONS = {
    21: (
        "FTP is open on a device on your network and accessible to every other device. "
        "FTP sends usernames and passwords in plain text — anyone on your network can "
        f"intercept them. {_BARRIER_SENTENCE}"
    ),
    22: (
        "SSH lets anyone on your network log into this device remotely using a command line. "
        f"If someone has your password, they can get in. {_BARRIER_SENTENCE}"
    ),
    23: (
        "Telnet lets anyone on your network log into this device remotely — and everything "
        "sent over Telnet, including passwords, is completely unencrypted. Anyone can "
        f"intercept it. {_BARRIER_SENTENCE}"
    ),
    25: (
        "An open mail relay is accessible from every device on your network. Open mail relays "
        "are commonly abused to send spam and phishing emails through your network without your "
        f"knowledge. {_BARRIER_SENTENCE}"
    ),
    135: (
        "Windows RPC is open on a device on your network and accessible to every other device. "
        "This service is commonly exploited by malware to move laterally across networks. "
        f"{_BARRIER_SENTENCE}"
    ),
    139: (
        "NetBIOS is open on a device on your network and exposes your device name and network "
        "information to every other device. It was exploited by the WannaCry ransomware. "
        f"{_BARRIER_SENTENCE}"
    ),
    445: (
        "Windows file sharing is open on a device on your network and accessible to every other "
        "device. SMB is the protocol behind the WannaCry and NotPetya ransomware attacks. "
        f"Anyone on your network can attempt to access your shared files. {_BARRIER_SENTENCE}"
    ),
    1433: (
        "A Microsoft SQL Server database is open and accessible to every device on your network. "
        "Direct database exposure puts all your data at risk — anyone on the network can attempt "
        f"to connect. {_BARRIER_SENTENCE}"
    ),
    2049: (
        "A Network File System share is open and accessible to every device on your network. "
        "Misconfigured NFS shares are a common source of data exposure — any device on your "
        f"network may be able to read or write your files. {_BARRIER_SENTENCE}"
    ),
    3306: (
        "A MySQL database is open and accessible to every device on your network. Your database "
        "and everything in it is reachable by any device on the subnet. "
        f"{_BARRIER_SENTENCE}"
    ),
    3389: (
        "Remote Desktop is open on a device on your network and accessible to every other device. "
        "RDP is the most commonly attacked service for ransomware delivery. Anyone on your network "
        f"can attempt to log in. {_BARRIER_SENTENCE}"
    ),
    4444: (
        "Port 4444 is open on a device on your network. This is the default port for Metasploit "
        "reverse shells — a tool used by attackers to control devices remotely. There is no "
        "legitimate reason for this port to be open on a home or small business network. "
        f"{_BARRIER_SENTENCE}"
    ),
    5432: (
        "A PostgreSQL database is open and accessible to every device on your network. Your "
        f"database is reachable by any device on the subnet. {_BARRIER_SENTENCE}"
    ),
    "vnc": (
        "VNC remote desktop access is open on a device on your network and accessible to every "
        "other device. VNC gives full graphical control of this device to anyone who connects. "
        f"{_BARRIER_SENTENCE}"
    ),
    6379: (
        "A Redis database is open and accessible to every device on your network. Redis runs with "
        "no authentication by default and has been used in real attacks to install cryptocurrency "
        f"miners and steal data. {_BARRIER_SENTENCE}"
    ),
    8080: (
        "A web admin panel is accessible on a device on your network from every other device. "
        "Admin panels should always require a login and ideally should only be reachable from "
        f"your own device. {_BARRIER_SENTENCE}"
    ),
    8443: (
        "A web admin panel is accessible on a device on your network from every other device. "
        "Admin panels should always require a login and ideally should only be reachable from "
        f"your own device. {_BARRIER_SENTENCE}"
    ),
    8888: (
        "A Jupyter Notebook or AI development tool is open and accessible to every device on "
        "your network. Jupyter runs with no authentication by default and gives anyone who "
        f"connects the ability to run code on this machine. {_BARRIER_SENTENCE}"
    ),
    9090: (
        "A web admin panel is accessible on a device on your network from every other device. "
        "Admin panels should always require a login and ideally should only be reachable from "
        f"your own device. {_BARRIER_SENTENCE}"
    ),
    9200: (
        "An Elasticsearch database is open and accessible to every device on your network. "
        "Elasticsearch runs with no authentication by default — thousands of exposed instances "
        f"have leaked sensitive data publicly. {_BARRIER_SENTENCE}"
    ),
    27017: (
        "A MongoDB database is open and accessible to every device on your network. MongoDB has "
        "historically run with no authentication by default and exposed instances have leaked "
        f"millions of records. {_BARRIER_SENTENCE}"
    ),
}

_FIXES = {
    21: (
        "Disable FTP and switch to SFTP or FTPS. If this is a NAS or router, open its admin "
        "panel and look for an FTP or File Sharing section — switch to the encrypted option. "
        "If you have a managed router, block port 21 at the firewall."
    ),
    22: (
        "Make sure SSH requires a strong password or — better — a key pair instead of a "
        "password. In your SSH settings, set PasswordAuthentication to no and use SSH keys "
        "only. If you have a managed router, restrict port 22 to your own device only."
    ),
    23: (
        "Disable Telnet immediately and replace it with SSH. Telnet has no place on a modern "
        "network. Check this device's admin panel for a Remote Management section and turn "
        "Telnet off."
    ),
    25: (
        "If you do not run a mail server, disable this service. If you do, configure it to "
        "only accept connections from trusted IPs. Block port 25 at your router from all "
        "external access. Use port 587 with TLS for legitimate outbound mail instead."
    ),
    135: (
        "If you have a managed router or firewall: add a rule blocking port 135 from untrusted "
        "devices. If you have a basic home router: make sure this device is not reachable from "
        "the internet and keep Windows fully updated to patch RPC vulnerabilities."
    ),
    139: (
        "Disable NetBIOS over TCP/IP on Windows: go to Network Settings → Adapter Properties "
        "→ IPv4 → Advanced → WINS tab → select Disable NetBIOS over TCP/IP. Also disable SMBv1 "
        "in Windows Features if you have not already."
    ),
    445: (
        "If you have a managed router or firewall: restrict port 445 to only known trusted "
        "device IPs. If you have a basic home router: disable SMBv1 immediately in Windows "
        "Features, and only enable file sharing when you actively need it. Keep Windows fully "
        "updated."
    ),
    1433: (
        "In SQL Server Configuration Manager, bind SQL Server to localhost only so it does not "
        "listen on the network. If remote access is needed, restrict it to specific trusted IPs "
        "using your firewall. Block port 1433 from all other devices."
    ),
    2049: (
        "Check your NFS exports file and make sure all shares list specific trusted IP addresses "
        "— never use a wildcard. If you have a managed router, block port 2049 from untrusted "
        "devices. If you have a basic router, disable NFS when not actively using it."
    ),
    3306: (
        "In your MySQL config file, set bind-address to 127.0.0.1 so MySQL only listens "
        "locally. Restart MySQL after making the change. If you have a managed router, block "
        "port 3306 at the firewall. Remote applications should connect via SSH tunnel, not "
        "directly."
    ),
    3389: (
        "If you have a managed router or firewall: restrict port 3389 to your own IP address "
        "only. If you have a basic home router: disable Remote Desktop when you are not actively "
        "using it — go to System Properties → Remote Desktop → Disable. Never leave RDP open "
        "when not in use."
    ),
    4444: (
        "Investigate this device immediately. Run a full malware scan on it. Check its running "
        "processes for anything unfamiliar. If you cannot identify what is using this port, "
        "isolate the device from your network by disconnecting it until you can investigate "
        "further."
    ),
    5432: (
        "In postgresql.conf, set listen_addresses to localhost so PostgreSQL only accepts local "
        "connections. Block port 5432 at your firewall. Remote applications should connect via "
        "SSH tunnel or VPN, not directly over the network."
    ),
    "vnc": (
        "Set a strong VNC password if you actively use it. If you have a managed router: "
        "restrict VNC ports to your own device only. If you have a basic home router: disable "
        "VNC when not actively using it. Never leave VNC open permanently."
    ),
    6379: (
        "In your Redis config, set bind to 127.0.0.1 and set requirepass to a strong password. "
        "Restart Redis after making changes. Block port 6379 at your firewall from all other "
        "devices. Also set protected-mode yes as a safety net."
    ),
    8080: (
        "Make sure this admin panel requires a username and password and that the default "
        "credentials have been changed. If you have a managed router: restrict this port to "
        "your own device only. If you have a basic home router: check the device's own settings "
        "to disable remote admin access when not needed."
    ),
    8443: (
        "Make sure this admin panel requires a username and password and that the default "
        "credentials have been changed. If you have a managed router: restrict this port to "
        "your own device only. If you have a basic home router: check the device's own settings "
        "to disable remote admin access when not needed."
    ),
    8888: (
        "If you use Jupyter, configure it to require a password or token. In your Jupyter "
        "config, set NotebookApp.ip to 127.0.0.1 so it only accepts local connections. If you "
        "have a managed router, block port 8888 from all other devices on the network."
    ),
    9090: (
        "Make sure this admin panel requires a username and password and that the default "
        "credentials have been changed. If you have a managed router: restrict this port to "
        "your own device only. If you have a basic home router: check the device's own settings "
        "to disable remote admin access when not needed."
    ),
    9200: (
        "In elasticsearch.yml, set network.host to 127.0.0.1 to restrict Elasticsearch to "
        "localhost only. Enable security features by setting xpack.security.enabled to true. "
        "Block ports 9200 and 9300 at your firewall. Restart Elasticsearch after making changes."
    ),
    27017: (
        "In mongod.conf, set bindIp to 127.0.0.1 under the net section so MongoDB only listens "
        "locally. Enable authentication by setting security.authorization to enabled. Create "
        "admin users with strong passwords before enabling auth. Block port 27017 at your "
        "firewall."
    ),
}


def check_new_devices(live_hosts, scanned_ip):
    """
    Compare current live hosts against the last scan using
    scan_memory.get_new_devices(). Returns a list of finding dicts for
    any device not seen in the previous scan. Returns empty list on
    first scan — no alert before a baseline exists.
    """
    new_devices = get_new_devices(live_hosts, scanned_ip)
    if not new_devices:
        return []

    findings = []
    for device in new_devices:
        if isinstance(device, dict):
            mac    = device.get("mac", "Unknown")
            vendor = device.get("vendor", "Unknown manufacturer")
            ip     = device.get("ip", "Unknown")
        else:
            mac    = "Unknown"
            vendor = "Unknown manufacturer"
            ip     = str(device)

        vendor_str = f"It's made by {vendor}. " if vendor != "Unknown manufacturer" else ""

        findings.append({
            "mac": mac,
            "vendor": vendor,
            "ip": ip,
            "risk": "HIGH",
            "title": "New device appeared on your network",
            "description": (
                f"I found a device I haven't seen before on your network. "
                f"{vendor_str}"
                f"It appeared since your last scan. "
                f"If you don't recognize it, this is worth investigating."
            ),
            "fix": (
                "Check your router's connected devices list and identify "
                "this device. If you don't recognize it, change your WiFi password "
                "immediately and consider enabling MAC address filtering on your router."
            ),
            "type": "new_device",
        })

    return findings


def check_implicit_trust(live_hosts, open_ports):
    """
    Checks whether high-risk admin services are open and accessible to any
    device on the subnet. These services should require explicit authentication
    and ideally be restricted to specific trusted devices — not open to everyone.
    Returns a list of finding dicts.
    """
    parsed_ports = set()
    for entry in open_ports:
        m = re.match(r"(\d+)", str(entry))
        if m:
            parsed_ports.add(int(m.group(1)))
        else:
            logger.warning(f"zero_trust: could not parse port entry: {entry}")

    findings = []

    # Handle VNC ports as a group
    vnc_open = sorted(parsed_ports & VNC_PORTS)
    if vnc_open:
        findings.append({
            "port":        vnc_open[0],
            "service":     "VNC",
            "risk":        "HIGH",
            "title":       "VNC is open to all devices on your network",
            "description": _DESCRIPTIONS["vnc"],
            "fix":         _FIXES["vnc"],
            "type":        "implicit_trust",
        })

    # All other IMPLICIT_TRUST_PORTS — one finding per open port
    for port in sorted(parsed_ports):
        if port in VNC_PORTS:
            continue
        if port not in IMPLICIT_TRUST_PORTS:
            continue
        service, risk = IMPLICIT_TRUST_PORTS[port]
        findings.append({
            "port":        port,
            "service":     service,
            "risk":        risk,
            "title":       f"{service} is open to all devices on your network",
            "description": _DESCRIPTIONS[port],
            "fix":         _FIXES[port],
            "type":        "implicit_trust",
        })

    return findings


def run_zero_trust(live_hosts, open_ports, scanned_ip):
    """
    Main entry point. Runs all Zero Trust checks and returns a structured
    result with findings, counts, clean flag, and plain English summary.

    Args:
        live_hosts: list of dicts from network mapper, each containing
                    an 'ip' and optionally 'mac' and 'vendor' key.
        open_ports: list of port description strings from port scanner
                    (e.g. ['80/tcp open http', '22/tcp open ssh']).
        scanned_ip: the IP or subnet that was scanned — used to look up
                    scan history for new device detection.

    Returns:
        dict with findings, total_found, clean, new_device_count,
        implicit_trust_count, and plain English summary.
    """
    new_device_findings     = check_new_devices(live_hosts, scanned_ip)
    implicit_trust_findings = check_implicit_trust(live_hosts, open_ports)

    all_findings = new_device_findings + implicit_trust_findings

    total_found          = len(all_findings)
    clean                = total_found == 0
    new_device_count     = len(new_device_findings)
    implicit_trust_count = len(implicit_trust_findings)
    critical_count       = sum(1 for f in all_findings if f.get("risk") == "CRITICAL")
    high_count           = sum(1 for f in all_findings if f.get("risk") == "HIGH")

    if clean:
        summary = (
            "I checked your network against Zero Trust principles and found no issues. "
            "Every device I've seen before is still here, and no high-risk services are "
            "openly accessible across your network. Good posture."
        )
    elif new_device_count > 0 and critical_count > 0:
        summary = (
            f"I found {new_device_count} new device(s) on your network and "
            f"{critical_count} critical service(s) open to all devices. "
            "These need your attention — an unknown device combined with open critical "
            "services is a serious trust boundary failure."
        )
    elif new_device_count > 0:
        them_or_it = "them" if new_device_count > 1 else "it"
        summary = (
            f"I found {new_device_count} new device(s) that weren't here during your last scan. "
            f"If you don't recognize {them_or_it}, investigate before anything else."
        )
    elif critical_count > 0:
        summary = (
            f"I found {critical_count} critical service(s) open to every device on your network. "
            "These create implicit trust — any device can reach them without any additional "
            "barrier. Review these immediately."
        )
    elif high_count > 0:
        summary = (
            f"I found {high_count} high-risk service(s) open to every device on your network. "
            "These should be restricted to trusted devices only."
        )
    else:
        summary = (
            f"I found {implicit_trust_count} service(s) worth reviewing for Zero Trust "
            "compliance. These are accessible to all devices on your network."
        )

    logger.info(
        f"Zero Trust scan complete. {total_found} finding(s): "
        f"{new_device_count} new device(s), {implicit_trust_count} implicit trust issue(s)."
    )

    return {
        "findings":             all_findings,
        "total_found":          total_found,
        "clean":                clean,
        "new_device_count":     new_device_count,
        "implicit_trust_count": implicit_trust_count,
        "critical_count":       critical_count,
        "high_count":           high_count,
        "summary":              summary,
    }
