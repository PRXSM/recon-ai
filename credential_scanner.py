"""
credential_scanner.py — Phase 9
Credential Risk Assessment.
Checks discovered network devices for authentication weaknesses.

Three checks:
1. Insecure protocols — Telnet, FTP, plain HTTP admin panels
2. Default credentials — common factory username/password combinations
3. Admin service exposure — SSH, RDP, web admin panels open with no protection

This tool NEVER stores, logs, or transmits any credential it tests.
It attempts a connection, reads the response, and discards everything.
Recon AI observes and reports only. The user decides what to do.
"""

import re

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

INSECURE_PORTS = {
    21: {
        "service": "FTP",
        "risk": "HIGH",
        "description": (
            "FTP transmits your username and password in plain text. "
            "Anyone on the same network can intercept them. "
            "Use SFTP or FTPS instead."
        ),
        "fix": (
            "Disable FTP and switch to SFTP or FTPS instead. "
            "If this is a NAS or router, open its admin panel and look for "
            "an FTP or File Sharing section — turn it off or switch to "
            "the encrypted option."
        ),
    },
    23: {
        "service": "Telnet",
        "risk": "CRITICAL",
        "description": (
            "Telnet sends everything — including passwords — in plain text. "
            "It has no encryption whatsoever. "
            "Replace it with SSH immediately."
        ),
        "fix": (
            "Disable Telnet on this device and enable SSH instead. "
            "Check your router or device admin panel for a "
            "'Remote Management' or 'Administration' section and turn "
            "Telnet off. SSH uses port 22 and provides the same remote "
            "access with full encryption."
        ),
    },
    25: {
        "service": "SMTP (Unencrypted)",
        "risk": "HIGH",
        "description": (
            "Unencrypted email sending. Credentials and message content "
            "can be intercepted. Use port 587 with TLS instead."
        ),
        "fix": (
            "Configure your mail server or email client to use port 587 "
            "with STARTTLS, or port 465 with SSL/TLS. "
            "Block port 25 at your firewall unless this is a dedicated "
            "mail relay — most devices don't need it open."
        ),
    },
    53: {
        "service": "DNS (Open Resolver)",
        "risk": "MEDIUM",
        "description": (
            "An open DNS resolver can be abused for amplification attacks "
            "and DNS poisoning. Should not be publicly accessible."
        ),
        "fix": (
            "If this is your router, disable external DNS resolution in "
            "its admin panel — it should only answer DNS queries from your "
            "own devices. If it's a server, configure your DNS software "
            "(e.g. BIND or Unbound) to restrict recursion to trusted "
            "IP ranges only."
        ),
    },
    69: {
        "service": "TFTP",
        "risk": "HIGH",
        "description": (
            "Trivial File Transfer Protocol has no authentication whatsoever. "
            "Anyone can read or write files on this service."
        ),
        "fix": (
            "Disable TFTP unless you specifically need it for device "
            "provisioning (e.g. IP phones or network switches). "
            "If it must run, restrict it with firewall rules so only "
            "known management IPs can reach it."
        ),
    },
    80: {
        "service": "HTTP (Unencrypted Web)",
        "risk": "MEDIUM",
        "description": (
            "Unencrypted web traffic. Any login credentials or data "
            "entered on this page travel in plain text across the network."
        ),
        "fix": (
            "Enable HTTPS on this device. If it's a router or IoT device, "
            "check its admin panel for an HTTPS or SSL option and enable it. "
            "If it's a web server, install a TLS certificate — Let's Encrypt "
            "provides free certificates. Redirect all HTTP traffic to HTTPS."
        ),
    },
    110: {
        "service": "POP3 (Unencrypted Email)",
        "risk": "HIGH",
        "description": (
            "Unencrypted email retrieval. Your email password and messages "
            "can be intercepted. Use POP3S on port 995 instead."
        ),
        "fix": (
            "Switch your email client to use POP3S on port 995, which "
            "uses SSL/TLS encryption. In your mail client settings, "
            "look for 'Security' or 'Encryption' and set it to SSL/TLS. "
            "If you run your own mail server, disable plain POP3 and "
            "enable only the encrypted version."
        ),
    },
    111: {
        "service": "RPCBind",
        "risk": "HIGH",
        "description": (
            "Remote Procedure Call service. Often exploited to enumerate "
            "network services and launch further attacks. Should not be "
            "publicly accessible."
        ),
        "fix": (
            "Block port 111 at your firewall so it is not reachable from "
            "outside your trusted network. On Linux, you can disable rpcbind "
            "with: sudo systemctl disable rpcbind && sudo systemctl stop rpcbind "
            "— unless you specifically need NFS or other RPC services."
        ),
    },
    119: {
        "service": "NNTP",
        "risk": "MEDIUM",
        "description": (
            "Network News Transfer Protocol — unencrypted and rarely needed "
            "on modern networks. Should be disabled."
        ),
        "fix": (
            "Disable the NNTP service on this device. It is almost never "
            "needed on a modern home or business network. Check your server "
            "or device services list and stop the NNTP daemon, then remove "
            "it from startup."
        ),
    },
    135: {
        "service": "Microsoft RPC",
        "risk": "HIGH",
        "description": (
            "Microsoft Remote Procedure Call. Commonly targeted by worms "
            "and exploits. Should never be exposed outside a trusted network."
        ),
        "fix": (
            "Block port 135 at your firewall — it should never be reachable "
            "from the internet. On Windows, use Windows Firewall to restrict "
            "this port to your local network only. "
            "This port is required internally by Windows but should not be "
            "visible beyond your LAN."
        ),
    },
    137: {
        "service": "NetBIOS Name Service",
        "risk": "HIGH",
        "description": (
            "NetBIOS exposes device names and network information. "
            "A common target for enumeration and lateral movement attacks."
        ),
        "fix": (
            "Disable NetBIOS over TCP/IP on Windows: go to Network Settings "
            "→ Adapter Properties → IPv4 → Advanced → WINS tab → "
            "select 'Disable NetBIOS over TCP/IP'. "
            "Also block ports 137-139 at your firewall from external access."
        ),
    },
    138: {
        "service": "NetBIOS Datagram",
        "risk": "HIGH",
        "description": (
            "NetBIOS datagram service. Used in older Windows file sharing. "
            "Should be disabled on modern networks."
        ),
        "fix": (
            "Disable NetBIOS over TCP/IP on Windows: go to Network Settings "
            "→ Adapter Properties → IPv4 → Advanced → WINS tab → "
            "select 'Disable NetBIOS over TCP/IP'. "
            "Block ports 137-139 at your firewall."
        ),
    },
    139: {
        "service": "NetBIOS Session (SMB)",
        "risk": "CRITICAL",
        "description": (
            "SMB over NetBIOS. Used by EternalBlue and WannaCry ransomware. "
            "Should never be exposed to the internet or untrusted networks."
        ),
        "fix": (
            "Block port 139 at your firewall immediately — it should never "
            "be reachable from the internet. On Windows, also disable SMBv1: "
            "go to Control Panel → Programs → Turn Windows features on or off "
            "→ uncheck 'SMB 1.0/CIFS File Sharing Support'. "
            "Modern Windows uses port 445 for SMB instead."
        ),
    },
    143: {
        "service": "IMAP (Unencrypted Email)",
        "risk": "HIGH",
        "description": (
            "Unencrypted email access. Your credentials and emails travel "
            "in plain text. Use IMAPS on port 993 instead."
        ),
        "fix": (
            "Switch your email client to IMAPS on port 993. "
            "In your mail client's account settings, change the IMAP port "
            "from 143 to 993 and set encryption to SSL/TLS. "
            "If you run your own mail server, configure it to require "
            "TLS on IMAP connections."
        ),
    },
    161: {
        "service": "SNMP",
        "risk": "HIGH",
        "description": (
            "Simple Network Management Protocol. Often misconfigured with "
            "default community strings like 'public' or 'private' that "
            "expose full device information to anyone who asks."
        ),
        "fix": (
            "Change the SNMP community strings from the defaults ('public', "
            "'private') to something long and random. If you don't use SNMP "
            "for network management, disable it entirely in your device's "
            "admin panel. Also upgrade to SNMPv3 which supports real "
            "authentication and encryption."
        ),
    },
    389: {
        "service": "LDAP (Unencrypted)",
        "risk": "HIGH",
        "description": (
            "Unencrypted directory service. Credentials and directory data "
            "travel in plain text. Use LDAPS on port 636 instead."
        ),
        "fix": (
            "Enable LDAPS (LDAP over SSL/TLS) on port 636 and require "
            "encrypted connections only. Install a TLS certificate on your "
            "directory server and configure clients to connect on port 636. "
            "Block port 389 from any untrusted network segments."
        ),
    },
    445: {
        "service": "SMB (Direct)",
        "risk": "CRITICAL",
        "description": (
            "Server Message Block — Windows file sharing. "
            "Exploited by EternalBlue, WannaCry, and NotPetya. "
            "Should never be exposed outside your local trusted network."
        ),
        "fix": (
            "Block port 445 at your firewall — it must never be reachable "
            "from the internet. On Windows, disable SMBv1 in Control Panel "
            "→ Programs → Turn Windows features on or off → uncheck "
            "'SMB 1.0/CIFS File Sharing Support'. "
            "Keep Windows fully updated to patch SMB vulnerabilities."
        ),
    },
    512: {
        "service": "rexec",
        "risk": "CRITICAL",
        "description": (
            "Remote execution service with no encryption. "
            "Should not be running on any modern network."
        ),
        "fix": (
            "Disable the rexec service immediately. On Linux/Unix: "
            "remove or comment out the rexec line in /etc/inetd.conf or "
            "/etc/xinetd.d/, then restart inetd/xinetd. "
            "Replace any remote execution needs with SSH."
        ),
    },
    513: {
        "service": "rlogin",
        "risk": "CRITICAL",
        "description": (
            "Remote login with no encryption. "
            "Replace with SSH immediately."
        ),
        "fix": (
            "Disable rlogin on this device. On Linux/Unix, remove or "
            "disable the login entry in /etc/inetd.conf or the xinetd "
            "config directory. Install and configure SSH (openssh-server) "
            "as the replacement for all remote login needs."
        ),
    },
    514: {
        "service": "rsh",
        "risk": "CRITICAL",
        "description": (
            "Remote shell with no authentication or encryption. "
            "Extremely dangerous if exposed."
        ),
        "fix": (
            "Disable rsh immediately. On Linux/Unix, remove or disable "
            "the shell entry in /etc/inetd.conf or xinetd config. "
            "Delete any .rhosts files that grant passwordless access: "
            "find / -name .rhosts -delete. Use SSH for all remote access."
        ),
    },
    515: {
        "service": "LPD (Line Printer Daemon)",
        "risk": "MEDIUM",
        "description": (
            "Legacy printing protocol with no authentication. "
            "Can be abused to send arbitrary print jobs or crash printers."
        ),
        "fix": (
            "If you don't need network printing on this device, disable LPD. "
            "On Linux: sudo systemctl disable cups-lpd. "
            "If printing is required, use IPP (Internet Printing Protocol) "
            "instead, which has better security controls, and restrict "
            "access to trusted IPs via firewall rules."
        ),
    },
    873: {
        "service": "rsync",
        "risk": "HIGH",
        "description": (
            "File synchronization service. If misconfigured, allows "
            "unauthenticated access to read or write files on the device."
        ),
        "fix": (
            "Check your /etc/rsyncd.conf file: ensure all modules require "
            "authentication (add 'auth users' and 'secrets file' directives) "
            "and restrict access with 'hosts allow'. "
            "If rsync is not needed externally, block port 873 at the "
            "firewall or run rsync only over SSH (rsync -e ssh)."
        ),
    },
    1433: {
        "service": "MSSQL",
        "risk": "CRITICAL",
        "description": (
            "Microsoft SQL Server database. Should never be exposed "
            "to the network without authentication. Default SA account "
            "with blank password is a critical risk."
        ),
        "fix": (
            "In SQL Server Configuration Manager, bind SQL Server to "
            "localhost only so it doesn't listen on external interfaces. "
            "Disable the SA account or set a strong password for it. "
            "Block port 1433 at your firewall. "
            "Applications should connect via a local socket or VPN, "
            "never directly over the internet."
        ),
    },
    1521: {
        "service": "Oracle DB",
        "risk": "CRITICAL",
        "description": (
            "Oracle database port. Direct database exposure is a critical "
            "risk. Should be behind a firewall and never publicly accessible."
        ),
        "fix": (
            "Block port 1521 at your firewall immediately. "
            "Configure Oracle Listener to only accept connections from "
            "trusted application server IPs. Change all default Oracle "
            "passwords (SYS, SYSTEM, DBSNMP). "
            "Applications should connect through an application tier, "
            "never directly from client devices."
        ),
    },
    2049: {
        "service": "NFS",
        "risk": "HIGH",
        "description": (
            "Network File System. If misconfigured, allows unauthenticated "
            "access to shared files. A common source of data exposure."
        ),
        "fix": (
            "Check /etc/exports and ensure all NFS shares explicitly list "
            "trusted IP addresses (e.g. /data 192.168.1.0/24(rw,sync)). "
            "Never use wildcard (*) exports. "
            "Block port 2049 at your firewall from untrusted networks. "
            "Consider using NFSv4 with Kerberos authentication."
        ),
    },
    3306: {
        "service": "MySQL",
        "risk": "CRITICAL",
        "description": (
            "MySQL database. Should never be exposed to the network "
            "without strong authentication. Direct database exposure "
            "puts all your data at risk."
        ),
        "fix": (
            "In your MySQL config file (my.cnf or my.ini), set "
            "'bind-address = 127.0.0.1' so MySQL only listens on localhost. "
            "Restart MySQL after making the change. "
            "Block port 3306 at your firewall. "
            "Applications on other servers should connect via SSH tunnel "
            "or a VPN, not directly over the network."
        ),
    },
    3389: {
        "service": "RDP (Remote Desktop)",
        "risk": "CRITICAL",
        "description": (
            "Windows Remote Desktop. A top target for brute force attacks "
            "and ransomware delivery. Should never be exposed to the "
            "internet without a VPN."
        ),
        "fix": (
            "Do not expose RDP directly to the internet. "
            "Set up a VPN (e.g. WireGuard or OpenVPN) and require VPN "
            "connection before allowing RDP. "
            "If RDP must be accessible, enable Network Level Authentication "
            "in System Properties → Remote Desktop, and use Windows Firewall "
            "to restrict port 3389 to known IP addresses only."
        ),
    },
    4444: {
        "service": "Metasploit Default",
        "risk": "CRITICAL",
        "description": (
            "Port 4444 is the default listener port for Metasploit "
            "reverse shells. If this is open, investigate immediately."
        ),
        "fix": (
            "Investigate this device immediately — port 4444 has no "
            "legitimate business use and is the default port for Metasploit "
            "reverse shell payloads. "
            "Run a full antivirus/malware scan, check running processes "
            "for anything unfamiliar, and review recent login history. "
            "Block port 4444 at your firewall as an immediate step."
        ),
    },
    5432: {
        "service": "PostgreSQL",
        "risk": "CRITICAL",
        "description": (
            "PostgreSQL database. Direct exposure puts all your data at risk. "
            "Should be behind a firewall and never publicly accessible."
        ),
        "fix": (
            "In postgresql.conf, set listen_addresses = 'localhost' so "
            "PostgreSQL only accepts local connections. "
            "Also review pg_hba.conf to ensure only trusted hosts can "
            "authenticate. Block port 5432 at your firewall. "
            "Remote applications should connect via SSH tunnel or VPN."
        ),
    },
    5900: {
        "service": "VNC",
        "risk": "HIGH",
        "description": (
            "VNC allows full remote desktop access. If not properly "
            "secured, anyone can take control of this device."
        ),
        "fix": (
            "Never expose VNC directly to the internet. "
            "Set a strong VNC password (not blank or default). "
            "Use an SSH tunnel for VNC: ssh -L 5900:localhost:5900 user@host "
            "then connect VNC to localhost:5900 on your end. "
            "Block port 5900 at your firewall from all external access."
        ),
    },
    6379: {
        "service": "Redis",
        "risk": "CRITICAL",
        "description": (
            "Redis database — often runs with no authentication by default. "
            "Exposed Redis instances have been used to install cryptominers "
            "and steal data. Should never be publicly accessible."
        ),
        "fix": (
            "In redis.conf, set 'bind 127.0.0.1' to restrict Redis to "
            "localhost only, and set 'requirepass YourStrongPassword' to "
            "require authentication. Restart Redis after making changes. "
            "Block port 6379 at your firewall. "
            "Also set 'protected-mode yes' as a safety net."
        ),
    },
    8080: {
        "service": "HTTP Alternate / Admin Panel",
        "risk": "MEDIUM",
        "description": (
            "Common alternate HTTP port. Often used for admin panels "
            "on routers and IoT devices. Check if this requires "
            "authentication and uses HTTPS."
        ),
        "fix": (
            "Open this address in your browser and check whether it "
            "prompts for a login. If it doesn't require authentication, "
            "disable remote management in your device's settings. "
            "Change the default admin password if you haven't already. "
            "If possible, switch the admin panel to HTTPS."
        ),
    },
    9200: {
        "service": "Elasticsearch",
        "risk": "CRITICAL",
        "description": (
            "Elasticsearch database API — runs with no authentication "
            "by default. Thousands of exposed Elasticsearch instances "
            "have leaked sensitive data publicly."
        ),
        "fix": (
            "In elasticsearch.yml, set 'network.host: 127.0.0.1' to "
            "restrict Elasticsearch to localhost only. "
            "Enable the built-in security features: set "
            "'xpack.security.enabled: true' (available in all versions "
            "since 6.8/7.1). Block port 9200 and 9300 at your firewall. "
            "Restart Elasticsearch after changes."
        ),
    },
    11211: {
        "service": "Memcached",
        "risk": "HIGH",
        "description": (
            "Memcached runs with no authentication by default. "
            "Has been used in massive DDoS amplification attacks. "
            "Should never be publicly accessible."
        ),
        "fix": (
            "Bind Memcached to localhost: start it with the -l 127.0.0.1 "
            "flag, or set '-l 127.0.0.1' in your Memcached config. "
            "Block port 11211 at your firewall from all external access. "
            "Also disable UDP support with the -U 0 flag to prevent "
            "use in amplification attacks."
        ),
    },
    27017: {
        "service": "MongoDB",
        "risk": "CRITICAL",
        "description": (
            "MongoDB database — historically ran with no authentication "
            "by default. Exposed MongoDB instances have leaked millions "
            "of records. Should never be publicly accessible."
        ),
        "fix": (
            "In mongod.conf, set bindIp to 127.0.0.1 under the net section "
            "so MongoDB only listens locally. Enable authentication by "
            "setting 'security.authorization: enabled'. "
            "Create admin users with strong passwords before enabling auth. "
            "Block port 27017 at your firewall."
        ),
    },
}

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", ""),
    ("root", "root"),
    ("root", ""),
    ("root", "toor"),
    ("user", "user"),
    ("guest", "guest"),
    ("admin", "admin123"),
]

ADMIN_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP (Remote Desktop)",
    5900: "VNC",
    8080: "Web Admin Panel",
    8443: "Web Admin Panel (HTTPS)",
    8888: "Web Admin Panel",
    9090: "Web Admin Panel",
}


def check_insecure_protocols(ip, open_ports):
    """
    Check if any open ports match known insecure protocols.
    Returns a list of finding dicts.
    """
    findings = []
    for port in open_ports:
        if port in INSECURE_PORTS:
            entry = INSECURE_PORTS[port]
            findings.append({
                "ip": ip,
                "port": port,
                "service": entry["service"],
                "risk": entry["risk"],
                "description": entry["description"],
                "fix": entry["fix"],
            })
    return findings


def check_default_credentials(ip, open_ports):
    """
    Attempt HTTP basic auth on port 80 or 8080 using DEFAULT_CREDENTIALS.
    Makes real login attempts — read-only, discards all results immediately.
    Reports only whether a default credential was accepted. Never stores,
    logs, or transmits any credential. Runs only on networks the user has
    confirmed they own via the authorization checkbox.
    Returns a list of finding dicts.
    """
    if not REQUESTS_AVAILABLE:
        return []

    findings = []
    web_ports = [p for p in open_ports if p in (80, 8080)]

    for port in web_ports:
        scheme = "http"
        url = f"{scheme}://{ip}:{port}/"
        accepted = False

        for username, password in DEFAULT_CREDENTIALS:
            if accepted:
                break
            try:
                response = requests.get(
                    url,
                    auth=(username, password),
                    timeout=3,
                    allow_redirects=True,
                    verify=False,
                )
                if response.status_code == 200:
                    accepted = True
            except Exception:
                continue

        if accepted:
            findings.append({
                "ip": ip,
                "port": port,
                "service": "Web Admin Panel",
                "risk": "CRITICAL",
                "description": (
                    "This device accepted a default username and password. "
                    "Anyone who knows the factory defaults can log in."
                ),
                "fix": (
                    "Log into this device and change the admin password "
                    "immediately to something unique and strong. "
                    "Use at least 12 characters with a mix of letters, "
                    "numbers, and symbols. Never use the same password "
                    "on more than one device."
                ),
            })

    return findings


def check_admin_exposure(ip, open_ports):
    """
    Check if admin service ports are open on the device.
    Returns a list of finding dicts.
    """
    risk_map = {
        22: ("MEDIUM", (
            "SSH is open on this device. SSH itself is encrypted and "
            "reasonably secure, but if it's using password authentication "
            "instead of key-based auth, it's vulnerable to brute force attacks."
        ), (
            "Switch SSH to key-based authentication and disable password login. "
            "In /etc/ssh/sshd_config, set 'PasswordAuthentication no' and "
            "'PubkeyAuthentication yes'. Also consider changing SSH to a "
            "non-standard port to reduce automated scanning noise."
        )),
        23: ("CRITICAL", (
            "Telnet is open. This service sends everything — including "
            "passwords — in plain text with zero encryption."
        ), (
            "Disable Telnet immediately and replace it with SSH. "
            "Check your device's admin panel for a 'Remote Management' "
            "section and turn Telnet off."
        )),
        3389: ("HIGH", (
            "Remote Desktop (RDP) is exposed on this device. "
            "RDP is a top target for brute force and ransomware attacks. "
            "It should never be directly accessible from outside your "
            "trusted network."
        ), (
            "Block port 3389 at your firewall from all external access. "
            "Require a VPN connection before allowing RDP. Enable Network "
            "Level Authentication in System Properties → Remote Desktop."
        )),
        5900: ("HIGH", (
            "VNC remote desktop access is open. VNC gives full graphical "
            "control of this device and must be properly secured."
        ), (
            "Never expose VNC directly to the internet. Set a strong VNC "
            "password and access it only through an SSH tunnel. "
            "Block port 5900 at your firewall."
        )),
        8080: ("HIGH", (
            "A web admin panel is accessible on port 8080. "
            "Admin panels exposed to the network should always require "
            "authentication and use HTTPS."
        ), (
            "Confirm this panel requires a login. If it doesn't, disable "
            "remote management in your device settings. Change the default "
            "admin password and switch to HTTPS if supported."
        )),
        8443: ("HIGH", (
            "A web admin panel is accessible on port 8443 (HTTPS). "
            "While HTTPS is good, admin panels should still be restricted "
            "to trusted IPs only."
        ), (
            "Verify this panel requires authentication and restrict access "
            "to known IP addresses using your firewall. "
            "Change the default admin password if you haven't already."
        )),
        8888: ("HIGH", (
            "A web admin panel is accessible on port 8888. "
            "Admin panels exposed to the network are a common attack target."
        ), (
            "Confirm this panel requires authentication. Change default "
            "credentials if present. Restrict access to this port to "
            "trusted IPs using your firewall rules."
        )),
        9090: ("HIGH", (
            "A web admin panel is accessible on port 9090. "
            "This is commonly used by device management interfaces and "
            "monitoring tools that may have default credentials."
        ), (
            "Check that this panel requires a login and that default "
            "credentials have been changed. Block port 9090 from external "
            "access at your firewall if it's only needed internally."
        )),
    }

    findings = []
    reported_ports = set()

    for port in open_ports:
        if port in ADMIN_PORTS and port in risk_map:
            risk, description, fix = risk_map[port]
            service = ADMIN_PORTS[port]
            if port not in reported_ports:
                findings.append({
                    "ip": ip,
                    "port": port,
                    "service": service,
                    "risk": risk,
                    "description": description,
                    "fix": fix,
                })
                reported_ports.add(port)

    return findings


def run_credential_assessment(live_hosts, open_ports):
    """
    Main entry point. Runs all three credential checks across all discovered hosts.

    Args:
        live_hosts: list of dicts from network mapper, each containing an "ip" key.
        open_ports: list of port description strings from port scanner
                    (e.g. ["80/tcp open http", "22/tcp open ssh"]).

    Returns:
        dict with findings, counts, clean flag, and plain English summary.
    """
    # Parse port numbers from port scanner output strings
    parsed_ports = []
    for entry in open_ports:
        match = re.match(r"(\d+)", str(entry))
        if match:
            parsed_ports.append(int(match.group(1)))
    parsed_ports = list(set(parsed_ports))

    all_findings = []
    devices_checked = 0

    for host in live_hosts:
        ip = host.get("ip") if isinstance(host, dict) else str(host)
        if not ip:
            continue

        devices_checked += 1
        reported_keys = set()

        protocol_findings = check_insecure_protocols(ip, parsed_ports)
        admin_findings = check_admin_exposure(ip, parsed_ports)
        credential_findings = check_default_credentials(ip, parsed_ports)

        for finding in protocol_findings + admin_findings + credential_findings:
            key = (finding["ip"], finding["port"], finding["service"])
            if key not in reported_keys:
                all_findings.append(finding)
                reported_keys.add(key)

    critical_count = sum(1 for f in all_findings if f["risk"] == "CRITICAL")
    high_count = sum(1 for f in all_findings if f["risk"] == "HIGH")
    medium_count = sum(1 for f in all_findings if f["risk"] == "MEDIUM")
    clean = len(all_findings) == 0

    affected_ips = len({f["ip"] for f in all_findings if f["risk"] in ("CRITICAL", "HIGH")})

    if clean:
        summary = (
            f"I checked {devices_checked} device(s) and found no credential risks. "
            "Good posture."
        )
    elif critical_count > 0:
        summary = (
            f"I found critical credential risks on {affected_ips} device(s). "
            "These need immediate attention."
        )
    elif high_count > 0:
        high_ips = len({f["ip"] for f in all_findings if f["risk"] == "HIGH"})
        summary = (
            f"I found authentication weaknesses on {high_ips} device(s). "
            "Review these soon."
        )
    else:
        med_ips = len({f["ip"] for f in all_findings if f["risk"] == "MEDIUM"})
        summary = (
            f"I found {med_ips} device(s) with admin services exposed. "
            "Worth reviewing."
        )

    return {
        "findings": all_findings,
        "total_devices_checked": devices_checked,
        "clean": clean,
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "summary": summary,
    }
