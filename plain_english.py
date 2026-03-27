"""
plain_english.py — Offline knowledge base for common port findings.
No API key or internet connection required.
Covers every port in vulnerability_reporter.py VULNERABILITY_DB.
"""

PORT_EXPLANATIONS = {
    21: {
        "name": "FTP (File Transfer Protocol)",
        "what_it_is": (
            "FTP is an old protocol used to transfer files between computers. "
            "Think of it as a file-sharing service from the 1970s that was never designed with security in mind."
        ),
        "why_its_risky": (
            "Everything sent over FTP — including your username and password — travels across the network as plain text. "
            "Anyone on the same network (or between you and the server) can read it like an open letter. "
            "Attackers regularly scan for open FTP ports and attempt to log in with common credentials."
        ),
        "risk_level": "HIGH",
        "fix_steps": [
            "Disable FTP entirely if you don't actively use it.",
            "If you need file transfers, use SFTP (SSH File Transfer Protocol) on port 22 instead — it encrypts everything.",
            "Alternatively, use SCP or a modern tool like rsync over SSH.",
            "If FTP must stay, restrict access to specific IP addresses via your firewall.",
        ],
        "verify": "Run a scan again — port 21 should be gone. That means the door is closed.",
        "verify_deep": [
            "Run 'nmap -p 21 localhost' — it should show 'closed' or 'filtered'.",
            "Try 'ftp localhost' in terminal — it should refuse the connection.",
            "Check running services with 'sudo lsof -i :21' — nothing should appear.",
        ],
    },
    22: {
        "name": "SSH (Secure Shell)",
        "what_it_is": (
            "SSH is the secure, encrypted way to remotely log into another computer. "
            "It's the standard tool for server administration and is generally well-designed."
        ),
        "why_its_risky": (
            "SSH itself is secure, but an open SSH port is a constant target for brute-force attacks — "
            "automated bots try millions of username/password combinations around the clock. "
            "If you use weak passwords or allow root login, this becomes a serious vulnerability."
        ),
        "risk_level": "LOW",
        "fix_steps": [
            "Switch to key-based authentication and disable password login entirely.",
            "Disable root login via SSH (set 'PermitRootLogin no' in /etc/ssh/sshd_config).",
            "Consider moving SSH to a non-standard port to reduce automated scan noise.",
            "Use fail2ban or similar to automatically block IPs after repeated failed attempts.",
            "Restrict SSH access to specific IP addresses if possible.",
        ],
        "verify": "Try logging in with a password instead of your key — it should be rejected. That means key-only auth is working.",
        "verify_deep": [
            "Run 'ssh -o PreferredAuthentications=password user@localhost' — should say permission denied.",
            "Check sshd_config: 'grep Password /etc/ssh/sshd_config' — should show PasswordAuthentication no.",
            "Run 'sudo lsof -i :22' to confirm only your SSH daemon is listening.",
        ],
    },
    23: {
        "name": "Telnet",
        "what_it_is": (
            "Telnet is a very old remote login protocol from 1969. "
            "It was the predecessor to SSH and is entirely unencrypted."
        ),
        "why_its_risky": (
            "Telnet sends absolutely everything in plaintext — your password, every command you type, "
            "every response from the server. Anyone between you and the device can see it all. "
            "There is no legitimate reason to run Telnet on a modern network."
        ),
        "risk_level": "CRITICAL",
        "fix_steps": [
            "Disable Telnet immediately — there is no secure way to use it.",
            "Replace it with SSH (port 22) for all remote management.",
            "If the device running Telnet cannot support SSH, it should be replaced or isolated from the network.",
            "Block port 23 at your firewall as an additional layer.",
        ],
        "verify": "Run a scan again — port 23 should be completely gone.",
        "verify_deep": [
            "Run 'telnet localhost' — should immediately refuse the connection.",
            "Check with 'sudo lsof -i :23' — nothing should appear.",
            "Run 'nmap -p 23 localhost' — should show closed or filtered.",
        ],
    },
    25: {
        "name": "SMTP (Simple Mail Transfer Protocol)",
        "what_it_is": (
            "SMTP is the protocol computers use to send email. "
            "Port 25 is the original server-to-server email delivery port."
        ),
        "why_its_risky": (
            "An open SMTP server that allows anyone to send email through it is called an 'open relay.' "
            "Spammers actively search for open relays to route millions of spam or phishing emails through your server, "
            "which can get your IP blacklisted and make you legally liable."
        ),
        "risk_level": "MEDIUM",
        "fix_steps": [
            "Ensure your mail server requires authentication before allowing email to be sent.",
            "Configure your mail server to only relay email for your own domain.",
            "Use a mail server test (e.g., MXToolbox) to verify you are not an open relay.",
            "If you don't run a mail server, block port 25 at your firewall.",
        ],
        "verify": "Go to mxtoolbox.com and run their open relay test on your IP — it should say not an open relay.",
        "verify_deep": [
            "Test with 'telnet yourip 25' from outside your network — should require authentication.",
            "Send a test email through your server and check mail logs for any relay attempts.",
            "Run 'nmap -p 25 yourip' from outside — if blocked, it shows filtered.",
        ],
    },
    53: {
        "name": "DNS (Domain Name System)",
        "what_it_is": (
            "DNS is the internet's phone book — it translates domain names like 'google.com' into IP addresses. "
            "Every device on a network typically needs access to a DNS server."
        ),
        "why_its_risky": (
            "An 'open resolver' — a DNS server that answers queries from any internet IP — "
            "can be abused in DNS amplification attacks. Attackers send small queries with a forged source IP "
            "(your victim's address), and your server sends large responses to the victim, overwhelming them. "
            "This is one of the most common DDoS attack techniques."
        ),
        "risk_level": "MEDIUM",
        "fix_steps": [
            "Configure your DNS server to only respond to queries from your own network (e.g., 192.168.0.0/16).",
            "Disable recursion for external clients.",
            "Use a firewall rule to block DNS queries from outside your network.",
            "Consider using a managed DNS service instead of running your own resolver.",
        ],
        "verify": "Run a scan again — if your DNS is locked down, outside devices can no longer use your server as a shortcut.",
        "verify_deep": [
            "From an external network run: 'dig @yourip google.com' — should return REFUSED for non-local queries.",
            "Check your DNS server config for 'allow-recursion' — should only list your internal subnets.",
            "Use dnscheck.tools to test your resolver from outside.",
        ],
    },
    80: {
        "name": "HTTP (Web Server)",
        "what_it_is": (
            "HTTP is the protocol that serves web pages. "
            "Port 80 is the standard unencrypted web port."
        ),
        "why_its_risky": (
            "HTTP traffic is unencrypted, meaning any data sent between a browser and this server — "
            "including login credentials, form submissions, and session cookies — can be intercepted. "
            "Modern browsers now warn users when visiting HTTP sites."
        ),
        "risk_level": "MEDIUM",
        "fix_steps": [
            "Set up HTTPS (port 443) with a valid TLS certificate. Free certificates are available via Let's Encrypt.",
            "Configure the server to automatically redirect all HTTP traffic to HTTPS.",
            "Add HTTP Strict Transport Security (HSTS) headers once HTTPS is working.",
            "If port 80 serves no purpose, disable it entirely.",
        ],
        "verify": "Type your website address starting with http:// — it should automatically switch to https://. That redirect means it worked.",
        "verify_deep": [
            "Run 'curl -I http://yourdomain.com' — look for '301 Moved Permanently' pointing to https.",
            "Check your server config for the redirect rule.",
            "Use ssllabs.com/ssltest to confirm HTTPS is properly configured.",
        ],
    },
    88: {
        "name": "Kerberos (Authentication Service)",
        "what_it_is": (
            "Kerberos is the authentication protocol used in Windows Active Directory environments. "
            "It issues 'tickets' that prove a user's identity across a network."
        ),
        "why_its_risky": (
            "Kerberos tickets can be stolen and reused (pass-the-ticket attacks), or the encryption can be "
            "attacked offline (Kerberoasting — where attackers request service tickets and crack them offline). "
            "An exposed Kerberos port is a sign of a domain controller, which is a high-value target."
        ),
        "risk_level": "MEDIUM",
        "fix_steps": [
            "Ensure your domain controllers are patched and up to date.",
            "Use strong, long passwords for service accounts to resist Kerberoasting.",
            "Restrict access to port 88 to only machines that need it (domain-joined computers).",
            "Enable audit logging for Kerberos authentication failures.",
        ],
        "verify": "Run the scan again from a non-domain device — port 88 should not be reachable.",
        "verify_deep": [
            "Use 'nmap -p 88 yourdc' from a non-domain machine — should show filtered.",
            "Check firewall rules to confirm port 88 is restricted to domain subnets only.",
            "Review Windows Event Viewer for Kerberos authentication logs — look for unexpected failures.",
        ],
    },
    110: {
        "name": "POP3 (Post Office Protocol)",
        "what_it_is": (
            "POP3 is a protocol for downloading email from a mail server to a local device. "
            "Port 110 is the unencrypted version."
        ),
        "why_its_risky": (
            "POP3 on port 110 sends your email credentials and message content in plaintext. "
            "Anyone sniffing the network can capture your email password and read your messages."
        ),
        "risk_level": "HIGH",
        "fix_steps": [
            "Switch to POP3S on port 995, which encrypts the connection with TLS.",
            "Better yet, use IMAP with TLS (port 993) — IMAP keeps emails on the server and syncs across devices.",
            "Update your email client to connect on the encrypted port.",
            "Disable port 110 on your mail server once all clients are migrated.",
        ],
        "verify": "Open your email app — if it connects and downloads email normally on the new port, the switch worked.",
        "verify_deep": [
            "Check your email client settings — incoming server should now be port 995 with SSL.",
            "Run 'openssl s_client -connect mailserver:995' — should show a valid certificate.",
            "Disable port 110 on the mail server and confirm no clients break.",
        ],
    },
    143: {
        "name": "IMAP (Internet Message Access Protocol)",
        "what_it_is": (
            "IMAP is the modern protocol for accessing email stored on a server. "
            "Port 143 is the unencrypted version."
        ),
        "why_its_risky": (
            "Like POP3, unencrypted IMAP exposes your email credentials and message content to anyone "
            "who can observe the network traffic between your device and the mail server."
        ),
        "risk_level": "HIGH",
        "fix_steps": [
            "Switch to IMAPS on port 993, which uses TLS encryption.",
            "Update your email client settings to use port 993 with SSL/TLS enabled.",
            "Disable port 143 on your mail server once all clients have been updated.",
            "Ensure your TLS certificate is valid and not self-signed for production use.",
        ],
        "verify": "Open your email app — if it syncs normally with no errors, the encrypted connection is working.",
        "verify_deep": [
            "Check email client settings — should show port 993 with SSL/TLS.",
            "Run 'openssl s_client -connect mailserver:993' to test the encrypted connection.",
            "Check mail server logs for any remaining port 143 connection attempts.",
        ],
    },
    443: {
        "name": "HTTPS (Secure Web Server)",
        "what_it_is": (
            "HTTPS is the encrypted version of HTTP. All modern websites should use this port. "
            "It encrypts all traffic between the browser and the server using TLS."
        ),
        "why_its_risky": (
            "HTTPS itself is secure, but the configuration matters. An expired or invalid certificate "
            "will cause browser warnings. Weak TLS configurations (old protocols like TLS 1.0, weak ciphers) "
            "can be exploited. The web application itself may also have vulnerabilities independent of the protocol."
        ),
        "risk_level": "LOW",
        "fix_steps": [
            "Verify your SSL/TLS certificate is valid and not expired.",
            "Use a tool like SSL Labs (ssllabs.com/ssltest) to check your TLS configuration.",
            "Disable TLS 1.0 and 1.1 — only allow TLS 1.2 and 1.3.",
            "Keep your web server software (nginx, Apache, etc.) up to date.",
        ],
        "verify": "Go to ssllabs.com/ssltest and enter your domain — aim for an A or A+ grade.",
        "verify_deep": [
            "Check certificate expiry: 'echo | openssl s_client -connect yourdomain:443 2>/dev/null | openssl x509 -noout -dates'",
            "Verify TLS version: only 1.2 and 1.3 should be enabled.",
            "Check HSTS header is present: 'curl -I https://yourdomain.com' and look for Strict-Transport-Security.",
        ],
    },
    445: {
        "name": "SMB (Server Message Block / Windows File Sharing)",
        "what_it_is": (
            "SMB is the protocol Windows uses for file sharing, printer sharing, and network communication "
            "between Windows machines. It's what lets you browse network drives."
        ),
        "why_its_risky": (
            "SMB has a devastating track record. The EternalBlue exploit (leaked NSA tool) used port 445 "
            "to spread WannaCry ransomware, infecting hundreds of thousands of machines worldwide in 2017. "
            "SMBv1 in particular is riddled with critical vulnerabilities. An exposed SMB port on the internet "
            "is actively targeted by ransomware groups every day."
        ),
        "risk_level": "CRITICAL",
        "fix_steps": [
            "Disable SMBv1 immediately — it has no place on a modern network.",
            "Block port 445 at your perimeter firewall — SMB should never be exposed to the internet.",
            "If SMB is needed internally, restrict it to trusted IP ranges only.",
            "Apply all Windows security patches, especially MS17-010 (EternalBlue patch).",
            "Consider using a VPN for remote file access instead of exposing SMB.",
        ],
        "verify": "Run the scan again — port 445 should not show up from outside your home network. If it's gone, you're protected.",
        "verify_deep": [
            "From outside your network run 'nmap -p 445 yourpublicip' — should show filtered.",
            "On Windows run: 'Get-SmbServerConfiguration | Select EnableSMB1Protocol' — should return False.",
            "Check Windows Event Viewer for SMB connection attempts after making changes.",
        ],
    },
    631: {
        "name": "IPP (Internet Printing Protocol)",
        "what_it_is": (
            "This is your printer sharing service. Your Mac opens this automatically "
            "when printer sharing or AirPrint is turned on."
        ),
        "why_its_risky": (
            "On your home network this is low risk. On a public or work network an exposed printer port "
            "can let strangers print to your printer or access your documents."
        ),
        "risk_level": "LOW",
        "fix_steps": [
            "Go to System Settings → General → Sharing and turn off Printer Sharing if you don't need it.",
            "If you use AirPrint, keep it on but make sure your WiFi network has a strong password.",
        ],
        "verify": "Run the scan again — port 631 should be gone if you turned off printer sharing.",
        "verify_deep": [
            "Run 'sudo lsof -i :631' — nothing should appear if the service is off.",
            "Go to System Settings → Sharing and confirm Printer Sharing is toggled off.",
        ],
    },
    3389: {
        "name": "RDP (Remote Desktop Protocol)",
        "what_it_is": (
            "RDP is Microsoft's protocol for remote desktop access — it lets you see and control "
            "a Windows desktop over the network, as if you were sitting in front of it."
        ),
        "why_its_risky": (
            "An internet-exposed RDP port is one of the top entry points for ransomware attacks. "
            "Attackers brute-force credentials, exploit unpatched vulnerabilities (BlueKeep, DejaBlue), "
            "or buy stolen RDP credentials on dark web markets. Once inside via RDP, attackers have "
            "full graphical access to the machine."
        ),
        "risk_level": "HIGH",
        "fix_steps": [
            "If RDP is not needed, disable it entirely (System Properties → Remote → uncheck Remote Desktop).",
            "If RDP is needed, place it behind a VPN — never expose it directly to the internet.",
            "Enable Network Level Authentication (NLA) for an extra authentication step.",
            "Use a strong, unique password for all accounts that have RDP access.",
            "Patch Windows regularly — several critical RDP vulnerabilities have been discovered in recent years.",
            "Consider using a jump host or bastion server as an intermediary.",
        ],
        "verify": "Try connecting via Remote Desktop from outside your VPN — it should fail to connect. Inside VPN it should still work fine.",
        "verify_deep": [
            "From outside VPN run 'nmap -p 3389 yourpublicip' — should show filtered.",
            "Check your firewall logs for any RDP connection attempts — you'll often see automated bots trying constantly.",
            "Enable RDP audit logging in Windows Event Viewer to monitor future attempts.",
        ],
    },
    8080: {
        "name": "HTTP-Alt (Alternative Web Port)",
        "what_it_is": (
            "Port 8080 is commonly used as an alternative HTTP port, often by development servers, "
            "proxy servers, or applications that can't run on the privileged port 80."
        ),
        "why_its_risky": (
            "Development or test servers on port 8080 often lack the hardening of production servers — "
            "they may run with debug mode enabled, default credentials, or expose administrative interfaces "
            "that should not be public. Like port 80, the traffic is also unencrypted."
        ),
        "risk_level": "MEDIUM",
        "fix_steps": [
            "Verify this port is intentionally open — check what application is listening on it.",
            "If it's a development server, ensure it's not accessible from outside your local network.",
            "If it's a production service, consider moving it to port 443 with HTTPS.",
            "Disable default credentials on any web admin interface accessible on this port.",
        ],
        "verify": "Try visiting http://yourip:8080 from your phone on mobile data — if it times out, the port is properly closed off.",
        "verify_deep": [
            "Run 'nmap -p 8080 yourpublicip' from outside — should show filtered or closed.",
            "Check what process owns the port: 'sudo lsof -i :8080'.",
            "If it's a dev server, confirm it's bound to 127.0.0.1 only, not 0.0.0.0.",
        ],
    },
}


def explain_port(port: int) -> dict:
    """
    Return a plain-English explanation for a given port number.
    Falls back to a generic explanation for unknown ports.
    """
    if port in PORT_EXPLANATIONS:
        return PORT_EXPLANATIONS[port]
    return {
        "name": f"Unknown Service (port {port})",
        "what_it_is": (
            f"Port {port} is not in the Recon AI knowledge base. "
            "An unknown service is running on this port."
        ),
        "why_its_risky": (
            "Unknown open ports should always be investigated. They may be legitimate applications, "
            "but they could also be malware, a misconfigured service, or a backdoor left by an attacker."
        ),
        "risk_level": "UNKNOWN",
        "fix_steps": [
            f"Identify what is running on port {port}: run 'lsof -i :{port}' (macOS/Linux) or "
            f"'netstat -ano | findstr :{port}' (Windows).",
            "If you don't recognize the process, research it before assuming it's safe.",
            "If the port is not needed, disable the application or block it at your firewall.",
        ],
        "verify": "Run the scan again after closing the app — the port should disappear.",
        "verify_deep": [
            f"Run 'sudo lsof -i :{port}' to confirm nothing is listening.",
            "If the port persists, check startup items for anything unfamiliar.",
        ],
    }


def explain_ports(port_list: list) -> list:
    """Return plain-English explanations for a list of port numbers."""
    return [{"port": p, **explain_port(p)} for p in port_list]


def format_explanation(port: int) -> str:
    """Return a formatted text explanation for a single port (CLI use)."""
    info = explain_port(port)
    lines = [
        f"Port {port} — {info['name']}",
        f"Risk Level : {info['risk_level']}",
        "",
        "What it is:",
        f"  {info['what_it_is']}",
        "",
        "Why it's risky:",
        f"  {info['why_its_risky']}",
        "",
        "How to fix it:",
    ]
    for i, step in enumerate(info["fix_steps"], 1):
        lines.append(f"  {i}. {step}")
    return "\n".join(lines)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
            print(format_explanation(port))
        except ValueError:
            print("Usage: python3 plain_english.py <port_number>")
    else:
        print("Recon AI Plain-English Port Knowledge Base")
        print(f"Covers {len(PORT_EXPLANATIONS)} ports: {sorted(PORT_EXPLANATIONS.keys())}")
        print("Usage: python3 plain_english.py <port_number>")
