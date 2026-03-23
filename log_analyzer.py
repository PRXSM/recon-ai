import os
import re
import logging
import datetime
import platform
from pathlib import Path

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Suspicious patterns to look for in logs
PATTERNS = {
    "failed_login": {
        "regex": r"Failed password|authentication failure|Login incorrect",
        "risk": "HIGH",
        "description": "Failed login attempt detected."
    },
    "brute_force":{
        "regex": r"Failed password|authentication failure",
        "risk": "CRITICAL",
        "description": "Possible brute force attack - multiple failed logins"
    },
    "root_access": {
        "regex": r"sudo|root|superuser",
        "risk": "MEDIUM",
        "description": "Elevated privilege activity detected."
    },
    "new_user_created": {
        "regex": r"useradd|adduser|new user|user added",
        "risk": "HIGH",
        "description": "New user account created - verify this was authroized."
    },
    "user_deleted": {
        "regex": r"userdel|user deleted|removed user",
        "risk": "HIGH",
        "description": "User account deleted - verify this was authorized."
    },
    "password_changed": {
        "regex": r"password changed|passwd|chpasswd",
        "risk": "MEDIUM",
        "description": "Password change detected - verify this was authorized."
    },
    "ssh_key_added": {
        "regex": r"authorized_keys|ssh key|RSA key",
        "risk": "HIGH",
        "description": "SSH key added - new remote access method created."
    },
    "firewall_changed": {
        "regex": r"iptables|firewall|ufw|pf enable|pfctl",
        "risk": "HIGH",
        "description": "Firewall rule change detected - verify this was intentional."
    },
    "cron_job_added": {
        "regex": r"crontab|cron\.d|scheduled task|at command",
        "risk": "HIGH",
        "description": "Scheduled task added - could indicate persistence attempt."
    },
    "large_file_transfer": {
        "regex": r"scp|rsync|ftp|sftp|transferred. *Mb|sent.*MB",
        "risk": "MEDIUM",
        "description": "large file transfer detected - possible data exfiltration."
    },
    "service_changed": {
        "regex": r"service started|service stopped|systemctl|daemon",
        "risk": "MEDIUM",
        "description": "System service started or stopped - verify this was intentional."
    },
    "repeated_connection": {
        "regex": r"Connection refused|connection attempt",
        "risk": "LOW",
        "description": "Repeated connection attempt detected."
    },
    "port_scan": {
        "regex": r"port scan|nmap|scanning",
        "risk": "HIGH",
        "description": "Possible port scan detected."
    },
    "unusual_login_time": {
        "regex": r"session opened|Accepted password|Accepted publickey",
        "risk": "MEDIUM",
        "description": "Login session detected - review if outside business hours."
    },
    "malware_indicator": {
        "regex": r"malware|trojan|virus|ransomware|exploit|payload",
        "risk": "CRITICAL",
        "description": "Malware indicator found in logs - immediate investigation required."
    },
    "suspicious_process": {
        "regex": r"nc -e|netcat|/bin/sh|/bin/bash -i|cmd.exe|powershell -enc",
        "risk": "CRITICAL",
        "description": "Suspicious process execution - possible reverse shell attempt."
    },
    "privilege_escalation": {
        "regex": r"NOPASSWD|sudoers|chmod 777|setuid|setgid",
        "risk": "CRITICAL",
        "description": "Privilege escalation attempt detected."
    },
    "data_exfiltration": {
        "regex": r"Curl|wget|base64|/dev/tcp|/dev/udp|data exfiltration",
        "risk": "CRITICAL",
        "description": "Possible data exfiltration tool used."
    },
    "log_tampering": {
        "regex": r"rm.*log|truncate|shred|wipe|clear.*log",
        "risk": "CRITICAL",
        "description": "Possible log tampering activity detected - attacker may be covering their tracks."
    },
    "crypto_mining": {
        "regex": r"minerd|mining|xmrig|cryptonight|monero|mining pool",
        "risk": "HIGH",
        "description": "Crypto mining software detected - unauthorized resource usage."
    },
    "ransomware_indicator": {
        "regex": r"encrypted|\.locked|\.encrypted|ransom|decrypt",
        "risk": "CRITICAL",
        "description": "Ransomware indicator detected - immediate investigation required."
    },
    "network_reconnaissance": {
        "regex": r"arp -a |netstat|ifconfig|ipconfig|traceroute|tracert",
        "risk": "MEDIUM",
        "description": "Network reconnaissance commands detected."
    },
    "suspicious_download":{
        "regex": r"wget|curl|powershell.*-enc|Invoke-WebRequest|*http|pip install|apt-get|yum install",
        "risk": "MEDIUM",
        "description": "Software download detected - verify this was authorized."
    },
    "failed_sudo": {
        "regex": r"sudo:.*authentication failure",
        "risk": "HIGH",
        "description": "Failed sudo attempt detected - possible privilege escalation attempt."
    },
    "failed_ssh": {
        "regex": r"sshd.*Failed password",
        "risk": "HIGH",
        "description": "Failed SSH login attempt detected."
    },
    "failed_rdp": {
        "regex": r"rdp.*failed login|mstsc.*authentication failure",
        "risk": "HIGH",
        "description": "Failed RDP login attempt detected."
    },
    "failed_vpn": {
        "regex": r"vpn.*failed login|openvpn.*authentication failure",
        "risk": "HIGH",
        "description": "Failed VPN login attempt detected."
    },
    "failed_database_login": {
        "regex": r"mysql|postgresql|mongodb.*failed login",
        "risk": "HIGH",
        "description": "Failed database login attempt detected."
    },
    "failed_web_login": {
        "regex": r"apache|nginx|iis.*failed login",
        "risk": "HIGH",
        "description": "Failed web application login attempt detected."
    },
    "failed_email_login": {
        "regex": r"postfix|dovecot|exim.*failed login",
        "risk": "HIGH",
        "description": "Failed email login attempt detected."
    },
    "failed_smb_login": {
        "regex": r"smb.*failed login|samba.*authentication failure",
        "risk": "HIGH",
        "description": "Failed SMB login attempt detected."
    },
    "failed_kerberos": {
        "regex": r"kerberos.*failed|krb5.*authentication failure",
        "risk": "HIGH",
        "description": "Failed Kerberos authentication attempt detected."
    },
}
def find_log_files():
    logger.info("Searching for log files...")
    system = platform.system().lower()
    if system == "windows":
        log_locations = [
            Path("C:/Windows/System32/winevt/Logs"),
            Path(os.environ.get("APPDATA", "") + "/Local/Temp")
        ]
    elif system == "darwin":
        log_locations = [
            Path("/var/log"),
            Path.home() / "Library" / "Logs"
        ]
    else:
        log_locations = [
            Path("/var/log"),
            Path("/var/log/syslog").parent
        ]
    log_files = []
    for location in log_locations:
        if location.exists():
            for file in location.rglob("*.log"):
                log_files.append(file)
    logger.info(f"Found {len(log_files)} log files")
    return log_files

def analyze_log(filepath):
    logger.info(f"Analyzing {filepath}")
    findings = []
    try:
        with open(filepath, "r", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for pattern_name, pattern_data in PATTERNS.items():
                    if re.search(pattern_data["regex"], line, re.IGNORECASE):
                        findings.append({
                            "file": str(filepath),
                            "line_number": line_num,
                            "line": line.strip(),
                            "pattern": pattern_name,
                            "risk": pattern_data["risk"],
                            "description": pattern_data["description"]
                        })
    except PermissionError:
        logger.warning(f"Permission denied: {filepath}")
    return findings
def group_findings(findings):
    grouped = {}
    for finding in findings:
        key = finding["pattern"]
        if key not in grouped:
            grouped[key] = {
                "pattern": finding["pattern"],
                "risk": finding["risk"],
                "description": finding["description"],
                "count": 0,
                "files": set(),
                "first_occurrence": finding["line_number"],
                "last_occurrence": finding["line_number"]
            }
        grouped[key]["count"] += 1
        grouped[key]["files"].add(finding["file"])
        grouped[key]["last_occurrence"] = finding["line_number"]

    for key in grouped:
        grouped[key]["files"] = list(grouped[key]["files"])
    return list(grouped.values())

def save_report(findings, timestamp, filename):
    logger.info(f"Saving report to {filename}")
    with open(filename, "w") as f:
        f.write(f"Log Analysis Report\n")
        f.write(f"Time: {timestamp}\n")
        f.write("="*40 + "\n\n")
        if not findings:
            f.write("No Suspicious activity found.\n")
        else:
            for finding in findings:
                f.write(f"[{finding['risk']}] {finding['description']}\n")
                f.write(f"File: {finding['file']}\n")
                f.write(f"Line {finding['line_number']}: {finding['line']}\n")
                f.write("-"*40 + "\n")
            f.write(f"\nTotal findings: {len(findings)}\n")

def main():
    timestamp = datetime.datetime.now().isoformat()
    filename = f"log_analysis_{timestamp}.txt"
    logger.info("Starting log analysis...")
    log_files = find_log_files()
    all_findings = []
    for log_file in log_files:
        findings = analyze_log(log_file)
        all_findings.extend(findings)
    save_report(all_findings, timestamp, filename)
    print(f"\nAnalysis complete.")
    print(f"Total suspicious findings: {len(all_findings)}")
    print(f"Report saved to: {filename}")
if __name__ == "__main__":
	main()