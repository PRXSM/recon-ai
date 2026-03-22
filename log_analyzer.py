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
    "root_access": {
        "regex": r"sudo|root|superuser",
        "risk": "MEDIUM",
        "description": "Elevated privilege activity detected."
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
    }
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