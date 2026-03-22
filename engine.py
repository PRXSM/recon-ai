# engine.py
# Recon AI — Unified Engine
# Connects all 5 tools into one command

import datetime
import logging

# Import core functions from all 5 tools
from port_scanner import scan_target
from network_mapper import scan_subnet
from log_analyzer import find_log_files, analyze_log
from vulnerability_reporter import analyze_ports
from ai_assistant import analyze_with_ai

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# scan modes
SCAN_MODES = {
    "1": "Quick Scan      — Port scan + AI analysis",
    "2": "Network Scan    — Map network + Port scan + AI analysis",
    "3": "Full Recon      — Everything, full report",
    "4": "Log Analysis    — Analyze local logs + AI analysis",
}

# menu
def show_menu():
    print("\n" + "="*50)
    print("        RECON AI — UNIFIED ENGINE")
    print("="*50)
    for key, value in SCAN_MODES.items():
        print(f"  [{key}] {value}")
    print("="*50)

# the brain
def run_engine():
    show_menu()
    choice = input("\nSelect scan mode (1-4): ").strip()

    if choice not in SCAN_MODES:
        print("Invalid choice. Exiting.")
        return None, None

    timestamp = datetime.datetime.now().isoformat()
    report_data = {}

    # MODE 1 — Quick Scan
    if choice == "1":
        target = input("Enter target IP: ").strip()
        print(f"\nScanning ports on {target}...")
        open_ports = scan_target(target)
        report_data["target"] = target
        report_data["open_ports"] = open_ports
        report_data["mode"] = "Quick Scan"

    # MODE 2 — Network Scan
    elif choice == "2":
        subnet = input("Enter subnet (e.g. 192.168.1.0/24): ").strip()
        print(f"\nMapping network {subnet}...")
        live_hosts = scan_subnet(subnet)
        all_ports = []
        for host in live_hosts:
            print(f"Scanning ports on {host}...")
            ports = scan_target(host)
            all_ports.extend(ports)
        report_data["subnet"] = subnet
        report_data["live_hosts"] = live_hosts
        report_data["open_ports"] = all_ports
        report_data["mode"] = "Network Scan"

    # MODE 3 — Full Recon
    elif choice == "3":
        target = input("Enter target IP: ").strip()
        subnet = input("Enter subnet (e.g. 192.168.1.0/24): ").strip()
        print(f"\nRunning full recon on {target}...")
        open_ports = scan_target(target)
        live_hosts = scan_subnet(subnet)
        port_numbers = []
        for p in open_ports:
            try:
                port_num = int(p.split()[1].replace(":", ""))
                port_numbers.append(port_num)
            except:
                pass
        vuln_findings = analyze_ports(port_numbers, target)
        log_files = find_log_files()
        log_findings = []
        for lf in log_files:
            log_findings.extend(analyze_log(lf))
        report_data["target"] = target
        report_data["open_ports"] = open_ports
        report_data["live_hosts"] = live_hosts
        report_data["vulnerabilities"] = vuln_findings
        report_data["log_findings"] = log_findings
        report_data["mode"] = "Full Recon"

    # MODE 4 — Log Analysis
    elif choice == "4":
        print("\nSearching for log files on this machine...")
        log_files = find_log_files()
        log_findings = []
        for lf in log_files:
            log_findings.extend(analyze_log(lf))
        report_data["log_findings"] = log_findings
        report_data["mode"] = "Log Analysis"

    return report_data, timestamp

# build summary of the ai
def build_scan_summary(report_data):
    lines = []
    mode = report_data.get("mode", "Unknown")
    lines.append(f"Scan Mode: {mode}")

    if "target" in report_data:
        lines.append(f"Target: [REDACTED]")

    if "live_hosts" in report_data:
        lines.append(f"\nLive Hosts Found: {len(report_data['live_hosts'])}")
        for host in report_data["live_hosts"]:
            lines.append(f"  - {host}")

    if "open_ports" in report_data:
        lines.append(f"\nOpen Ports:")
        for port in report_data["open_ports"]:
            lines.append(f"  {port}")

    if "vulnerabilities" in report_data:
        lines.append(f"\nVulnerabilities:")
        for v in report_data["vulnerabilities"]:
            lines.append(
                f"  [{v['severity']}] Port {v['port']} - {v['service']}: {v['description']}"
            )

    if "log_findings" in report_data:
        lines.append(f"\nLog Findings: {len(report_data['log_findings'])} suspicious entries")
        for f in report_data["log_findings"][:5]:
            lines.append(f"  [{f['risk']}] {f['description']}")

    return "\n".join(lines)

# save unified report
def save_unified_report(report_data, ai_analysis, timestamp):
    mode = report_data.get("mode", "scan").replace(" ", "_")
    filename = f"recon_ai_{mode}_{timestamp}.txt"
    with open(filename, "w") as f:
        f.write("="*50 + "\n")
        f.write("       RECON AI — UNIFIED REPORT\n")
        f.write("="*50 + "\n")
        f.write(f"Mode: {report_data.get('mode')}\n")
        f.write(f"Time: {timestamp}\n")
        f.write("="*50 + "\n\n")
        f.write("SCAN SUMMARY:\n")
        f.write(build_scan_summary(report_data) + "\n\n")
        f.write("="*50 + "\n")
        f.write("RECON AI ANALYSIS:\n")
        f.write("="*50 + "\n")
        f.write(ai_analysis + "\n")
    return filename

if __name__ == "__main__":
    report_data, timestamp = run_engine()
    if report_data:
        print("\nSending results to Recon AI for analysis...")
        summary = build_scan_summary(report_data)
        ai_analysis = analyze_with_ai(summary)
        print("\n" + "="*50)
        print("RECON AI SAYS:")
        print("="*50)
        print(ai_analysis)
        filename = save_unified_report(report_data, ai_analysis, timestamp)
        print(f"\nFull report saved to: {filename}")