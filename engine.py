import datetime
import logging
import platform
from port_scanner import scan_target
from network_mapper import scan_subnet
from log_analyzer import find_log_files, analyze_log, group_findings
from vulnerability_reporter import analyze_ports
from ai_assistant import analyze_with_ai

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

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

# build summary for AI — IP always redacted for privacy
def build_scan_summary(report_data):
    lines = []
    lines.append(f"Scan Mode: {report_data.get('mode', 'Unknown')}")
    lines.append(f"Operating System: {platform.system()} {platform.release()}")

    # privacy — IP never sent to AI
    if "target" in report_data:
        lines.append(f"Target: [REDACTED]")

    if "live_hosts" in report_data:
        lines.append(f"\nLive Hosts Found: {len(report_data['live_hosts'])}")
        for i, host in enumerate(report_data["live_hosts"], 1):
            lines.append(f"  - [HOST {i} REDACTED]")

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
        # grouped findings — send summary not raw list
        lines.append(f"\nLog Findings: {len(report_data['log_findings'])} unique threat types detected")
        for f in report_data["log_findings"]:
            lines.append(
                f"  [{f['risk']}] {f['description']} — detected {f['count']} times"
            )

    return "\n".join(lines)

# calculate network risk score
def calculate_risk_score(report_data):
    score = 100  # start at 100, deduct for findings

    severity_deductions = {
        "CRITICAL": 20,
        "HIGH": 10,
        "MEDIUM": 5,
        "LOW": 2,
        "UNKNOWN": 3
    }

    # deduct for open ports
    if "open_ports" in report_data:
        score -= len(report_data["open_ports"]) * 2

    # deduct for vulnerabilities
    if "vulnerabilities" in report_data:
        for v in report_data["vulnerabilities"]:
            score -= severity_deductions.get(v["severity"], 3)

    # deduct for log findings
    if "log_findings" in report_data:
        for f in report_data["log_findings"]:
            deduction = severity_deductions.get(f["risk"], 3)
            # cap each finding's impact
            score -= min(deduction, 10)

    # keep score between 0 and 100
    score = max(0, min(100, score))
    return score

def get_risk_label(score):
    if score >= 80:
        return "GOOD", "🟢"
    elif score >= 60:
        return "MODERATE", "🟡"
    elif score >= 40:
        return "AT RISK", "🟠"
    else:
        return "CRITICAL", "🔴"

# save unified report
def save_unified_report(report_data, ai_analysis, timestamp, score):
    mode = report_data.get("mode", "scan").replace(" ", "_")
    filename = f"recon_ai_{mode}_{timestamp}.txt"
    label, emoji = get_risk_label(score)
    with open(filename, "w") as f:
        f.write("="*50 + "\n")
        f.write("       RECON AI — UNIFIED REPORT\n")
        f.write("="*50 + "\n")
        f.write(f"Mode: {report_data.get('mode')}\n")
        f.write(f"Time: {timestamp}\n")
        f.write(f"Network Health Score: {score}/100 {emoji} {label}\n")
        f.write("="*50 + "\n\n")
        f.write("SCAN SUMMARY:\n")
        f.write(build_scan_summary(report_data) + "\n\n")
        f.write("="*50 + "\n")
        f.write("RECON AI ANALYSIS:\n")
        f.write("="*50 + "\n")
        f.write(ai_analysis + "\n")
    return filename

# the brain
def run_engine():
    show_menu()
    choice = input("\nSelect scan mode (1-4): ").strip()

    if choice not in SCAN_MODES:
        print("Invalid choice. Exiting.")
        return None, None

    timestamp = datetime.datetime.now().isoformat()

    if choice == "1":
        target = input("Enter target IP: ").strip()
        open_ports = scan_target(target)
        report_data = {"mode": "Quick Scan", "target": target, "open_ports": open_ports}

    elif choice == "2":
        target = input("Enter subnet: ").strip()
        live_hosts = scan_subnet(target)
        report_data = {"mode": "Network Scan", "target": target, "live_hosts": live_hosts}

    elif choice == "3":
        target = input("Enter target IP: ").strip()
        open_ports = scan_target(target)
        report_data = {"mode": "Full Recon", "target": target, "open_ports": open_ports}

    elif choice == "4":
        log_files = find_log_files()
        raw = []
        for lf in log_files:
            raw.extend(analyze_log(lf))
        report_data = {"mode": "Log Analysis", "log_findings": group_findings(raw)}

    return report_data, timestamp

if __name__ == "__main__":
    report_data, timestamp = run_engine()
    if report_data:
        score = calculate_risk_score(report_data)
        label, emoji = get_risk_label(score)
        print(f"\nNetwork Health Score: {score}/100 {emoji} {label}")
        print("\nSending results to Recon AI for analysis...")
        summary = build_scan_summary(report_data)
        ai_analysis = analyze_with_ai(summary)
        print("\n" + "="*50)
        print("RECON AI SAYS:")
        print("="*50)
        print(ai_analysis)
        filename = save_unified_report(
            report_data, ai_analysis, timestamp, score)
        print(f"\nFull report saved to: {filename}")