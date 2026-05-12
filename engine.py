import datetime
import logging
import platform
from port_scanner import scan_target
from network_mapper import scan_subnet
from log_analyzer import find_log_files, analyze_log, group_findings
from vulnerability_reporter import analyze_ports
from ai_assistant import analyze_with_ai
from nist_owasp import map_findings, generate_compliance_summary
from prompt_injection import sanitize, sanitize_list

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def parse_port_number(port_string):
    """Extract the integer port number from a scan result string like 'Port 80: OPEN (HTTP)'."""
    return int(port_string.split()[1].replace(":", ""))

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
    injection_findings = []
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
        raw_ports = report_data.get("open_ports", [])
        clean_ports, port_findings = sanitize_list(
            raw_ports, field_name="open_port", source="port_scanner"
        )
        injection_findings.extend(port_findings)
        lines.append(f"\nOpen Ports:")
        for port in clean_ports:
            lines.append(f"  {port}")

    if "vulnerabilities" in report_data:
        lines.append(f"\nVulnerabilities:")
        for v in report_data["vulnerabilities"]:
            clean_service, sf = sanitize(
                v.get("service", ""),
                field_name="service",
                source="vuln_reporter"
            )
            clean_desc, df = sanitize(
                v.get("description", ""),
                field_name="description",
                source="vuln_reporter"
            )
            if sf: injection_findings.append(sf)
            if df: injection_findings.append(df)
            lines.append(
                f"  [{v['severity']}] Port {v['port']} - "
                f"{clean_service}: {clean_desc}"
            )

    if "log_findings" in report_data:
        lines.append(
            f"\nLog Findings: {len(report_data['log_findings'])} "
            f"unique threat types detected"
        )
        for f in report_data["log_findings"]:
            clean_desc, df = sanitize(
                f.get("description", ""),
                field_name="log_description",
                source="log_analyzer"
            )
            if df: injection_findings.append(df)
            lines.append(
                f"  [{f['risk']}] {clean_desc} — "
                f"detected {f['count']} times"
            )

    if "credential_assessment" in report_data and report_data["credential_assessment"]:
        ca = report_data["credential_assessment"]
        lines.append(f"\nCredential Assessment: {ca.get('summary', '')}")
        for f in ca.get("findings", []):
            clean_service, sf = sanitize(
                f.get("service", ""),
                field_name="service",
                source="credential_scanner"
            )
            clean_desc, df = sanitize(
                f.get("description", ""),
                field_name="description",
                source="credential_scanner"
            )
            if sf: injection_findings.append(sf)
            if df: injection_findings.append(df)
            lines.append(
                f"  [{f['risk']}] {clean_service} — {clean_desc}"
            )

    if "system_inspection" in report_data and report_data["system_inspection"]:
        si = report_data["system_inspection"]
        lines.append(f"\nSystem Inspection: {si.get('summary', '')}")
        flagged_processes = si.get("processes", {}).get("flagged", [])
        for p in flagged_processes:
            clean_name, nf = sanitize(
                p.get("name", ""),
                field_name="process_name",
                source="system_inspector"
            )
            clean_desc, df = sanitize(
                p.get("description", ""),
                field_name="process_description",
                source="system_inspector"
            )
            if nf: injection_findings.append(nf)
            if df: injection_findings.append(df)
            lines.append(
                f"  [HIGH] Suspicious process: "
                f"{clean_name} — {clean_desc}"
            )
        flagged_startup = si.get("startup", {}).get("flagged", [])
        for s in flagged_startup:
            clean_name, nf = sanitize(
                s.get("name", ""),
                field_name="startup_item",
                source="system_inspector"
            )
            if nf: injection_findings.append(nf)
            lines.append(
                f"  [MEDIUM] Suspicious startup item: {clean_name}"
            )

    if "zero_trust" in report_data and report_data["zero_trust"]:
        zt = report_data["zero_trust"]
        lines.append(
            f"\nZero Trust Verification: {zt.get('summary', '')}"
        )
        for f in zt.get("findings", []):
            clean_title, tf = sanitize(
                f.get("title", ""),
                field_name="zt_title",
                source="zero_trust"
            )
            clean_desc, df = sanitize(
                f.get("description", "")[:120],
                field_name="zt_description",
                source="zero_trust"
            )
            if tf: injection_findings.append(tf)
            if df: injection_findings.append(df)
            lines.append(
                f"  [{f['risk']}] {clean_title} — {clean_desc}"
            )

    if injection_findings:
        lines.append(
            f"\n⚠️  SECURITY ALERT: {len(injection_findings)} prompt "
            f"injection attempt(s) detected in scan data. Someone on "
            f"your network may be attempting to manipulate Recon AI's "
            f"AI analysis. These findings have been sanitized and "
            f"blocked from reaching the AI."
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

    # deduct for shadow AI findings
    if "shadow_ai_findings" in report_data:
        shadow_deduction = 0
        for f in report_data["shadow_ai_findings"]:
            risk = f.get("risk", "")
            if risk == "HIGH":
                shadow_deduction += 10
            elif risk == "MEDIUM":
                shadow_deduction += 5
        score -= min(shadow_deduction, 20)

    # Zero Trust deductions
    zero_trust = report_data.get("zero_trust")
    if zero_trust and not zero_trust.get("clean"):
        zt_critical = zero_trust.get("critical_count", 0)
        zt_high     = zero_trust.get("high_count", 0)
        zt_new      = zero_trust.get("new_device_count", 0)
        score -= zt_critical * 8
        score -= zt_high     * 4
        score -= zt_new      * 5

    # deduct for disabled firewall
    firewall_status = report_data.get("firewall_status")
    if firewall_status and firewall_status.get("risk") == "HIGH":
        score -= 10

    # deduct for NIST Respond/Detect findings
    if "compliance" in report_data:
        nist_counts = report_data["compliance"].get("nist_counts", {})
        nist_deduction = nist_counts.get("Respond", 0) * 10
        nist_deduction += nist_counts.get("Detect", 0) * 5
        score -= min(nist_deduction, 15)

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

    all_findings = report_data.get("vulnerabilities", []) + report_data.get("log_findings", [])
    if all_findings:
        mapped = map_findings(all_findings)
        report_data["mapped_findings"] = mapped
        report_data["compliance"] = generate_compliance_summary(mapped)

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