from flask import Flask, render_template, request
from engine import run_engine, build_scan_summary, save_unified_report
from ai_assistant import analyze_with_ai
from dotenv import load_dotenv
import datetime
import os

load_dotenv()

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target")
    mode = request.form.get("mode")
    use_ai = request.form.get("use_ai") == "true"
    timestamp = datetime.datetime.now().isoformat()

    # actually run the scan
    report_data = run_scan(target, mode)

    # only send to AI if user opted in
    ai_analysis = None
    if use_ai:
        summary = build_scan_summary(report_data)
        ai_analysis = analyze_with_ai(summary)

    return render_template("results.html",
        report_data=report_data,
        ai_analysis=ai_analysis,
        timestamp=timestamp)

def run_scan(target, mode):
    from port_scanner import scan_target
    from network_mapper import scan_subnet
    from log_analyzer import find_log_files, analyze_log
    from vulnerability_reporter import analyze_ports

    report_data = {"mode": mode, "target": target}

    if mode == "Quick Scan":
        print(f"\nScanning ports on {target}...")
        open_ports = scan_target(target)
        report_data["open_ports"] = open_ports

    elif mode == "Network Scan":
        live_hosts = scan_subnet(target)
        all_ports = []
        for host in live_hosts:
            ports = scan_target(host)
            all_ports.extend(ports)
        report_data["live_hosts"] = live_hosts
        report_data["open_ports"] = all_ports

    elif mode == "Full Recon":
        open_ports = scan_target(target)
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
        report_data["open_ports"] = open_ports
        report_data["vulnerabilities"] = vuln_findings
        report_data["log_findings"] = log_findings[:50]

    elif mode == "Log Analysis":
        log_files = find_log_files()
        log_findings = []
        for lf in log_files:
            log_findings.extend(analyze_log(lf))
        report_data["log_findings"] = log_findings[:50]

    return report_data

if __name__ == "__main__":
    app.run(debug=True)