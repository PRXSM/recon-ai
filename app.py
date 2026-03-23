from flask import Flask, render_template, request
from engine import build_scan_summary, calculate_risk_score, get_risk_label
from ai_assistant import analyze_with_ai
from port_scanner import scan_target
from network_mapper import scan_subnet
from log_analyzer import find_log_files, analyze_log, group_findings
from vulnerability_reporter import analyze_ports
from dotenv import load_dotenv
import datetime
import logging
import re
import os

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# input validation
def is_valid_ip(ip):
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)

# scan modes — each in its own function
def quick_scan(target):
    logger.info(f"Quick scan on {target}")
    try:
        open_ports = scan_target(target)
    except Exception as e:
        logger.error(f"Port scan failed: {e}")
        open_ports = []
    return {
        "mode": "Quick Scan",
        "target": target,
        "open_ports": open_ports
    }

def network_scan(target):
    logger.info(f"Network scan on {target}")
    try:
        live_hosts = scan_subnet(target)
    except Exception as e:
        logger.error(f"Network scan failed: {e}")
        live_hosts = []
    all_ports = []
    for host in live_hosts:
        try:
            ports = scan_target(host)
            all_ports.extend(ports)
        except Exception as e:
            logger.error(f"Port scan failed on {host}: {e}")
    return {
        "mode": "Network Scan",
        "target": target,
        "live_hosts": live_hosts,
        "open_ports": all_ports
    }

def full_recon(target):
    logger.info(f"Full recon on {target}")
    try:
        open_ports = scan_target(target)
    except Exception as e:
        logger.error(f"Port scan failed: {e}")
        open_ports = []
    port_numbers = []
    for p in open_ports:
        try:
            port_num = int(p.split()[1].replace(":", ""))
            port_numbers.append(port_num)
        except:
            pass
    try:
        vuln_findings = analyze_ports(port_numbers, target)
    except Exception as e:
        logger.error(f"Vulnerability analysis failed: {e}")
        vuln_findings = []
    try:
        log_files = find_log_files()
        raw_findings = []
        for lf in log_files:
            raw_findings.extend(analyze_log(lf))
        log_findings = group_findings(raw_findings)
    except Exception as e:
        logger.error(f"Log analysis failed: {e}")
        log_findings = []
    return {
        "mode": "Full Recon",
        "target": target,
        "open_ports": open_ports,
        "vulnerabilities": vuln_findings,
        "log_findings": log_findings
    }

def log_analysis():
    logger.info("Log analysis started")
    try:
        log_files = find_log_files()
        raw_findings = []
        for lf in log_files:
            raw_findings.extend(analyze_log(lf))
        log_findings = group_findings(raw_findings)
    except Exception as e:
        logger.error(f"Log analysis failed: {e}")
        log_findings = []
    return {
        "mode": "Log Analysis",
        "log_findings": log_findings
    }

# run scan — routes to the right function
def run_scan(target, mode):
    if mode == "Quick Scan":
        return quick_scan(target)
    elif mode == "Network Scan":
        return network_scan(target)
    elif mode == "Full Recon":
        return full_recon(target)
    elif mode == "Log Analysis":
        return log_analysis()
    else:
        return {"mode": "Unknown", "error": "Invalid scan mode selected"}

# routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    target = request.form.get("target", "").strip()
    mode = request.form.get("mode", "").strip()
    use_ai = request.form.get("use_ai") == "true"
    timestamp = datetime.datetime.now().isoformat()

    # validate IP unless log analysis
    if mode != "Log Analysis":
        if not is_valid_ip(target):
            return render_template("index.html",
                error="Invalid IP address. Please enter a valid IPv4 address.")

    # run the scan
    report_data = run_scan(target, mode)
    
    # calculate risk score
    score = calculate_risk_score(report_data)
    label, emoji = get_risk_label(score)
    report_data["score"] = score
    report_data["score_label"] = label
    report_data["score_emoji"] = emoji

    # only send to AI if user opted in
    ai_analysis = None
    if use_ai:
        try:
            summary = build_scan_summary(report_data)
            ai_analysis = analyze_with_ai(summary)
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            ai_analysis = "AI analysis unavailable. Your scan results are shown below."

    return render_template("results.html",
        report_data=report_data,
        ai_analysis=ai_analysis,
        timestamp=timestamp)

# run
if __name__ == "__main__":
    app.run(debug=True)