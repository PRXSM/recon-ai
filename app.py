from flask import Flask, render_template, request, send_file
import io
from engine import build_scan_summary, calculate_risk_score, get_risk_label, parse_port_number
from ai_assistant import analyze_with_ai
import markdown as md
from port_scanner import scan_target
from network_mapper import scan_subnet
from log_analyzer import find_log_files, analyze_log, group_findings
from vulnerability_reporter import analyze_ports
from plain_english import explain_port
from network_intel import (
    get_network_interfaces, explain_interface, group_interfaces,
    get_arp_table, explain_arp_entry,
    get_active_connections, group_connections, explain_connection,
    run_traceroute, explain_hop,
)
from scan_memory import (
    save_scan, get_last_scan,
    get_new_devices, init_db
)
from dotenv import load_dotenv
import datetime
import logging
import re
import os

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
init_db()

# input validation
def is_valid_ip(ip):
    # Strip optional CIDR suffix before validating the IP part
    host = ip.split("/")[0]
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if not re.match(pattern, host):
        return False
    if not all(0 <= int(p) <= 255 for p in host.split(".")):
        return False
    # If CIDR present, validate prefix length (0–32)
    if "/" in ip:
        try:
            prefix = int(ip.split("/")[1])
            return 0 <= prefix <= 32
        except ValueError:
            return False
    return True

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
            port_num = parse_port_number(p)
            port_numbers.append(port_num)
        except Exception as e:
            logger.warning(f"Could not parse port string '{p}': {e}")
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

def build_text_report(report_data, ai_analysis, timestamp):
    lines = []
    lines.append("=" * 50)
    lines.append("       RECON AI — NETWORK REPORT")
    lines.append("=" * 50)
    lines.append(f"Mode: {report_data.get('mode', 'Unknown')}")
    lines.append(f"Time: {timestamp}")
    if report_data.get("score") is not None:
        lines.append(f"Network Health Score: {report_data['score']}/100 — {report_data.get('score_label', '')}")
    lines.append("=" * 50)

    if report_data.get("open_ports"):
        lines.append("\nOPEN PORTS:")
        for port in report_data["open_ports"]:
            lines.append(f"  {port}")

    if report_data.get("live_hosts"):
        lines.append("\nDEVICES FOUND ON YOUR NETWORK:")
        for host in report_data["live_hosts"]:
            lines.append(f"  {host}")

    if report_data.get("vulnerabilities"):
        lines.append("\nVULNERABILITIES:")
        for v in report_data["vulnerabilities"]:
            lines.append(f"  [{v['severity']}] Port {v['port']} — {v['service']}")
            lines.append(f"    {v['description']}")
            lines.append(f"    Recommendation: {v['recommendation']}")

    if report_data.get("log_findings"):
        lines.append("\nLOG FINDINGS:")
        for f in report_data["log_findings"]:
            lines.append(f"  [{f['risk']}] {f['description']} — {f['count']}x detected")

    if ai_analysis:
        lines.append("\n" + "=" * 50)
        lines.append("RECON AI ANALYSIS:")
        lines.append("=" * 50)
        clean = re.sub(r'<[^>]+>', '', ai_analysis)
        lines.append(clean)

    return "\n".join(lines)

# routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    ip = request.form.get("target", "").strip()
    tools = request.form.getlist("tools")   # list of checked tool values
    intensity = request.form.get("intensity", "normal").strip()
    timestamp = datetime.datetime.now().isoformat()

    use_ai = "ai_analysis" in tools
    ai_mode = request.form.get("ai_mode", "offline")
    needs_target = any(t in tools for t in ("port_scanner", "network_mapper", "vuln_reporter"))

    # validate IP when a network tool is selected
    if needs_target and not is_valid_ip(ip):
        return render_template("index.html",
            error="Invalid IP address. Please enter a valid IPv4 address.")

    if not tools:
        return render_template("index.html",
            error="Please select at least one tool to run.")

    report_data = {
        "mode": "Custom Scan",
        "target": ip,
        "tools_run": tools,
        "intensity": intensity,
    }

    # Port Scanner
    if "port_scanner" in tools:
        try:
            open_ports = scan_target(ip)
        except Exception as e:
            logger.error(f"Port scan failed: {e}")
            open_ports = []
        report_data["open_ports"] = open_ports

    # Network Mapper
    if "network_mapper" in tools:
        try:
            live_hosts = scan_subnet(ip)
        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            live_hosts = []
        report_data["live_hosts"] = live_hosts
        # also port-scan discovered hosts
        if live_hosts and "port_scanner" not in tools:
            all_ports = []
            for host in live_hosts:
                try:
                    all_ports.extend(scan_target(host))
                except Exception as e:
                    logger.error(f"Port scan failed on {host}: {e}")
            report_data.setdefault("open_ports", []).extend(all_ports)

    # Log Analyzer
    if "log_analyzer" in tools:
        try:
            log_files = find_log_files()
            raw_findings = []
            for lf in log_files:
                raw_findings.extend(analyze_log(lf))
            report_data["log_findings"] = group_findings(raw_findings)
        except Exception as e:
            logger.error(f"Log analysis failed: {e}")
            report_data["log_findings"] = []

    # Vulnerability Reporter (needs open ports)
    if "vuln_reporter" in tools:
        open_ports = report_data.get("open_ports", [])
        port_numbers = []
        for p in open_ports:
            try:
                port_numbers.append(parse_port_number(p))
            except Exception:
                pass
        try:
            report_data["vulnerabilities"] = analyze_ports(
                port_numbers, ip,
                log_findings=report_data.get("log_findings"),
                live_hosts=report_data.get("live_hosts"),
            )
        except Exception as e:
            logger.error(f"Vulnerability analysis failed: {e}")
            report_data["vulnerabilities"] = []

    # Risk score
    score = calculate_risk_score(report_data)
    label, emoji = get_risk_label(score)
    report_data["score"] = score
    report_data["score_label"] = label
    report_data["score_emoji"] = emoji

    # Phase 6 — Scan Memory
    # Get previous scan for comparison
    last_scan = get_last_scan(ip)

    # Detect new devices
    new_devices = []
    if "network_mapper" in tools:
        current_devices = report_data.get("live_hosts", [])
        new_devices = get_new_devices(current_devices, ip)

    # Save this scan to memory
    save_scan(report_data, ip, timestamp)

    # AI Analysis
    ai_analysis = None
    if use_ai:
        try:
            summary = build_scan_summary(report_data)
            if ai_mode == "private":
                from ai_assistant import analyze_with_ollama
                raw = analyze_with_ollama(summary)
            else:
                raw = analyze_with_ai(summary)
            ai_analysis = md.markdown(raw, extensions=["fenced_code", "tables"])
        except Exception as e:
            logger.error(f"AI analysis failed: {e}", exc_info=True)
            ai_analysis = "<p>AI analysis unavailable. Your scan results are shown below.</p>"

    # Offline explanations — built from plain_english.py when AI is not used
    offline_explanations = []
    if not use_ai:
        open_ports = report_data.get("open_ports", [])
        port_numbers = []
        for p in open_ports:
            try:
                port_numbers.append(parse_port_number(p))
            except Exception:
                pass
        for port in port_numbers:
            offline_explanations.append({"port": port, **explain_port(port)})

    text_report = build_text_report(report_data, ai_analysis, timestamp)
    return render_template("results.html",
        report_data=report_data,
        ai_analysis=ai_analysis,
        offline_explanations=offline_explanations,
        timestamp=timestamp,
        text_report=text_report,
        last_scan=last_scan,
        new_devices=new_devices)

@app.route("/network-intel")
def network_intel():
    interfaces   = get_network_interfaces()
    explanations = explain_interface(interfaces)
    grouped      = group_interfaces(interfaces)
    return render_template("network_intel.html",
        interfaces=interfaces,
        explanations=explanations,
        grouped=grouped)


@app.route("/arp-table")
def arp_table():
    interfaces = get_network_interfaces()
    gateway    = next((i["gateway"] for i in interfaces.values() if i.get("gateway")), None)
    entries    = get_arp_table()
    exps       = [explain_arp_entry(e, gateway=gateway) for e in entries]
    incomplete = sum(1 for e in entries if e.get("type") == "incomplete")
    return render_template("arp_table.html",
        items=list(zip(entries, exps)), gateway=gateway,
        total=len(entries), incomplete=incomplete)


@app.route("/netstat")
def netstat():
    conns = get_active_connections()
    state_order = ['LISTEN', 'ESTABLISHED', 'CLOSE_WAIT', 'TIME_WAIT', 'OTHER']
    buckets = {s: [] for s in state_order}
    for conn in conns:
        state = conn.get('state', '').upper()
        if state in ('LISTEN', 'LISTENING'):
            key = 'LISTEN'
        elif state == 'ESTABLISHED':
            key = 'ESTABLISHED'
        elif state == 'CLOSE_WAIT':
            key = 'CLOSE_WAIT'
        elif state == 'TIME_WAIT':
            key = 'TIME_WAIT'
        else:
            key = 'OTHER'
        buckets[key].append({'conn': conn, 'ex': explain_connection(conn)})
    grouped = [(s, buckets[s]) for s in state_order if buckets[s]]
    return render_template("netstat.html", grouped=grouped, total=len(conns))


@app.route("/traceroute")
def traceroute_view():
    host = request.args.get("host", "8.8.8.8").strip()
    if not re.match(r'^[a-zA-Z0-9.\-]+$', host):
        host = "8.8.8.8"
    hops, error = run_traceroute(host)
    exps        = [explain_hop(h) for h in hops]
    return render_template("traceroute.html",
        items=list(zip(hops, exps)), host=host, error=error)


@app.route("/download-report", methods=["POST"])
def download_report():
    report_text = request.form.get("report_text", "")
    timestamp = request.form.get("timestamp", datetime.datetime.now().isoformat())
    safe_ts = timestamp.replace(":", "-").replace(".", "-")
    buffer = io.BytesIO(report_text.encode("utf-8"))
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="text/plain",
        as_attachment=True,
        download_name=f"recon_ai_report_{safe_ts}.txt"
    )

# run
if __name__ == "__main__":
    app.run(debug=False, threaded=True)