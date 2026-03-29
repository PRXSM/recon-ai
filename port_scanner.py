import socket
import datetime
import logging
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

# Setup logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Common ports and their services for basic identification
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    6379: "Redis",
    6667: "IRC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Dev",
    9090: "HTTP-Alt-2",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

def scan_port(target, port):
    logger.info(f"Scanning port {port} on {target}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.5)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except socket.error as e:
        logger.warning(f"Error scanning port {port}: {e}")
        return False

def scan_ports_threaded(target, port_range, max_workers=100):
    """
    Scan ports using threading.
    port_range: tuple (start, end)
    max_workers: concurrent threads
    Returns list of open port strings.
    """
    results = []
    start, end = port_range

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, target, port): port
            for port in range(start, end)
        }
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                service = common_ports.get(port, "Unknown")
                line = f"Port {port}: OPEN ({service})"
                print(line)
                results.append(line)

    results.sort(key=lambda x: int(x.split()[1].rstrip(":")))
    return results

def simple_scan(target):
    """Scan ports 1–1024. Fast. For everyday use."""
    logger.info(f"Starting simple scan on {target} (ports 1-1024)")
    logger.info(f"Running on {platform.system()}")
    return scan_ports_threaded(target, (1, 1025), max_workers=100)

def deep_scan(target):
    """Scan all 65,535 ports. Thorough. Takes 3–5 minutes."""
    logger.info(f"Starting deep scan on {target} (ports 1-65535)")
    logger.info(f"Running on {platform.system()}")
    return scan_ports_threaded(target, (1, 65536), max_workers=200)

def scan_target(target):
    """Alias for simple_scan() — keeps existing app.py calls working."""
    return simple_scan(target)

def save_report(target, results, timestamp, filename):
    logger.info(f"Saving report to {filename}")
    with open(filename, "w") as f:
        f.write(f"Scan Report - {target}\n")
        f.write(f"Time: {timestamp}\n")
        f.write(f"Platform: {platform.system()}\n")
        f.write("="*40 + "\n")
        if not results:
            f.write("No open ports found.\n")
        else:
            for line in results:
                f.write(line + "\n")
        f.write(f"\nTotal open ports: {len(results)}\n")

def main():
    target = input("Enter IP to scan: ")
    timestamp = datetime.datetime.now().isoformat()
    filename = f"scan_{target}_{timestamp}.txt"
    print(f"\nScanning {target}...\n")
    results = scan_target(target)
    save_report(target, results, timestamp, filename)
    print(f"\nScan complete.")
    print(f"Total open ports found: {len(results)}")
    print(f"Report saved to: {filename}")

if __name__ == "__main__":
    main()
