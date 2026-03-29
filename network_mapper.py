from datetime import datetime
import ipaddress
import logging
import re
import subprocess
import platform

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def ping_host(ip):
    logger.info(f"Pinging {ip}")
    system = platform.system().lower()
    if system == "windows":
        command = ["ping", "-n", "1", "-w", "1000", str(ip)]
    else:
        command = ["ping", "-c", "1", "-W", "1", str(ip)]
    result = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0

def get_mac_from_arp(ip):
    """
    Get MAC address of an IP from the local ARP cache.
    Works on macOS and Linux.
    Returns MAC string or None.
    """
    try:
        result = subprocess.run(
            ["arp", "-n", str(ip)],
            capture_output=True,
            text=True,
            timeout=2
        )
        mac_pattern = r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})"
        match = re.search(mac_pattern, result.stdout)
        if match:
            return match.group(1).lower()
        return None
    except Exception:
        return None

def scan_subnet(subnet):
    logger.info(f"Scanning {subnet}")
    live_hosts = []
    for ip in ipaddress.IPv4Network(subnet, strict=False):
        if ping_host(ip):
            logger.info(f"Host found: {ip}")
            mac = get_mac_from_arp(ip)
            live_hosts.append({
                "ip": str(ip),
                "mac": mac or ""
            })
    return live_hosts


def save_report(subnet, live_hosts, timestamp, filename):
    logger.info(f"Saving report to {filename}")
    with open(filename, "w") as f:
        f.write(f"Network Scan Report\n")
        f.write(f"Subnet: {subnet}\n")
        f.write(f"Time: {timestamp}\n")
        f.write("="*40 + "\n")
        for host in live_hosts:
            ip = host["ip"] if isinstance(host, dict) else host
            f.write(f"[+] {ip} - ALIVE\n")
        f.write(f"\nTotal hosts found: {len(live_hosts)}\n")

def main():
    subnet = input("Enter subnet to scan (e.g., 192.168.1.0/24): ")
    timestamp = datetime.now().isoformat()
    filename = f"network_scan_{timestamp}.txt"

    logger.info(f"Starting scan for {subnet} at {timestamp}")

    print(f"\nScanning subnet {subnet}...\n")
    live_hosts = scan_subnet(subnet)
    save_report(subnet, live_hosts, timestamp, filename)
    print(f"\nScan complete. {len(live_hosts)} hosts found.")
    print(f"Report saved to: {filename}")

if __name__ == "__main__":
    main()
