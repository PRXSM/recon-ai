from datetime import datetime
import ipaddress
import logging
import re
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    Cross-platform: uses 'arp -n' on macOS/Linux, 'arp -a' on Windows.
    Returns MAC string (lowercase, colon-separated) or None.
    """
    try:
        system = platform.system().lower()
        if system == "windows":
            result = subprocess.run(
                ["arp", "-a", str(ip)],
                capture_output=True, text=True, timeout=2
            )
            # Windows arp -a output format: "  192.168.1.1     aa-bb-cc-dd-ee-ff     dynamic"
            # MAC uses dashes on Windows — normalize to colons
            mac_pattern = r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})"
            match = re.search(mac_pattern, result.stdout)
            if match:
                return match.group(1).replace("-", ":").lower()
            return None
        else:
            result = subprocess.run(
                ["arp", "-n", str(ip)],
                capture_output=True, text=True, timeout=2
            )
            mac_pattern = r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})"
            match = re.search(mac_pattern, result.stdout)
            if match:
                return match.group(1).lower()
            return None
    except Exception:
        return None

def scan_subnet(subnet):
    """
    Discovers live hosts on a subnet using concurrent ping scanning.
    Uses ThreadPoolExecutor with max_workers=50 — dramatically faster
    than sequential scanning. A /24 subnet completes in under 15 seconds
    instead of 4+ minutes.

    Returns a list of dicts with 'ip' and 'mac' keys for each live host.
    """
    logger.info(f"Scanning {subnet} (threaded)")
    live_hosts = []

    try:
        addresses = list(ipaddress.IPv4Network(subnet, strict=False))
    except ValueError as e:
        logger.error(f"Invalid subnet {subnet}: {e}")
        return []

    def check_host(ip):
        if ping_host(ip):
            mac = get_mac_from_arp(ip)
            return {"ip": str(ip), "mac": mac or ""}
        return None

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_host, ip): ip for ip in addresses}
        for future in as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    live_hosts.append(result)
                    logger.info(f"Host found: {result['ip']}")
            except Exception as e:
                logger.error(f"Host check failed: {e}")

    # Sort results by IP address for consistent output
    live_hosts.sort(key=lambda h: tuple(int(p) for p in h["ip"].split(".")))
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
