import socket
import datetime
import ipaddress

def ping_host(ip):
    import subprocess
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", str(ip)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return result.returncode == 0

subnet = input("Enter subnet to scan (e.g., 192.168.1.0/24): ")
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
filename = f"network_scan_{timestamp}.txt"

print(f"\nScanning subnet {subnet}...\n")

live_hosts = []

for ip in ipaddress.IPv4Network(subnet, strict=False):
    if ping_host(ip):
        print(f"[+] {ip} - ALIVE")
        live_hosts.append(str(ip))

with open(filename, "w") as f:
    f.write(f"Network Scan Report\n")
    f.write(f"Subnet: {subnet}\n")
    f.write(f"Time: {timestamp}\n")
    f.write("="*40 + "\n")
    for host in live_hosts:
        f.write(f"[+] {host} - ALIVE\n")
    f.write(f"\nTotal hosts found: {len(live_hosts)}\n")

print(f"\nScan complete. {len(live_hosts)} hosts found.")
print(f"Report saved to: {filename}")