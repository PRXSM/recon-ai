import socket
import datetime

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
	3389: "RDP",
	8080: "HTTP-Alt"
}

target = input("Enter IP to scan: ")
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
filename = f"scan_{target}_{timestamp}.txt"

print(f"\nScanning {target}...\n")

results = []

for port in range(1, 1025):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	socket.setdefaulttimeout(0.5)
	result = sock.connect_ex((target, port))
	if result == 0:
		service = common_ports.get(port, "Unknown")
		line = f"Port {port}: OPEN ({service})"
		print(line)
		results.append(line)
	sock.close()

with open(filename, "w") as f:
	f.write(f"Scan Report - {target}\n")
	f.write(f"Time: {timestamp}\n")
	f.write("="*40 + "\n")
	for line in results:
		f.write(line + "\n")

print("\nScan complete.")
print(f"Report saved to: {filename}")
