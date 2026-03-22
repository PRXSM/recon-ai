import socket
import datetime
import logging
import platform

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
	3389: "RDP",
	8080: "HTTP-Alt"
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
	
def scan_target (target):
	logger.info(f"Starting scan on {target}")
	logger.info(f"Running on {platform.system()}")
	results = []
	for port in range(1, 1025):
		if scan_port(target, port):
			service = common_ports.get(port, "Unknown")
			line = f"Port {port}: OPEN ({service})"
			print(line)
			results.append(line)
	return results

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
	print(f"\nScan complete. ")
	print(f"Total open ports found: {len(results)}")
	print(f"Report saved to: {filename}")
if __name__ == "__main__":
	main()