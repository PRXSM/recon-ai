# Port Scanner

A Python-based TCP port scanner built for network reconnaissance and security analysis.

## Features
- Scans ports 1-1024 on any target IP
- Identifies common services by port number
- Timestamps every scan automatically
- Saves results to a formatted report file

## Tools Used
- Python 3.14
- Socket Library
- Datetime library

## How to Run
python3 port_scanner.py

## Sample Output
Scan Report - 127.0.0.1
Time: 2026-03-20 22-28-20
=============================================
Port 88: OPEN (Kerberos)
Port 445: OPEN (SMB)
