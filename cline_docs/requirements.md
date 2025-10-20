# Network Scanner Requirements

## Project Goal
Build a Python network scanner using nmap that scans home networks and identifies devices and vulnerabilities.

## Core Features
- Scan local network (192.168.x.x range)
- List all connected devices with IP and MAC addresses
- Identify open ports on each device
- Detect device types (router, phone, computer, IoT)
- Flag common vulnerabilities
- Show results in clean terminal output

## Technical Requirements
- Python 3.x
- python-nmap library
- Optional SQLite for scan history
- Under 300 lines of code
- Simple and functional

## Output Requirements
- Device IP address
- MAC address and manufacturer
- Open ports and services
- Hostname if available
- Risk level (High/Medium/Low)
- Basic security recommendations

## Usage
```bash
python network_scanner.py
# Automatically scans 192.168.1.0/24
