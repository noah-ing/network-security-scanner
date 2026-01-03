# Network Scanner

A Python-based network scanner that identifies devices and potential vulnerabilities on your home network.

## Features

- Scans local network (192.168.x.x range)
- Lists all connected devices with IP and MAC addresses
- Identifies open ports on each device
- Detects device types (router, phone, computer, IoT)
- Flags common vulnerabilities
- Shows results in clean, colored terminal output
- Risk level assessment (High/Medium/Low)
- Security recommendations

## Prerequisites

### Required Software

1. **Python 3.x** - Already installed
2. **Nmap** - Network scanning engine

### Installing Nmap

#### Windows
Download and install from: https://nmap.org/download.html
- Download the latest stable release installer
- Run the installer with default settings
- Restart your terminal after installation

#### Alternative (using Chocolatey):
```bash
choco install nmap
```

#### Linux
```bash
sudo apt-get install nmap  # Debian/Ubuntu
sudo yum install nmap      # RHEL/CentOS
sudo pacman -S nmap        # Arch
```

#### macOS
```bash
brew install nmap
```

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Verify nmap is installed:
```bash
nmap --version
```

## Usage

### Primary Scanner (with Nmap) - FULLY FUNCTIONAL 
```bash
python network_scanner_working.py
```
This version uses nmap directly for comprehensive network scanning.

### Alternative Scanner (Pure Python)
```bash
python network_scanner_lite.py
```
This version provides basic network scanning without requiring nmap.

### Legacy Version
```bash
python network_scanner.py
```
Note: This version may have compatibility issues with the python-nmap library.

## Tested and Working
- Successfully scans home networks
- Identifies device types (Router, Computer, Phone, IoT)
- Detects open ports and services
- Provides security risk assessment (High/Medium/Low)
- Offers specific security recommendations

## Security Notes

- This tool is for educational purposes and authorized network assessment only
- Only scan networks you own or have permission to test
- Some features require administrator/root privileges for full functionality
- The scanner is passive and does not exploit any vulnerabilities

## Output Information

The scanner provides:
- **IP Address**: Network address of the device
- **MAC Address**: Hardware address and manufacturer
- **Device Type**: Identified type (Router, Computer, Phone, IoT, etc.)
- **Open Ports**: List of accessible network ports
- **Risk Level**: Security assessment (High/Medium/Low)
- **Vulnerabilities**: Potential security issues detected
- **Recommendations**: Suggested security improvements

## Troubleshooting

### "nmap: command not found"
- Ensure nmap is installed correctly
- Restart your terminal after installation
- Add nmap to your system PATH if needed

### Permission Denied
- On Linux/Mac: Run with `sudo python network_scanner.py`
- On Windows: Run terminal as Administrator

### No devices found
- Check your network connection
- Verify the network range (default: 192.168.1.0/24)
- Some devices may not respond to network scans
