#!/usr/bin/env python3
"""
Network Scanner Lite - Alternative scanner without nmap dependency
Uses pure Python for basic network scanning
"""

import socket
import subprocess
import sys
import threading
import time
import ipaddress
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init()

class NetworkScannerLite:
    def __init__(self):
        self.devices = []
        self.os_type = platform.system()
        
    def get_local_network(self):
        """Detect the local network range"""
        try:
            # Try to get IP by connecting to external server
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Parse the network
            ip = ipaddress.IPv4Address(local_ip)
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            return str(network)
        except:
            try:
                # Fallback to hostname method
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                ip = ipaddress.IPv4Address(local_ip)
                network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                return str(network)
            except:
                # Default to common home network range
                return "192.168.1.0/24"
    
    def ping_host(self, ip):
        """Check if a host is reachable using ping or TCP connection"""
        # First try a quick TCP connection to common ports
        common_test_ports = [80, 443, 445, 139, 22, 23, 21, 3389, 8080]
        
        for port in common_test_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)
                result = sock.connect_ex((str(ip), port))
                sock.close()
                if result == 0:
                    return True
            except:
                pass
        
        # If no TCP ports respond, try ping
        try:
            # Platform-specific ping command
            if self.os_type == "Windows":
                # Try Windows ping command
                cmd = ["ping", "-n", "1", "-w", "500", str(ip)]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
            
            result = subprocess.run(cmd, capture_output=True, timeout=1)
            return result.returncode == 0
        except:
            pass
        
        # Last resort: try ARP to see if host exists
        try:
            socket.gethostbyaddr(str(ip))
            return True
        except:
            return False
    
    def scan_port(self, host, port, timeout=1):
        """Check if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def get_hostname(self, ip):
        """Get hostname for an IP address"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return "Unknown"
    
    def get_mac_address(self, ip):
        """Get MAC address using ARP (Windows/Linux)"""
        try:
            if self.os_type == "Windows":
                # Use arp -a command
                result = subprocess.run(f"arp -a {ip}", shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                if '-' in part and len(part) == 17:
                                    return part.upper()
            else:
                # Linux/Mac
                result = subprocess.run(f"arp -n {ip}", shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                return parts[2].upper()
        except:
            pass
        return ""
    
    def identify_device_type(self, hostname, open_ports):
        """Identify device type based on characteristics"""
        hostname_lower = hostname.lower() if hostname else ""
        
        # Common device patterns
        if any(port in open_ports for port in [80, 443, 8080]) and \
           any(port in open_ports for port in [53, 67]):
            return "Router/Gateway"
        
        if 445 in open_ports or 139 in open_ports or 135 in open_ports:
            return "Windows Computer"
        
        if 22 in open_ports and 631 in open_ports:
            return "Linux/Unix Computer"
        
        if 5353 in open_ports or 62078 in open_ports:
            return "Apple Device"
        
        if any(word in hostname_lower for word in ['printer', 'print', 'hp', 'canon', 'epson']):
            return "Printer"
        
        if any(word in hostname_lower for word in ['tv', 'roku', 'chromecast', 'firestick']):
            return "Smart TV/Media"
        
        if any(word in hostname_lower for word in ['iphone', 'android', 'phone', 'mobile']):
            return "Mobile Phone"
        
        if open_ports:
            return "Network Device"
        
        return "Unknown Device"
    
    def assess_risk(self, open_ports):
        """Simple risk assessment based on open ports"""
        high_risk_ports = [23, 21, 135, 139, 445, 3389, 5900]  # Telnet, FTP, SMB, RDP, VNC
        medium_risk_ports = [80, 8080, 443, 22, 3306, 5432]  # HTTP, SSH, Databases
        
        risk_level = "Low"
        vulnerabilities = []
        
        for port in open_ports:
            if port in high_risk_ports:
                risk_level = "High"
                if port == 23:
                    vulnerabilities.append(f"Port 23 (Telnet): Unencrypted remote access - CRITICAL")
                elif port == 21:
                    vulnerabilities.append(f"Port 21 (FTP): Unencrypted file transfer")
                elif port in [135, 139, 445]:
                    vulnerabilities.append(f"Port {port} (SMB/NetBIOS): Potential ransomware vector")
                elif port == 3389:
                    vulnerabilities.append(f"Port 3389 (RDP): Remote Desktop exposed")
                elif port == 5900:
                    vulnerabilities.append(f"Port 5900 (VNC): Remote desktop with weak auth")
            
            elif port in medium_risk_ports and risk_level != "High":
                risk_level = "Medium"
                if port in [80, 8080]:
                    vulnerabilities.append(f"Port {port} (HTTP): Unencrypted web service")
                elif port == 22:
                    vulnerabilities.append(f"Port 22 (SSH): Ensure strong passwords")
                elif port == 3306:
                    vulnerabilities.append(f"Port 3306 (MySQL): Database exposed")
                elif port == 5432:
                    vulnerabilities.append(f"Port 5432 (PostgreSQL): Database exposed")
        
        return risk_level, vulnerabilities
    
    def scan_device(self, ip):
        """Scan a single device"""
        device_info = {
            'ip': str(ip),
            'hostname': 'Unknown',
            'mac': '',
            'open_ports': [],
            'device_type': 'Unknown',
            'risk_level': 'Low',
            'vulnerabilities': []
        }
        
        # Check if host is alive
        if not self.ping_host(str(ip)):
            return None
        
        # Get hostname
        device_info['hostname'] = self.get_hostname(str(ip))
        
        # Get MAC address
        device_info['mac'] = self.get_mac_address(str(ip))
        
        # Scan common ports (limited set for speed)
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 
                       631, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
        
        print(f"  Scanning ports on {ip}...", end='', flush=True)
        for port in common_ports:
            if self.scan_port(str(ip), port, timeout=0.5):
                device_info['open_ports'].append(port)
        print(" Done")
        
        # Identify device type
        device_info['device_type'] = self.identify_device_type(
            device_info['hostname'], 
            device_info['open_ports']
        )
        
        # Assess risk
        device_info['risk_level'], device_info['vulnerabilities'] = self.assess_risk(
            device_info['open_ports']
        )
        
        return device_info
    
    def scan_network(self, network_range=None):
        """Perform the network scan"""
        if not network_range:
            network_range = self.get_local_network()
        
        print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════")
        print(f"      NETWORK SCANNER LITE - Security Assessment")
        print(f"═══════════════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}[*] Scanning network: {network_range}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] This may take a few minutes...{Style.RESET_ALL}\n")
        
        # Parse network range
        try:
            network = ipaddress.IPv4Network(network_range)
        except:
            print(f"{Fore.RED}[!] Invalid network range{Style.RESET_ALL}")
            return
        
        # Discover active hosts
        print(f"{Fore.BLUE}[+] Discovering active hosts...{Style.RESET_ALL}")
        print(f"  (Scanning {len(list(network.hosts()))} possible addresses)")
        active_hosts = []
        
        # Use fewer workers to avoid overwhelming the network
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self.ping_host, str(ip)): ip 
                      for ip in network.hosts()}
            
            count = 0
            total = len(futures)
            for future in as_completed(futures):
                count += 1
                ip = futures[future]
                try:
                    if future.result():
                        active_hosts.append(ip)
                        print(f"  Found active host: {ip}")
                    elif count % 10 == 0:
                        print(f"  Progress: {count}/{total} hosts checked...")
                except:
                    pass
        
        print(f"\n{Fore.GREEN}[✓] Found {len(active_hosts)} active hosts{Style.RESET_ALL}\n")
        
        # Scan each active host
        print(f"{Fore.BLUE}[+] Performing detailed scan...{Style.RESET_ALL}")
        for idx, ip in enumerate(active_hosts, 1):
            print(f"\n[{idx}/{len(active_hosts)}] Scanning {ip}...")
            device_info = self.scan_device(ip)
            if device_info:
                self.devices.append(device_info)
        
        print(f"\n{Fore.GREEN}[✓] Scan complete!{Style.RESET_ALL}")
    
    def display_results(self):
        """Display scan results"""
        print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════")
        print(f"                    SCAN RESULTS")
        print(f"═══════════════════════════════════════════════════════{Style.RESET_ALL}\n")
        
        if not self.devices:
            print(f"{Fore.YELLOW}No devices found on the network.{Style.RESET_ALL}")
            return
        
        # Sort by risk level
        risk_order = {'High': 0, 'Medium': 1, 'Low': 2}
        self.devices.sort(key=lambda x: risk_order.get(x['risk_level'], 3))
        
        for device in self.devices:
            # Color based on risk
            if device['risk_level'] == 'High':
                color = Fore.RED
            elif device['risk_level'] == 'Medium':
                color = Fore.YELLOW
            else:
                color = Fore.GREEN
            
            print(f"{color}{'─' * 55}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}IP Address:    {device['ip']}{Style.RESET_ALL}")
            print(f"Hostname:      {device['hostname']}")
            print(f"Device Type:   {device['device_type']}")
            
            if device['mac']:
                print(f"MAC Address:   {device['mac']}")
            
            if device['open_ports']:
                ports_str = ', '.join(map(str, sorted(device['open_ports'])))
                print(f"Open Ports:    {ports_str}")
            
            print(f"Risk Level:    {color}{device['risk_level']}{Style.RESET_ALL}")
            
            if device['vulnerabilities']:
                print(f"\n{Fore.RED}⚠ Potential Issues:{Style.RESET_ALL}")
                for vuln in device['vulnerabilities']:
                    print(f"  • {vuln}")
            
            # Recommendations
            print(f"\n{Fore.CYAN}Recommendations:{Style.RESET_ALL}")
            if device['risk_level'] == 'High':
                print("  • URGENT: Review and close unnecessary ports")
                print("  • Update to encrypted alternatives (SSH instead of Telnet)")
                print("  • Enable firewall rules")
            elif device['risk_level'] == 'Medium':
                print("  • Review service configurations")
                print("  • Ensure strong authentication")
                print("  • Consider using VPN for remote access")
            else:
                print("  • Regular security updates")
                print("  • Monitor for unusual activity")
        
        # Summary
        print(f"\n{Fore.CYAN}{'═' * 55}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}SUMMARY:{Style.RESET_ALL}")
        print(f"Total Devices: {len(self.devices)}")
        
        high = sum(1 for d in self.devices if d['risk_level'] == 'High')
        medium = sum(1 for d in self.devices if d['risk_level'] == 'Medium')
        low = sum(1 for d in self.devices if d['risk_level'] == 'Low')
        
        print(f"{Fore.RED}High Risk:     {high}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Medium Risk:   {medium}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Low Risk:      {low}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Note: This is a basic scan. For comprehensive security{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}assessment, consider using the full version with nmap.{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 55}{Style.RESET_ALL}\n")

def main():
    """Main function"""
    try:
        print(f"{Fore.YELLOW}Network Scanner Lite - No nmap required{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Using pure Python for network scanning{Style.RESET_ALL}")
        
        scanner = NetworkScannerLite()
        scanner.scan_network()
        scanner.display_results()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
