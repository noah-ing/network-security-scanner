#!/usr/bin/env python3
"""
Network Scanner - Home Network Security Assessment Tool
Scans local network for devices and potential vulnerabilities
"""

import nmap
import socket
import sys
import time
import ipaddress
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init()

class NetworkScanner:
    def __init__(self):
        import os
        
        # Explicitly set the nmap executable path for Windows
        nmap_exe = r"C:\Program Files (x86)\Nmap\nmap.exe"
        
        if os.path.exists(nmap_exe):
            print(f"{Fore.GREEN}[✓] Using nmap at: {nmap_exe}{Style.RESET_ALL}")
            # Pass the explicit path to python-nmap
            self.nm = nmap.PortScanner(nmap_search_path=(r"C:\Program Files (x86)\Nmap",))
        else:
            print(f"{Fore.RED}[!] Nmap not found at expected location{Style.RESET_ALL}")
            sys.exit(1)
            
        self.devices = []
        self.vulnerabilities = []
        
    def get_local_network(self):
        """Detect the local network range"""
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        # Default to common home network range
        network = "192.168.1.0/24"
        
        # Try to determine actual network
        try:
            ip = ipaddress.IPv4Address(local_ip)
            network = str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
        except:
            pass
            
        return network
    
    def identify_device_type(self, hostname, os_match, open_ports):
        """Identify device type based on characteristics"""
        hostname_lower = hostname.lower() if hostname else ""
        
        # Router detection
        if any(port in open_ports for port in [80, 443, 8080]) and \
           any(port in open_ports for port in [23, 22, 53]):
            return "Router/Gateway"
        
        # Printer detection
        if 9100 in open_ports or 631 in open_ports:
            return "Printer"
        
        # Smart TV / Media device
        if any(word in hostname_lower for word in ['tv', 'roku', 'chromecast', 'firestick', 'apple-tv']):
            return "Smart TV/Media"
        
        # IoT device detection
        if any(port in open_ports for port in [1883, 8883]):  # MQTT ports
            return "IoT Device"
        
        # Phone detection
        if any(word in hostname_lower for word in ['iphone', 'android', 'phone', 'mobile']):
            return "Mobile Phone"
        
        # Windows computer
        if 445 in open_ports or 139 in open_ports:
            return "Windows Computer"
        
        # Linux/Unix server
        if 22 in open_ports and (111 in open_ports or 2049 in open_ports):
            return "Linux/Unix Server"
        
        # Default based on open services
        if 22 in open_ports:
            return "Computer/Server"
        
        return "Unknown Device"
    
    def assess_vulnerability(self, device_info):
        """Assess security vulnerabilities for a device"""
        vulnerabilities = []
        risk_level = "Low"
        
        open_ports = device_info.get('open_ports', [])
        services = device_info.get('services', {})
        
        # Check for dangerous open ports
        dangerous_ports = {
            23: ("Telnet", "Unencrypted remote access - CRITICAL"),
            21: ("FTP", "Unencrypted file transfer"),
            445: ("SMB", "Potential ransomware vector"),
            139: ("NetBIOS", "Legacy Windows sharing"),
            3389: ("RDP", "Remote Desktop - ensure strong passwords"),
            5900: ("VNC", "Remote desktop - often weak authentication"),
            1433: ("MSSQL", "Database exposed"),
            3306: ("MySQL", "Database exposed"),
            5432: ("PostgreSQL", "Database exposed")
        }
        
        for port, (service, warning) in dangerous_ports.items():
            if port in open_ports:
                vulnerabilities.append(f"Port {port} ({service}): {warning}")
                if port in [23, 21]:
                    risk_level = "High"
                elif risk_level != "High":
                    risk_level = "Medium"
        
        # Check for default web interface
        if any(port in open_ports for port in [80, 8080, 443, 8443]):
            vulnerabilities.append("Web interface detected - check for default credentials")
            if risk_level == "Low":
                risk_level = "Medium"
        
        # Check for outdated services
        for port, service_info in services.items():
            if 'version' in service_info:
                version = service_info['version'].lower()
                if any(old in version for old in ['1.0', '2.0', 'beta', 'alpha']):
                    vulnerabilities.append(f"Potentially outdated service on port {port}")
        
        return risk_level, vulnerabilities
    
    def scan_network(self, network_range=None):
        """Perform the network scan"""
        if not network_range:
            network_range = self.get_local_network()
        
        print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════")
        print(f"          NETWORK SCANNER - Security Assessment")
        print(f"═══════════════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}[*] Scanning network: {network_range}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] This may take a few minutes...{Style.RESET_ALL}\n")
        
        try:
            # Perform host discovery
            print(f"{Fore.BLUE}[+] Discovering hosts...{Style.RESET_ALL}")
            self.nm.scan(hosts=network_range, arguments='-sn')
            host_list = [(x, self.nm[x]['status']['state']) for x in self.nm.all_hosts()]
            
            print(f"{Fore.GREEN}[✓] Found {len(host_list)} active hosts{Style.RESET_ALL}\n")
            
            # Scan each discovered host
            for idx, (host, status) in enumerate(host_list, 1):
                print(f"{Fore.BLUE}[+] Scanning host {idx}/{len(host_list)}: {host}{Style.RESET_ALL}")
                
                # Perform detailed port scan
                self.nm.scan(hosts=host, arguments='-sV -O -T4 --top-ports 100')
                
                if host in self.nm.all_hosts():
                    device_info = self.extract_device_info(host)
                    self.devices.append(device_info)
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Make sure nmap is installed and you have appropriate permissions{Style.RESET_ALL}")
            sys.exit(1)
    
    def extract_device_info(self, host):
        """Extract detailed information about a host"""
        device_info = {
            'ip': host,
            'hostname': '',
            'mac': '',
            'vendor': '',
            'open_ports': [],
            'services': {},
            'os': '',
            'device_type': '',
            'risk_level': 'Low',
            'vulnerabilities': []
        }
        
        # Get hostname
        try:
            device_info['hostname'] = socket.gethostbyaddr(host)[0]
        except:
            device_info['hostname'] = 'Unknown'
        
        # Get MAC address and vendor
        if 'mac' in self.nm[host]['addresses']:
            device_info['mac'] = self.nm[host]['addresses']['mac']
            if 'vendor' in self.nm[host] and self.nm[host]['vendor']:
                device_info['vendor'] = list(self.nm[host]['vendor'].values())[0]
        
        # Get open ports and services
        if 'tcp' in self.nm[host]:
            for port in self.nm[host]['tcp']:
                if self.nm[host]['tcp'][port]['state'] == 'open':
                    device_info['open_ports'].append(port)
                    device_info['services'][port] = {
                        'name': self.nm[host]['tcp'][port]['name'],
                        'version': self.nm[host]['tcp'][port]['version'],
                        'product': self.nm[host]['tcp'][port]['product']
                    }
        
        # Get OS information
        if 'osmatch' in self.nm[host]:
            if self.nm[host]['osmatch']:
                device_info['os'] = self.nm[host]['osmatch'][0]['name']
        
        # Identify device type
        device_info['device_type'] = self.identify_device_type(
            device_info['hostname'],
            device_info['os'],
            device_info['open_ports']
        )
        
        # Assess vulnerabilities
        device_info['risk_level'], device_info['vulnerabilities'] = self.assess_vulnerability(device_info)
        
        return device_info
    
    def display_results(self):
        """Display scan results in a formatted manner"""
        print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════")
        print(f"                    SCAN RESULTS")
        print(f"═══════════════════════════════════════════════════════{Style.RESET_ALL}\n")
        
        if not self.devices:
            print(f"{Fore.YELLOW}No devices found on the network.{Style.RESET_ALL}")
            return
        
        # Sort devices by risk level
        risk_order = {'High': 0, 'Medium': 1, 'Low': 2}
        self.devices.sort(key=lambda x: risk_order.get(x['risk_level'], 3))
        
        for device in self.devices:
            # Choose color based on risk level
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
            if device['vendor']:
                print(f"Manufacturer:  {device['vendor']}")
            if device['os']:
                print(f"OS:            {device['os'][:50]}")
            
            # Display open ports
            if device['open_ports']:
                ports_str = ', '.join(map(str, device['open_ports'][:10]))
                if len(device['open_ports']) > 10:
                    ports_str += f" ... +{len(device['open_ports'])-10} more"
                print(f"Open Ports:    {ports_str}")
            
            # Display risk level
            print(f"Risk Level:    {color}{device['risk_level']}{Style.RESET_ALL}")
            
            # Display vulnerabilities
            if device['vulnerabilities']:
                print(f"\n{Fore.RED}⚠ Vulnerabilities:{Style.RESET_ALL}")
                for vuln in device['vulnerabilities'][:3]:  # Show top 3
                    print(f"  • {vuln}")
                if len(device['vulnerabilities']) > 3:
                    print(f"  • ... +{len(device['vulnerabilities'])-3} more issues")
            else:
                print(f"\n{Fore.GREEN}✓ No major vulnerabilities detected{Style.RESET_ALL}")
            
            # Recommendations
            print(f"\n{Fore.CYAN}Recommendations:{Style.RESET_ALL}")
            if device['risk_level'] == 'High':
                print("  • URGENT: Address critical vulnerabilities immediately")
                print("  • Disable unnecessary services")
                print("  • Update firmware/software")
            elif device['risk_level'] == 'Medium':
                print("  • Review and harden service configurations")
                print("  • Ensure strong authentication is enabled")
            else:
                print("  • Continue regular security monitoring")
                print("  • Keep software updated")
        
        # Summary statistics
        print(f"\n{Fore.CYAN}{'═' * 55}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}SUMMARY:{Style.RESET_ALL}")
        print(f"Total Devices: {len(self.devices)}")
        
        high_risk = sum(1 for d in self.devices if d['risk_level'] == 'High')
        medium_risk = sum(1 for d in self.devices if d['risk_level'] == 'Medium')
        low_risk = sum(1 for d in self.devices if d['risk_level'] == 'Low')
        
        print(f"{Fore.RED}High Risk:     {high_risk}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Medium Risk:   {medium_risk}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Low Risk:      {low_risk}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 55}{Style.RESET_ALL}\n")

def main():
    """Main function"""
    try:
        scanner = NetworkScanner()
        scanner.scan_network()
        scanner.display_results()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
