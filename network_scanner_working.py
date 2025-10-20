#!/usr/bin/env python3
"""
Network Scanner Working Version - Direct nmap execution
Scans local network for devices and potential vulnerabilities
"""

import subprocess
import socket
import sys
import json
import re
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored output
init()

class NetworkScanner:
    def __init__(self):
        self.devices = []
        self.nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        
        # Verify nmap is accessible
        try:
            result = subprocess.run([self.nmap_path, "--version"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"{Fore.GREEN}[✓] Nmap found and working!{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Nmap found but not working properly{Style.RESET_ALL}")
                sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] Error testing nmap: {e}{Style.RESET_ALL}")
            sys.exit(1)
    
    def get_local_network(self):
        """Detect the local network range"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            ip = ipaddress.IPv4Address(local_ip)
            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
            return str(network)
        except:
            return "192.168.1.0/24"
    
    def run_nmap_scan(self, target, arguments):
        """Run nmap with given arguments and return output"""
        cmd = [self.nmap_path] + arguments.split() + [target, "-oX", "-"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                return result.stdout
            else:
                print(f"{Fore.YELLOW}Warning: Nmap returned non-zero exit code{Style.RESET_ALL}")
                return result.stdout
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[!] Scan timeout{Style.RESET_ALL}")
            return None
        except Exception as e:
            print(f"{Fore.RED}[!] Error running nmap: {e}{Style.RESET_ALL}")
            return None
    
    def parse_nmap_xml(self, xml_output):
        """Parse nmap XML output"""
        try:
            root = ET.fromstring(xml_output)
            hosts = []
            
            for host in root.findall('.//host'):
                if host.find('status').get('state') == 'up':
                    host_info = {}
                    
                    # Get IP address
                    for addr in host.findall('address'):
                        if addr.get('addrtype') == 'ipv4':
                            host_info['ip'] = addr.get('addr')
                        elif addr.get('addrtype') == 'mac':
                            host_info['mac'] = addr.get('addr')
                            host_info['vendor'] = addr.get('vendor', '')
                    
                    # Get hostname
                    hostname_elem = host.find('.//hostname')
                    host_info['hostname'] = hostname_elem.get('name', 'Unknown') if hostname_elem is not None else 'Unknown'
                    
                    # Get open ports
                    host_info['ports'] = []
                    for port in host.findall('.//port'):
                        if port.find('state').get('state') == 'open':
                            port_info = {
                                'port': int(port.get('portid')),
                                'protocol': port.get('protocol'),
                                'service': port.find('service').get('name', 'unknown') if port.find('service') is not None else 'unknown'
                            }
                            host_info['ports'].append(port_info)
                    
                    # Get OS info
                    os_match = host.find('.//osmatch')
                    host_info['os'] = os_match.get('name', '') if os_match is not None else ''
                    
                    hosts.append(host_info)
            
            return hosts
        except Exception as e:
            print(f"{Fore.RED}[!] Error parsing XML: {e}{Style.RESET_ALL}")
            return []
    
    def identify_device_type(self, host_info):
        """Identify device type based on characteristics"""
        hostname = host_info.get('hostname', '').lower()
        open_ports = [p['port'] for p in host_info.get('ports', [])]
        
        if any(port in open_ports for port in [80, 443, 8080]) and \
           any(port in open_ports for port in [23, 22, 53]):
            return "Router/Gateway"
        
        if 9100 in open_ports or 631 in open_ports:
            return "Printer"
        
        if any(word in hostname for word in ['tv', 'roku', 'chromecast']):
            return "Smart TV/Media"
        
        if 445 in open_ports or 139 in open_ports:
            return "Windows Computer"
        
        if 22 in open_ports:
            return "Computer/Server"
        
        return "Unknown Device"
    
    def assess_risk(self, host_info):
        """Assess security risk level"""
        open_ports = [p['port'] for p in host_info.get('ports', [])]
        vulnerabilities = []
        
        dangerous_ports = {
            23: "Telnet - Unencrypted remote access",
            21: "FTP - Unencrypted file transfer",
            445: "SMB - Potential ransomware vector",
            139: "NetBIOS - Legacy Windows sharing",
            3389: "RDP - Remote Desktop exposed"
        }
        
        risk_level = "Low"
        for port, desc in dangerous_ports.items():
            if port in open_ports:
                vulnerabilities.append(f"Port {port}: {desc}")
                if port in [23, 21]:
                    risk_level = "High"
                elif risk_level != "High":
                    risk_level = "Medium"
        
        if any(port in open_ports for port in [80, 8080]):
            vulnerabilities.append("HTTP - Unencrypted web service")
            if risk_level == "Low":
                risk_level = "Medium"
        
        return risk_level, vulnerabilities
    
    def scan_network(self):
        """Perform the network scan"""
        network_range = self.get_local_network()
        
        print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════")
        print(f"          NETWORK SCANNER - Security Assessment")
        print(f"═══════════════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}[*] Scanning network: {network_range}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] This may take a few minutes...{Style.RESET_ALL}\n")
        
        # Step 1: Host discovery
        print(f"{Fore.BLUE}[+] Discovering hosts...{Style.RESET_ALL}")
        xml_output = self.run_nmap_scan(network_range, "-sn")
        
        if not xml_output:
            print(f"{Fore.RED}[!] Host discovery failed{Style.RESET_ALL}")
            return
        
        discovered_hosts = self.parse_nmap_xml(xml_output)
        print(f"{Fore.GREEN}[✓] Found {len(discovered_hosts)} active hosts{Style.RESET_ALL}\n")
        
        # Step 2: Detailed scan of each host
        for idx, host in enumerate(discovered_hosts, 1):
            ip = host.get('ip')
            print(f"{Fore.BLUE}[+] Scanning host {idx}/{len(discovered_hosts)}: {ip}{Style.RESET_ALL}")
            
            # Perform detailed port scan
            xml_output = self.run_nmap_scan(ip, "-sV -T4 --top-ports 100")
            
            if xml_output:
                detailed_info = self.parse_nmap_xml(xml_output)
                if detailed_info:
                    host_data = detailed_info[0]
                    host_data['device_type'] = self.identify_device_type(host_data)
                    host_data['risk_level'], host_data['vulnerabilities'] = self.assess_risk(host_data)
                    self.devices.append(host_data)
    
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
        self.devices.sort(key=lambda x: risk_order.get(x.get('risk_level', 'Low'), 3))
        
        for device in self.devices:
            # Choose color based on risk level
            risk = device.get('risk_level', 'Low')
            if risk == 'High':
                color = Fore.RED
            elif risk == 'Medium':
                color = Fore.YELLOW
            else:
                color = Fore.GREEN
            
            print(f"{color}{'─' * 55}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}IP Address:    {device.get('ip', 'Unknown')}{Style.RESET_ALL}")
            print(f"Hostname:      {device.get('hostname', 'Unknown')}")
            print(f"Device Type:   {device.get('device_type', 'Unknown')}")
            
            if device.get('mac'):
                print(f"MAC Address:   {device.get('mac')}")
            if device.get('vendor'):
                print(f"Manufacturer:  {device.get('vendor')}")
            if device.get('os'):
                print(f"OS:            {device.get('os')[:50]}")
            
            # Display open ports
            ports = device.get('ports', [])
            if ports:
                port_list = [str(p['port']) for p in ports[:10]]
                ports_str = ', '.join(port_list)
                if len(ports) > 10:
                    ports_str += f" ... +{len(ports)-10} more"
                print(f"Open Ports:    {ports_str}")
            
            print(f"Risk Level:    {color}{risk}{Style.RESET_ALL}")
            
            # Display vulnerabilities
            vulns = device.get('vulnerabilities', [])
            if vulns:
                print(f"\n{Fore.RED}⚠ Vulnerabilities:{Style.RESET_ALL}")
                for vuln in vulns[:3]:
                    print(f"  • {vuln}")
                if len(vulns) > 3:
                    print(f"  • ... +{len(vulns)-3} more issues")
            else:
                print(f"\n{Fore.GREEN}✓ No major vulnerabilities detected{Style.RESET_ALL}")
            
            # Recommendations
            print(f"\n{Fore.CYAN}Recommendations:{Style.RESET_ALL}")
            if risk == 'High':
                print("  • URGENT: Address critical vulnerabilities")
                print("  • Disable unnecessary services")
                print("  • Update firmware/software")
            elif risk == 'Medium':
                print("  • Review service configurations")
                print("  • Ensure strong authentication")
            else:
                print("  • Continue regular monitoring")
                print("  • Keep software updated")
        
        # Summary
        print(f"\n{Fore.CYAN}{'═' * 55}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}SUMMARY:{Style.RESET_ALL}")
        print(f"Total Devices: {len(self.devices)}")
        
        high = sum(1 for d in self.devices if d.get('risk_level') == 'High')
        medium = sum(1 for d in self.devices if d.get('risk_level') == 'Medium')
        low = sum(1 for d in self.devices if d.get('risk_level') == 'Low')
        
        print(f"{Fore.RED}High Risk:     {high}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Medium Risk:   {medium}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Low Risk:      {low}{Style.RESET_ALL}")
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
