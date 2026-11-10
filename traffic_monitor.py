#!/usr/bin/env python3
"""
WiFi Traffic Monitor - Listen to network traffic for selected device
Shows websites visited (DNS queries, HTTP Host headers)
"""

import os
import sys
import subprocess
import re
import signal
from datetime import datetime
from typing import Dict, List, Optional

# ANSI colors
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

class TrafficMonitor:
    def __init__(self):
        self.interface = None
        self.target_ip = None
        self.target_mac = None
        self.target_name = None
        self.running = False
        
    def print_banner(self):
        banner = f"""
{Colors.BRIGHT_MAGENTA}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════════╗
║                        NETWORK TRAFFIC MONITOR                            ║
║                    Website & DNS Traffic Analyzer                         ║
╚═══════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
        print(banner)
    
    def get_interface(self):
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            match = re.search(r'dev (\S+)', result.stdout)
            if match:
                self.interface = match.group(1)
                return True
        except:
            pass
        return False
    
    def load_devices(self) -> List[Dict]:
        """Load devices from recent scan or scan now"""
        devices = []
        # Try to scan quickly
        try:
            result = subprocess.run(['ip', 'neigh', 'show'], 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # Get gateway
            result_gw = subprocess.run(['ip', 'route', 'show', 'default'], 
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            gw_match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result_gw.stdout)
            gateway_ip = gw_match.group(1) if gw_match else None
            
            # Get local IP
            if gateway_ip:
                result_ip = subprocess.run(['ip', 'route', 'get', gateway_ip], 
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                local_match = re.search(r'src (\d+\.\d+\.\d+\.\d+)', result_ip.stdout)
                local_ip = local_match.group(1) if local_match else None
            else:
                local_ip = None
            
            # Add gateway
            if gateway_ip:
                devices.append({
                    'ip': gateway_ip,
                    'mac': 'N/A',
                    'name': 'Gateway/Router',
                    'type': 'ROUTER'
                })
            
            # Add devices from neighbors
            for line in result.stdout.strip().split('\n'):
                if line.strip() and 'lladdr' in line:
                    if any(state in line for state in ['REACHABLE', 'STALE', 'DELAY', 'PERMANENT']):
                        parts = line.split()
                        if len(parts) >= 4:
                            ip = parts[0]
                            if ':' in ip:
                                continue
                            try:
                                mac_idx = parts.index('lladdr') + 1
                                if mac_idx < len(parts):
                                    mac = parts[mac_idx].upper()
                                    if ip != local_ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                                        # Try hostname
                                        name = 'Unknown'
                                        try:
                                            hostname = __import__('socket').gethostbyaddr(ip)[0]
                                            if hostname and hostname != ip:
                                                name = hostname
                                        except:
                                            pass
                                        devices.append({
                                            'ip': ip,
                                            'mac': mac,
                                            'name': name,
                                            'type': 'DEVICE'
                                        })
                            except:
                                pass
        except Exception as e:
            print(f"{Colors.RED}Error scanning: {e}{Colors.RESET}")
        
        return devices
    
    def select_device(self, devices: List[Dict]) -> bool:
        """Let user select a device to monitor"""
        if not devices:
            print(f"{Colors.RED}No devices found to monitor.{Colors.RESET}")
            return False
        
        print(f"\n{Colors.BRIGHT_CYAN}{Colors.BOLD}AVAILABLE DEVICES:{Colors.RESET}\n")
        for i, dev in enumerate(devices):
            if dev['type'] == 'ROUTER':
                print(f"{Colors.BRIGHT_YELLOW}[{i+1}]{Colors.RESET} {Colors.BRIGHT_WHITE}{dev['ip']:<16}{Colors.RESET} "
                      f"{Colors.CYAN}{dev['mac']:<19}{Colors.RESET} {Colors.BRIGHT_YELLOW}{dev['name']}{Colors.RESET} "
                      f"{Colors.BRIGHT_YELLOW}[ROUTER]{Colors.RESET}")
            else:
                print(f"{Colors.BRIGHT_CYAN}[{i+1}]{Colors.RESET} {Colors.WHITE}{dev['ip']:<16}{Colors.RESET} "
                      f"{Colors.CYAN}{dev['mac']:<19}{Colors.RESET} {Colors.WHITE}{dev['name']}{Colors.RESET}")
        
        print(f"\n{Colors.DIM}[0] Cancel{Colors.RESET}\n")
        
        try:
            choice = input(f"{Colors.BRIGHT_GREEN}Select device to monitor (1-{len(devices)}): {Colors.RESET}")
            choice_num = int(choice)
            if choice_num == 0:
                return False
            if 1 <= choice_num <= len(devices):
                selected = devices[choice_num - 1]
                self.target_ip = selected['ip']
                self.target_mac = selected['mac']
                self.target_name = selected['name']
                print(f"\n{Colors.GREEN}✓{Colors.RESET} Monitoring: {Colors.BRIGHT_WHITE}{self.target_ip}{Colors.RESET} ({self.target_name})")
                return True
            else:
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                return False
        except ValueError:
            print(f"{Colors.RED}Invalid input{Colors.RESET}")
            return False
        except KeyboardInterrupt:
            return False
    
    def monitor_traffic(self):
        """Start monitoring traffic for selected device"""
        if os.geteuid() != 0:
            print(f"\n{Colors.RED}✗{Colors.RESET} Traffic monitoring requires root privileges!")
            print(f"{Colors.DIM}Please run with: sudo python3 traffic_monitor.py{Colors.RESET}")
            return
        
        self.print_banner()
        
        if not self.get_interface():
            print(f"{Colors.RED}Failed to detect network interface{Colors.RESET}")
            return
        
        print(f"{Colors.GREEN}✓{Colors.RESET} Interface: {Colors.BRIGHT_WHITE}{self.interface}{Colors.RESET}\n")
        
        devices = self.load_devices()
        if not self.select_device(devices):
            return
        
        print(f"\n{Colors.BRIGHT_CYAN}{Colors.BOLD}═══════════════════════════════════════════════════════════════════════════{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}                        STARTING TRAFFIC CAPTURE                        {Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}═══════════════════════════════════════════════════════════════════════════{Colors.RESET}\n")
        
        print(f"{Colors.YELLOW}⚠{Colors.RESET}  Monitoring traffic for {Colors.BRIGHT_WHITE}{self.target_ip}{Colors.RESET}")
        print(f"{Colors.DIM}Press Ctrl+C to stop monitoring{Colors.RESET}\n")
        
        print(f"{Colors.BOLD}{Colors.WHITE}{'TIME':<12} {'TYPE':<12} {'DESTINATION/DOMAIN':<40} {'INFO':<30}{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 95}{Colors.RESET}\n")
        
        self.running = True
        
        # Try to use tshark for better parsing
        try:
            # Filter for traffic to/from target IP
            filter_expr = f"host {self.target_ip}"
            
            # Use tshark to capture DNS and HTTP
            cmd = [
                'tshark', '-i', self.interface,
                '-f', f'host {self.target_ip}',
                '-Y', 'dns.qry.name or http.host or http.request',
                '-T', 'fields',
                '-e', 'frame.time',
                '-e', '_ws.col.Protocol',
                '-e', 'dns.qry.name',
                '-e', 'http.host',
                '-e', 'http.request.uri',
                '-l'  # line buffered
            ]
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                   text=True, bufsize=1)
            
            def signal_handler(sig, frame):
                print(f"\n\n{Colors.YELLOW}Stopping capture...{Colors.RESET}")
                proc.terminate()
                self.running = False
                sys.exit(0)
            
            signal.signal(signal.SIGINT, signal_handler)
            
            for line in proc.stdout:
                if not self.running:
                    break
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split('\t')
                if len(parts) < 5:
                    continue
                
                timestamp = datetime.now().strftime('%H:%M:%S')
                protocol = parts[1] if len(parts) > 1 else ''
                dns_query = parts[2] if len(parts) > 2 else ''
                http_host = parts[3] if len(parts) > 3 else ''
                http_uri = parts[4] if len(parts) > 4 else ''
                
                if dns_query and dns_query.strip():
                    # DNS query - website lookup
                    domain = dns_query.strip()
                    # Filter out common noise
                    if not domain.endswith(('.local', '.arpa')) and domain:
                        print(f"{Colors.CYAN}{timestamp:<12}{Colors.RESET} "
                              f"{Colors.BRIGHT_GREEN}DNS{Colors.RESET}{'':<8} "
                              f"{Colors.BRIGHT_WHITE}{domain[:38]:<40}{Colors.RESET} "
                              f"{Colors.DIM}DNS Lookup{Colors.RESET}")
                
                elif http_host and http_host.strip():
                    host = http_host.strip()
                    uri = http_uri.strip() if http_uri.strip() else '/'
                    if host:
                        full_url = f"{host}{uri}" if uri != '/' else host
                        print(f"{Colors.CYAN}{timestamp:<12}{Colors.RESET} "
                              f"{Colors.BRIGHT_BLUE}HTTP{Colors.RESET}{'':<7} "
                              f"{Colors.BRIGHT_YELLOW}{full_url[:38]:<40}{Colors.RESET} "
                              f"{Colors.DIM}HTTP Request{Colors.RESET}")
                
            proc.wait()
            
        except FileNotFoundError:
            print(f"{Colors.RED}✗{Colors.RESET} tshark not found. Trying tcpdump...")
            self.monitor_with_tcpdump()
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.RESET}")
            print(f"{Colors.DIM}Trying alternative method...{Colors.RESET}")
            self.monitor_with_tcpdump()
    
    def monitor_with_tcpdump(self):
        """Fallback monitoring with tcpdump"""
        try:
            filter_expr = f"host {self.target_ip} and (port 53 or port 80 or port 443)"
            cmd = ['tcpdump', '-i', self.interface, '-l', '-n', filter_expr]
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                   text=True, bufsize=1)
            
            def signal_handler(sig, frame):
                print(f"\n\n{Colors.YELLOW}Stopping capture...{Colors.RESET}")
                proc.terminate()
                sys.exit(0)
            
            signal.signal(signal.SIGINT, signal_handler)
            
            print(f"{Colors.DIM}Using tcpdump - showing basic traffic...{Colors.RESET}\n")
            
            for line in proc.stdout:
                if not line.strip():
                    continue
                timestamp = datetime.now().strftime('%H:%M:%S')
                if '53' in line and 'A?' in line or 'query' in line.lower():
                    # Try to extract DNS
                    match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', line)
                    if match:
                        domain = match.group(1)
                        print(f"{Colors.CYAN}{timestamp:<12}{Colors.RESET} "
                              f"{Colors.BRIGHT_GREEN}DNS{Colors.RESET}{'':<8} "
                              f"{Colors.BRIGHT_WHITE}{domain[:38]:<40}{Colors.RESET}")
                elif ':80 ' in line or '.80:' in line:
                    print(f"{Colors.CYAN}{timestamp:<12}{Colors.RESET} "
                          f"{Colors.BRIGHT_BLUE}HTTP{Colors.RESET}{'':<7} "
                          f"{Colors.DIM}{line[:38]:<40}{Colors.RESET}")
            
            proc.wait()
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.RESET}")

def main():
    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}⚠{Colors.RESET} Warning: Not running as root. Traffic monitoring will not work.")
        print(f"{Colors.DIM}Run with: sudo python3 traffic_monitor.py{Colors.RESET}\n")
    
    monitor = TrafficMonitor()
    monitor.monitor_traffic()

if __name__ == '__main__':
    main()
