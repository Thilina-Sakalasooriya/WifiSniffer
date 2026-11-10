#!/usr/bin/env python3
"""
WiFi Network Toolkit - All-in-One CLI Tool
Combines network scanning and traffic monitoring in one interface
"""

import os
import sys
import subprocess
import re
import signal
import socket
from datetime import datetime
from typing import Dict, List, Optional

# ANSI colors
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    BLACK = '\033[30m'
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

class WifiToolkit:
    def __init__(self):
        self.interface = None
        self.gateway_ip = None
        self.local_ip = None
        self.network_cidr = None
        self.devices = []
        self.target_device = None
        
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_main_banner(self):
        banner = f"""
{Colors.BRIGHT_CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════════╗
║                        WIFI NETWORK TOOLKIT v1.0                           ║
║                    All-in-One Network Scanner & Monitor                    ║
╚═══════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.DIM}Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | User: {os.getenv('USER', 'Unknown')}{Colors.RESET}
"""
        print(banner)
    
    def get_network_info(self) -> bool:
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                self.gateway_ip = match.group(1)
            else:
                return False
            
            result = subprocess.run(['ip', 'route', 'get', self.gateway_ip], 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            match_ip = re.search(r'src (\d+\.\d+\.\d+\.\d+)', result.stdout)
            match_dev = re.search(r'dev (\S+)', result.stdout)
            if match_ip:
                self.local_ip = match_ip.group(1)
            if match_dev:
                self.interface = match_dev.group(1)
            
            if self.local_ip:
                ip_parts = self.local_ip.split('.')
                self.network_cidr = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            return True
        except:
            return False
    
    def scan_network(self) -> List[Dict]:
        self.clear_screen()
        self.print_main_banner()
        print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}[1] NETWORK SCANNER{Colors.RESET}\n")
        
        if not self.get_network_info():
            print(f"{Colors.RED}✗{Colors.RESET} Failed to get network information")
            input(f"\n{Colors.DIM}Press Enter to return to menu...{Colors.RESET}")
            return []
        
        print(f"{Colors.GREEN}✓{Colors.RESET} Gateway: {Colors.BRIGHT_WHITE}{self.gateway_ip}{Colors.RESET}")
        print(f"{Colors.GREEN}✓{Colors.RESET} Local IP: {Colors.BRIGHT_WHITE}{self.local_ip}{Colors.RESET}")
        print(f"{Colors.GREEN}✓{Colors.RESET} Interface: {Colors.BRIGHT_WHITE}{self.interface}{Colors.RESET}")
        print(f"{Colors.GREEN}✓{Colors.RESET} Network: {Colors.BRIGHT_WHITE}{self.network_cidr}{Colors.RESET}\n")
        
        print(f"{Colors.CYAN}→{Colors.RESET} Scanning network...\n")
        
        devices = []
        try:
            result = subprocess.run(['ip', 'neigh', 'show'], 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
                                    if ip != self.local_ip and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                                        hostname = 'Unknown'
                                        try:
                                            h = socket.gethostbyaddr(ip)[0]
                                            if h and h != ip:
                                                hostname = h
                                        except:
                                            pass
                                        devices.append({
                                            'ip': ip,
                                            'mac': mac,
                                            'hostname': hostname,
                                            'type': 'DEVICE'
                                        })
                            except ValueError:
                                pass
        except Exception as e:
            print(f"{Colors.RED}✗{Colors.RESET} Error: {e}")
        
        # Add gateway
        if self.gateway_ip:
            hostname_gw = 'Gateway/Router'
            try:
                h = socket.gethostbyaddr(self.gateway_ip)[0]
                if h:
                    hostname_gw = h
            except:
                pass
            devices.insert(0, {
                'ip': self.gateway_ip,
                'mac': 'N/A',
                'hostname': hostname_gw,
                'type': 'ROUTER'
            })
        
        self.devices = devices
        
        print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}═══════════════════════════════════════════════════════════════════════════{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}                        SCAN RESULTS ({len(devices)} DEVICES)                        {Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}═══════════════════════════════════════════════════════════════════════════{Colors.RESET}\n")
        
        print(f"{Colors.BOLD}{Colors.WHITE}"
              f"{'#':<4} {'IP ADDRESS':<18} {'MAC ADDRESS':<19} {'DEVICE NAME':<35}"
              f"{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 80}{Colors.RESET}")
        
        def ip_key(d):
            try:
                if ':' in d['ip']: return (1, d['ip'])
                else: return (0, tuple(map(int, d['ip'].split('.'))))
            except: return (2, d['ip'])
        
        for idx, device in enumerate(sorted(devices, key=ip_key), 1):
            ip = device['ip']
            mac = device['mac']
            hostname = device['hostname']
            if len(hostname) > 33:
                hostname = hostname[:30] + '...'
            
            if device['type'] == 'ROUTER':
                print(f"{Colors.BRIGHT_YELLOW}{idx:<4}{Colors.RESET} "
                      f"{Colors.BRIGHT_YELLOW}{ip:<18}{Colors.RESET} "
                      f"{Colors.CYAN}{mac:<19}{Colors.RESET} "
                      f"{Colors.BRIGHT_YELLOW}{hostname:<35} [ROUTER]{Colors.RESET}")
            elif ip == self.local_ip:
                print(f"{Colors.BRIGHT_BLUE}{idx:<4}{Colors.RESET} "
                      f"{Colors.BRIGHT_BLUE}{ip:<18}{Colors.RESET} "
                      f"{Colors.CYAN}{mac:<19}{Colors.RESET} "
                      f"{Colors.BRIGHT_BLUE}{hostname:<35} [THIS DEVICE]{Colors.RESET}")
            else:
                print(f"{Colors.WHITE}{idx:<4}{Colors.RESET} "
                      f"{Colors.WHITE}{ip:<18}{Colors.RESET} "
                      f"{Colors.CYAN}{mac:<19}{Colors.RESET} "
                      f"{Colors.WHITE}{hostname:<35}{Colors.RESET}")
        
        print(f"\n{Colors.DIM}{'─' * 80}{Colors.RESET}\n")
        print(f"{Colors.BRIGHT_CYAN}TIP:{Colors.RESET} Use option {Colors.BRIGHT_WHITE}[2]{Colors.RESET} to monitor traffic for any device\n")
        input(f"{Colors.DIM}Press Enter to return to menu...{Colors.RESET}")
        return devices
    
    def monitor_traffic_menu(self):
        self.clear_screen()
        self.print_main_banner()
        print(f"{Colors.BRIGHT_MAGENTA}{Colors.BOLD}[2] TRAFFIC MONITOR{Colors.RESET}\n")
        
        if os.geteuid() != 0:
            print(f"{Colors.RED}✗{Colors.RESET} Traffic monitoring requires ROOT privileges!")
            print(f"{Colors.YELLOW}⚠{Colors.RESET}  Please run this tool with: {Colors.BRIGHT_WHITE}sudo python3 wifi_toolkit.py{Colors.RESET}\n")
            input(f"{Colors.DIM}Press Enter to return to menu...{Colors.RESET}")
            return
        
        if not self.devices:
            print(f"{Colors.YELLOW}⚠{Colors.RESET}  No devices scanned yet. Scanning now...\n")
            self.scan_network()
            self.clear_screen()
            self.print_main_banner()
            print(f"{Colors.BRIGHT_MAGENTA}{Colors.BOLD}[2] TRAFFIC MONITOR{Colors.RESET}\n")
        
        if not self.devices:
            print(f"{Colors.RED}✗{Colors.RESET} No devices available")
            input(f"\n{Colors.DIM}Press Enter to return to menu...{Colors.RESET}")
            return
        
        if not self.get_network_info():
            print(f"{Colors.RED}✗{Colors.RESET} Failed to get network info")
            input(f"\n{Colors.DIM}Press Enter to return to menu...{Colors.RESET}")
            return
        
        print(f"{Colors.GREEN}✓{Colors.RESET} Interface: {Colors.BRIGHT_WHITE}{self.interface}{Colors.RESET}\n")
        print(f"{Colors.BRIGHT_CYAN}SELECT DEVICE TO MONITOR:{Colors.RESET}\n")
        
        def ip_key(d):
            try:
                if ':' in d['ip']: return (1, d['ip'])
                else: return (0, tuple(map(int, d['ip'].split('.'))))
            except: return (2, d['ip'])
        
        for idx, device in enumerate(sorted(self.devices, key=ip_key), 1):
            ip = device['ip']
            hostname = device['hostname']
            if len(hostname) > 30:
                hostname = hostname[:27] + '...'
            if device['type'] == 'ROUTER':
                print(f"{Colors.BRIGHT_YELLOW}[{idx}]{Colors.RESET} {Colors.BRIGHT_WHITE}{ip:<16}{Colors.RESET} {hostname} {Colors.BRIGHT_YELLOW}[ROUTER]{Colors.RESET}")
            elif ip == self.local_ip:
                print(f"{Colors.BRIGHT_BLUE}[{idx}]{Colors.RESET} {Colors.BRIGHT_WHITE}{ip:<16}{Colors.RESET} {hostname} {Colors.BRIGHT_BLUE}[THIS DEVICE]{Colors.RESET}")
            else:
                print(f"{Colors.CYAN}[{idx}]{Colors.RESET} {Colors.WHITE}{ip:<16}{Colors.RESET} {hostname}")
        
        print(f"\n{Colors.DIM}[0] Back to menu{Colors.RESET}\n")
        
        try:
            choice = input(f"{Colors.BRIGHT_GREEN}Enter selection: {Colors.RESET}")
            choice_num = int(choice)
            if choice_num == 0:
                return
            sorted_devices = sorted(self.devices, key=ip_key)
            if 1 <= choice_num <= len(sorted_devices):
                self.target_device = sorted_devices[choice_num - 1]
                self.start_monitoring()
            else:
                print(f"{Colors.RED}Invalid selection{Colors.RESET}")
                input(f"\n{Colors.DIM}Press Enter to return...{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}Invalid input{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to return...{Colors.RESET}")
        except KeyboardInterrupt:
            return
    
    def start_monitoring(self):
        self.clear_screen()
        self.print_main_banner()
        print(f"{Colors.BRIGHT_MAGENTA}{Colors.BOLD}[TRAFFIC MONITOR - ACTIVE]{Colors.RESET}\n")
        
        target_ip = self.target_device['ip']
        target_name = self.target_device['hostname']
        
        print(f"{Colors.GREEN}✓{Colors.RESET} Target: {Colors.BRIGHT_WHITE}{target_ip}{Colors.RESET} ({target_name})")
        print(f"{Colors.GREEN}✓{Colors.RESET} Interface: {Colors.BRIGHT_WHITE}{self.interface}{Colors.RESET}\n")
        
        print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}═══════════════════════════════════════════════════════════════════════════{Colors.RESET}")
        print(f"{Colors.YELLOW}⚠{Colors.RESET}  Monitoring ALL traffic to/from {Colors.BRIGHT_WHITE}{target_ip}{Colors.RESET}")
        print(f"{Colors.DIM}Press {Colors.BRIGHT_WHITE}Ctrl+C{Colors.RESET} to stop monitoring{Colors.RESET}")
        print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}═══════════════════════════════════════════════════════════════════════════{Colors.RESET}\n")
        
        print(f"{Colors.BOLD}{Colors.WHITE}{'TIME':<12} {'TYPE':<12} {'DOMAIN/WEBSITE':<50} {'INFO':<25}{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 102}{Colors.RESET}\n")
        
        try:
            # Try tshark with broader capture
            cmd = [
                'tshark', '-i', self.interface,
                '-f', f'host {target_ip}',
                '-Y', 'dns.flags.response == 0 or http.host or tls.sni or dns.qry.name',
                '-T', 'fields',
                '-e', 'frame.time_epoch',
                '-e', '_ws.col.Protocol',
                '-e', 'dns.qry.name',
                '-e', 'http.host',
                '-e', 'tls.sni',
                '-l'
            ]
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                   text=True, bufsize=1)
            
            def signal_handler(sig, frame):
                print(f"\n\n{Colors.YELLOW}Stopping monitor...{Colors.RESET}")
                try:
                    proc.terminate()
                except:
                    pass
                print(f"{Colors.DIM}Press Enter to return to menu...{Colors.RESET}")
                input()
                sys.exit(0)
            
            signal.signal(signal.SIGINT, signal_handler)
            
            seen_domains = set()
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split('\t')
                timestamp = datetime.now().strftime('%H:%M:%S')
                protocol = parts[1].upper() if len(parts) > 1 else ''
                dns_query = parts[2].strip() if len(parts) > 2 else ''
                http_host = parts[3].strip() if len(parts) > 3 else ''
                tls_sni = parts[4].strip() if len(parts) > 4 else ''
                
                # Show DNS queries
                if dns_query and len(dns_query) > 0 and not dns_query.isspace():
                    domain = dns_query.lower()
                    if not domain.endswith(('.local', '.arpa', '.lan', 'in-addr.arpa')) and '.' in domain:
                        if domain not in seen_domains and len(domain) < 60:
                            seen_domains.add(domain)
                            print(f"{Colors.CYAN}{timestamp:<12}{Colors.RESET} "
                                  f"{Colors.BRIGHT_GREEN}{'DNS':<12}{Colors.RESET} "
                                  f"{Colors.BRIGHT_WHITE}{domain[:48]:<50}{Colors.RESET} "
                                  f"{Colors.DIM}DNS Query{Colors.RESET}")
                
                # Show HTTP hosts
                elif http_host and len(http_host) > 0 and not http_host.isspace():
                    host = http_host.lower()
                    if not host.endswith(('.local', '.lan')):
                        if host not in seen_domains and len(host) < 60:
                            seen_domains.add(host)
                            print(f"{Colors.CYAN}{timestamp:<12}{Colors.RESET} "
                                  f"{Colors.BRIGHT_BLUE}{'HTTP':<12}{Colors.RESET} "
                                  f"{Colors.BRIGHT_YELLOW}{host[:48]:<50}{Colors.RESET} "
                                  f"{Colors.DIM}HTTP Request{Colors.RESET}")
                
                # Show HTTPS SNI
                elif tls_sni and len(tls_sni) > 0 and not tls_sni.isspace():
                    host = tls_sni.lower()
                    if not host.endswith(('.local', '.lan')):
                        if host not in seen_domains and len(host) < 60:
                            seen_domains.add(host)
                            print(f"{Colors.CYAN}{timestamp:<12}{Colors.RESET} "
                                  f"{Colors.BRIGHT_MAGENTA}{'HTTPS(SNI)':<12}{Colors.RESET} "
                                  f"{Colors.BRIGHT_CYAN}{host[:48]:<50}{Colors.RESET} "
                                  f"{Colors.DIM}TLS Handshake{Colors.RESET}")
            
            proc.wait()
            print(f"\n{Colors.YELLOW}Capture ended.{Colors.RESET}")
            print(f"{Colors.DIM}Press Enter to return to menu...{Colors.RESET}")
            input()
            
        except FileNotFoundError:
            print(f"{Colors.RED}✗{Colors.RESET} tshark not found. Using tcpdump...")
            self.start_monitoring_tcpdump(target_ip)
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to return to menu...{Colors.RESET}")
    
    def start_monitoring_tcpdump(self, target_ip):
        try:
            cmd = ['tcpdump', '-i', self.interface, '-l', '-n', 
                   f'host {target_ip} and (port 53 or port 80)']
            
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                   text=True, bufsize=1)
            
            def signal_handler(sig, frame):
                print(f"\n\n{Colors.YELLOW}Stopping monitor...{Colors.RESET}")
                try:
                    proc.terminate()
                except:
                    pass
                print(f"{Colors.DIM}Press Enter to return to menu...{Colors.RESET}")
                input()
                sys.exit(0)
            
            signal.signal(signal.SIGINT, signal_handler)
            
            seen = set()
            for line in proc.stdout:
                if not line.strip():
                    continue
                timestamp = datetime.now().strftime('%H:%M:%S')
                
                if '53' in line and ('A?' in line or 'query' in line.lower() or 'ANY' in line):
                    match = re.search(r'([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', line)
                    if match:
                        domain = match.group(0)
                        if domain not in seen and not domain.endswith(('.in-addr.arpa',)):
                            seen.add(domain)
                            print(f"{Colors.CYAN}{timestamp:<12}{Colors.RESET} "
                                  f"{Colors.BRIGHT_GREEN}DNS{Colors.RESET}{'':<6} "
                                  f"{Colors.BRIGHT_WHITE}{domain[:43]:<45}{Colors.RESET}")
                
            proc.wait()
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to return to menu...{Colors.RESET}")
    
    def main_menu(self):
        while True:
            self.clear_screen()
            self.print_main_banner()
            print(f"{Colors.BRIGHT_CYAN}{Colors.BOLD}MAIN MENU{Colors.RESET}\n")
            print(f"{Colors.BRIGHT_GREEN}[1]{Colors.RESET} {Colors.WHITE}Scan Network (View all connected devices){Colors.RESET}")
            print(f"{Colors.BRIGHT_MAGENTA}[2]{Colors.RESET} {Colors.WHITE}Monitor Traffic (Listen to selected device){Colors.RESET}")
            print(f"{Colors.BRIGHT_YELLOW}[3]{Colors.RESET} {Colors.WHITE}Rescan Network{Colors.RESET}")
            print(f"{Colors.RED}[4]{Colors.RESET} {Colors.WHITE}Exit{Colors.RESET}\n")
            
            if self.interface:
                print(f"{Colors.DIM}Interface: {self.interface} | Gateway: {self.gateway_ip} | Local: {self.local_ip}{Colors.RESET}\n")
            else:
                print(f"{Colors.DIM}Not connected to network{Colors.RESET}\n")
            
            try:
                choice = input(f"{Colors.BRIGHT_GREEN}Select option [1-4]: {Colors.RESET}")
                if choice == '1':
                    self.scan_network()
                elif choice == '2':
                    self.monitor_traffic_menu()
                elif choice == '3':
                    self.devices = []
                    print(f"{Colors.CYAN}→{Colors.RESET} Rescanning...")
                    self.scan_network()
                elif choice == '4':
                    print(f"\n{Colors.CYAN}Thanks for using WiFi Network Toolkit!{Colors.RESET}")
                    sys.exit(0)
                else:
                    print(f"{Colors.RED}Invalid option{Colors.RESET}")
                    input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
            except KeyboardInterrupt:
                print(f"\n\n{Colors.CYAN}Thanks for using WiFi Network Toolkit!{Colors.RESET}")
                sys.exit(0)
            except EOFError:
                print(f"\n\n{Colors.CYAN}Thanks for using WiFi Network Toolkit!{Colors.RESET}")
                sys.exit(0)

def main():
    toolkit = WifiToolkit()
    toolkit.main_menu()

if __name__ == '__main__':
    main()
