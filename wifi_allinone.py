#!/usr/bin/env python3
"""
WIFI ALL-IN-ONE TOOLKIT
Scan + Monitor Mode + Live Traffic (DNS / HTTP / HTTPS-SNI)
"""

import os
import sys
import re
import signal
import time
import socket
import subprocess
from datetime import datetime

class C:
    R = '\033[0m'
    B = '\033[1m'
    D = '\033[2m'
    RED = '\033[31m'
    GRN = '\033[32m'
    YEL = '\033[33m'
    BLU = '\033[34m'
    MAG = '\033[35m'
    CYN = '\033[36m'
    WHT = '\033[37m'
    BRED = '\033[91m'
    BGRN = '\033[92m'
    BYEL = '\033[93m'
    BBLU = '\033[94m'
    BMAG = '\033[95m'
    BCYN = '\033[96m'
    BWHT = '\033[97m'

class WifiAllInOne:
    def __init__(self):
        self.original_iface = None
        self.current_iface = None
        self.monitor_iface = None
        self.gateway_ip = None
        self.local_ip = None
        self.devices = []
        self.in_monitor = False
        self.restored = False

    def clear(self):
        os.system('clear')

    def banner(self):
        print(f"""{C.BCYN}{C.B}
╔═══════════════════════════════════════════════════════════════════════════╗
║                    WIFI ALL-IN-ONE SCANNER + MONITOR                     ║
║                MONITOR MODE | DEVICE SCAN | LIVE TRAFFIC                  ║
╚═══════════════════════════════════════════════════════════════════════════╝
{C.R}
{C.D}Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.R}
""")

    def root_check(self):
        if os.geteuid() != 0:
            self.clear()
            self.banner()
            print(f"{C.BRED}[!] ERROR:{C.R} This tool MUST be run as root")
            print(f"{C.YEL}    Run with:{C.R} {C.BWHT}sudo python3 wifi_allinone.py{C.R}\n")
            sys.exit(1)

    def run_cmd(self, cmd, shell=False):
        try:
            res = subprocess.run(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return res.stdout, res.stderr, res.returncode
        except Exception as e:
            return "", str(e), 1

    def detect_iface(self):
        out, err, rc = self.run_cmd(['ip', 'route', 'show', 'default'])
        m = re.search(r'default via .* dev (\S+)', out)
        if m:
            self.original_iface = m.group(1)
            self.current_iface = m.group(1)
            return True
        out, err, rc = self.run_cmd(['iw', 'dev'])
        m2 = re.findall(r'Interface (\S+)', out)
        if m2:
            self.original_iface = m2[0]
            self.current_iface = m2[0]
            return True
        return False

    def check_mode(self, iface):
        if not iface:
            return 'unknown'
        out, err, rc = self.run_cmd(['iw', 'dev', iface, 'info'])
        if 'type monitor' in out:
            return 'monitor'
        if 'type managed' in out:
            return 'managed'
        return 'unknown'

    def enable_monitor(self):
        self.clear()
        self.banner()
        print(f"{C.BMAG}{C.B}[1] ENABLE MONITOR MODE{C.R}\n")
        if not self.detect_iface():
            print(f"{C.BRED}[X] Could not detect WiFi interface{C.R}")
            input(f"\n{C.D}Press Enter to return...{C.R}")
            return
        print(f"{C.BGRN}[+] Detected Interface:{C.R} {C.BWHT}{self.original_iface}{C.R}")
        print(f"{C.BGRN}[+] Current Mode:{C.R} {C.BYEL}{self.check_mode(self.original_iface)}{C.R}\n")

        if self.check_mode(self.original_iface) == 'monitor':
            print(f"{C.BGRN}[+] Already in MONITOR mode{C.R}")
            self.in_monitor = True
            self.monitor_iface = self.original_iface
            self.current_iface = self.original_iface
            input(f"\n{C.D}Press Enter to return...{C.R}")
            return

        print(f"{C.BLU}[*] Trying to switch to monitor mode...{C.R}")
        print(f"{C.D}This may kill NetworkManager/wpa_supplicant temporarily{C.R}\n")

        out, err, rc = self.run_cmd(['which', 'airmon-ng'])
        if rc == 0:
            print(f"{C.CYN}[~] Using airmon-ng{C.R}")
            self.run_cmd(['airmon-ng', 'check', 'kill'])
            time.sleep(2)
            self.run_cmd(['airmon-ng', 'start', self.original_iface])
            time.sleep(3)
            out3, err3, rc3 = self.run_cmd(['iw', 'dev'])
            mons = re.findall(r'Interface (\S+mon)', out3)
            if mons:
                self.monitor_iface = mons[0]
            elif self.check_mode(self.original_iface) == 'monitor':
                self.monitor_iface = self.original_iface
            else:
                cand = self.original_iface + 'mon'
                out4,err4,rc4 = self.run_cmd(['iw', 'dev', cand, 'info'])
                if rc4 == 0:
                    self.monitor_iface = cand
            if self.monitor_iface and self.check_mode(self.monitor_iface) == 'monitor':
                print(f"{C.BGRN}[+] Monitor mode ENABLED on:{C.R} {C.BWHT}{self.monitor_iface}{C.R}")
                self.in_monitor = True
                self.current_iface = self.monitor_iface
                input(f"\n{C.D}Press Enter to return...{C.R}")
                return
            else:
                print(f"{C.BYEL}[!] airmon-ng didn't create expected mon interface, trying iw...{C.R}")

        print(f"{C.CYN}[~] Using iw method{C.R}")
        self.run_cmd(['ip', 'link', 'set', self.original_iface, 'down'])
        self.run_cmd(['iw', 'dev', self.original_iface, 'set', 'type', 'monitor'])
        self.run_cmd(['ip', 'link', 'set', self.original_iface, 'up'])
        time.sleep(2)
        if self.check_mode(self.original_iface) == 'monitor':
            self.monitor_iface = self.original_iface
            self.current_iface = self.original_iface
            self.in_monitor = True
            print(f"{C.BGRN}[+] Monitor mode ENABLED on:{C.R} {C.BWHT}{self.monitor_iface}{C.R}")
        else:
            print(f"{C.BRED}[X] Failed to enable monitor mode{C.R}")
            print(f"{C.D}Check if your adapter supports monitor mode{C.R}")
        input(f"\n{C.D}Press Enter to return...{C.R}")

    def disable_monitor(self):
        self.clear()
        self.banner()
        print(f"{C.BLU}{C.B}[2] RESTORE MANAGED MODE{C.R}\n")
        if not self.in_monitor or not self.monitor_iface:
            print(f"{C.BYEL}[!] Not currently in monitor mode{C.R}")
            input(f"\n{C.D}Press Enter to return...{C.R}")
            return
        print(f"{C.BLU}[*] Restoring {C.BWHT}{self.monitor_iface}{C.R} to managed...{C.R}\n")
        out,err,rc = self.run_cmd(['which', 'airmon-ng'])
        if rc == 0 and self.monitor_iface.endswith('mon'):
            self.run_cmd(['airmon-ng', 'stop', self.monitor_iface])
            time.sleep(2)
        else:
            self.run_cmd(['ip', 'link', 'set', self.monitor_iface, 'down'])
            self.run_cmd(['iw', 'dev', self.monitor_iface, 'set', 'type', 'managed'])
            self.run_cmd(['ip', 'link', 'set', self.monitor_iface, 'up'])
            time.sleep(2)
        self.run_cmd(['systemctl', 'restart', 'NetworkManager'])
        time.sleep(2)
        self.in_monitor = False
        self.current_iface = self.original_iface
        print(f"{C.BGRN}[+] Restored to MANAGED mode{C.R}")
        print(f"{C.D}You may need to reconnect to WiFi{C.R}")
        self.restored = True
        input(f"\n{C.D}Press Enter to return...{C.R}")

    def scan_devices(self):
        self.clear()
        self.banner()
        print(f"{C.BGRN}{C.B}[3] SCAN CONNECTED DEVICES{C.R}\n")
        if not self.detect_iface():
            print(f"{C.BRED}[X] No interface found{C.R}")
            input(f"\n{C.D}Press Enter to return...{C.R}")
            return
        if self.in_monitor:
            print(f"{C.BYEL}[!] You're in MONITOR mode{C.R}")
            print(f"{C.D}For IP/MAC from ARP table better use MANAGED mode.{C.R}\n")
        out,err,rc = self.run_cmd(['ip', 'route', 'show', 'default'])
        m = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', out)
        if m: self.gateway_ip = m.group(1)
        if self.gateway_ip:
            out2,err2,rc2 = self.run_cmd(['ip', 'route', 'get', self.gateway_ip])
            m2 = re.search(r'src (\d+\.\d+\.\d+\.\d+)', out2)
            if m2: self.local_ip = m2.group(1)
            print(f"{C.BGRN}[+] Gateway:{C.R} {C.BWHT}{self.gateway_ip}{C.R}")
            print(f"{C.BGRN}[+] Your IP:{C.R} {C.BWHT}{self.local_ip}{C.R}")
            print(f"{C.BGRN}[+] Interface:{C.R} {C.BWHT}{self.current_iface}{C.R}\n")
        print(f"{C.CYN}[*] Scanning...{C.R}\n")
        devs = []
        outn,errn,rcn = self.run_cmd(['ip', 'neigh', 'show'])
        for line in outn.splitlines():
            if 'lladdr' in line and any(s in line for s in ['REACHABLE','STALE','DELAY','PERMANENT']):
                parts = line.split()
                if len(parts) < 4: continue
                ip = parts[0]
                if ':' in ip: continue
                if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip): continue
                try:
                    midx = parts.index('lladdr')+1
                    mac = parts[midx].upper()
                except: mac = 'N/A'
                hname = 'Unknown'
                try:
                    hname = socket.gethostbyaddr(ip)[0]
                except: pass
                devs.append({'ip':ip,'mac':mac,'name':hname,'type':'DEVICE'})
        # Add this device if we have local IP
        if self.local_ip and not any(d['ip'] == self.local_ip for d in devs):
            try:
                hname = socket.gethostname()
            except:
                hname = 'This Device'
            devs.append({'ip':self.local_ip,'mac':'N/A','name':hname,'type':'THIS'})
        if self.gateway_ip:
            gh = 'Gateway/Router'
            try: gh = socket.gethostbyaddr(self.gateway_ip)[0]
            except: pass
            # Check if gateway already in list
            if not any(d['ip'] == self.gateway_ip for d in devs):
                devs.insert(0, {'ip':self.gateway_ip,'mac':'N/A','name':gh,'type':'ROUTER'})
            else:
                # Update existing gateway entry
                for d in devs:
                    if d['ip'] == self.gateway_ip:
                        d['type'] = 'ROUTER'
                        d['name'] = gh
                        break
        self.devices = devs
        def ik(d):
            try:
                if ':' in d['ip']: return (1,d['ip'])
                return (0, tuple(map(int,d['ip'].split('.'))))
            except: return (2,d['ip'])
        print(f"{C.BCYN}═══════════════════════════════════════════════════════════════════════════{C.R}")
        print(f"{C.BCYN}{C.B}                        FOUND {len(devs)} DEVICE(S)                        {C.R}")
        print(f"{C.BCYN}═══════════════════════════════════════════════════════════════════════════{C.R}\n")
        print(f"{C.BWHT}{'#':<4}{'IP':<18}{'MAC':<20}{'DEVICE NAME':<40}{C.R}")
        print(f"{C.D}{'-'*86}{C.R}")
        for i,d in enumerate(sorted(devs,key=ik),1):
            ip=d['ip']; mac=d['mac']; nm=d['name']
            if len(nm)>38: nm=nm[:35]+'...'
            if d['type']=='ROUTER':
                print(f"{C.BYEL}{i:<4}{ip:<18}{mac:<20}{nm} [ROUTER]{C.R}")
            elif ip==self.local_ip or d['type']=='THIS':
                print(f"{C.BBLU}{i:<4}{ip:<18}{mac:<20}{nm} [THIS DEVICE]{C.R}")
            else:
                print(f"{C.WHT}{i:<4}{ip:<18}{mac:<20}{nm}{C.R}")
        print(f"\n{C.D}{'-'*86}{C.R}\n")
        input(f"{C.D}Press Enter to return to menu...{C.R}")

    def monitor_target(self):
        self.clear()
        self.banner()
        print(f"{C.BMAG}{C.B}[4] MONITOR SELECTED DEVICE (LIVE){C.R}\n")
        if not self.in_monitor:
            print(f"{C.BRED}[!] You are NOT in monitor mode{C.R}")
            print(f"{C.YEL}    Go to [1] and enable monitor mode first{C.R}\n")
            input(f"{C.D}Press Enter to return...{C.R}")
            return
        if not self.devices:
            print(f"{C.BYEL}[!] No device list found. Scanning now...{C.R}\n")
            self.scan_devices()
            self.clear()
            self.banner()
            print(f"{C.BMAG}{C.B}[4] MONITOR SELECTED DEVICE (LIVE){C.R}\n")
        if not self.devices:
            print(f"{C.BRED}[X] Nothing to select{C.R}")
            input(f"{C.D}Press Enter to return...{C.R}")
            return
        def ik(d):
            try:
                if ':' in d['ip']: return (1,d['ip'])
                return (0, tuple(map(int,d['ip'].split('.'))))
            except: return (2,d['ip'])
        print(f"{C.BCYN}SELECT TARGET:{C.R}\n")
        for i,d in enumerate(sorted(self.devices,key=ik),1):
            ip=d['ip']; nm=d['name']
            if len(nm)>32: nm=nm[:29]+'...'
            if d['type']=='ROUTER':
                print(f"{C.BYEL}[{i}]{C.R} {C.BWHT}{ip:<16}{C.R} {nm} [ROUTER]")
            elif ip==self.local_ip or d.get('type')=='THIS':
                print(f"{C.BBLU}[{i}]{C.R} {C.BWHT}{ip:<16}{C.R} {nm} [THIS DEVICE]")
            else:
                print(f"{C.CYN}[{i}]{C.R} {C.WHT}{ip:<16}{C.R} {nm}")
        print(f"\n{C.D}[0] Back{C.R}\n")
        try:
            ch = input(f"{C.BGRN}Enter number: {C.R}").strip()
            if ch=='0': return
            sdev = sorted(self.devices,key=ik)[int(ch)-1]
        except:
            print(f"{C.BRED}[X] Invalid choice{C.R}")
            input(f"{C.D}Press Enter...{C.R}")
            return
        target_ip = sdev['ip']
        target_nm = sdev['name']
        self.clear()
        self.banner()
        print(f"{C.BMAG}{C.B}[LIVE CAPTURE]{C.R}\n")
        print(f"{C.BGRN}[+] Target:{C.R} {C.BWHT}{target_ip}{C.R} ({target_nm})")
        print(f"{C.BGRN}[+] Interface:{C.R} {C.BWHT}{self.monitor_iface}{C.R}")
        print(f"{C.BYEL}[!] Watching for DNS / HTTP Host / TLS SNI{C.R}")
        print(f"{C.D}Press CTRL+C to stop immediately{C.R}\n")
        print(f"{C.BWHT}{'TIME':<12}{'TYPE':<14}{'SITE / DOMAIN':<55}{'INFO':<20}{C.R}")
        print(f"{C.D}{'-'*104}{C.R}\n")
        seen = set()
        p = None
        stop_flag = False
        def sigh(*a):
            nonlocal stop_flag
            stop_flag = True
            print(f"\n\n{C.BYEL}[!] Stopping capture...{C.R}")
            if p and p.poll() is None:
                try:
                    p.send_signal(signal.SIGINT)
                except:
                    try:
                        p.terminate()
                    except:
                        pass
            # Don't raise immediately, let loop handle it
        old_handler = signal.signal(signal.SIGINT, sigh)
        try:
            cmd = ['tshark','-i',self.monitor_iface,'-Y',f'host {target_ip} and (dns.qry.name or http.host or tls.sni)','-T','fields','-e','frame.time','-e','dns.qry.name','-e','http.host','-e','tls.sni','-l']
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            import select
            while True:
                if stop_flag:
                    break
                r,w,e = select.select([p.stdout], [], [], 0.5)
                if not r:
                    continue
                line = p.stdout.readline()
                if not line:
                    break
                try:
                    line=line.rstrip()
                    if not line.strip(): continue
                    parts=line.split('\t')
                    ts = datetime.now().strftime('%H:%M:%S')
                    dnsq = parts[1].strip().lower() if len(parts)>1 else ''
                    hhost = parts[2].strip().lower() if len(parts)>2 else ''
                    tsni = parts[3].strip().lower() if len(parts)>3 else ''
                    if dnsq and dnsq and '.' in dnsq and not dnsq.endswith(('.local','.arpa','.lan','in-addr.arpa')):
                        if dnsq not in seen and len(dnsq)<65:
                            seen.add(dnsq)
                            print(f"{C.CYN}{ts:<12}{C.R}{C.BGRN}{'DNS':<14}{C.R}{C.BWHT}{dnsq[:53]:<55}{C.R}{C.D}Query{C.R}")
                        continue
                    if hhost and hhost and '.' in hhost and not hhost.endswith(('.local','.lan')):
                        if hhost not in seen and len(hhost)<65:
                            seen.add(hhost)
                            print(f"{C.CYN}{ts:<12}{C.R}{C.BBLU}{'HTTP':<14}{C.R}{C.BYEL}{hhost[:53]:<55}{C.R}{C.D}Host{C.R}")
                        continue
                    if tsni and tsni and '.' in tsni and not tsni.endswith(('.local','.lan')):
                        if tsni not in seen and len(tsni)<65:
                            seen.add(tsni)
                            print(f"{C.CYN}{ts:<12}{C.R}{C.BMAG}{'HTTPS-SNI':<14}{C.R}{C.BCYN}{tsni[:53]:<55}{C.R}{C.D}TLS{C.R}")
                        continue
                except:
                    continue
            if p and p.poll() is None:
                try:
                    p.terminate()
                    time.sleep(0.2)
                    if p.poll() is None:
                        p.kill()
                except:
                    pass
        except KeyboardInterrupt:
            if p and p.poll() is None:
                try:
                    p.terminate()
                except:
                    pass
        except FileNotFoundError:
            print(f"{C.BRED}[X] tshark not found{C.R}")
            print(f"{C.D}Install: sudo apt install tshark wireshark-common{C.R}")
        except Exception as e:
            print(f"{C.BRED}[X] Error:{C.R} {e}")
        finally:
            signal.signal(signal.SIGINT, old_handler)
        print(f"\n\n{C.BGRN}[+] Capture stopped{C.R}")
        input(f"{C.D}Press Enter to return to menu...{C.R}")

    def status(self):
        print(f"\n{C.D}{'-'*60}{C.R}")
        print(f"{C.BWHT}STATUS:{C.R}")
        print(f"  Interface: {C.BCYN}{self.current_iface or 'N/A'}{C.R}")
        print(f"  Mode: {C.BYEL}{self.check_mode(self.current_iface) if self.current_iface else 'N/A'}{C.R}")
        print(f"  Monitor: {C.BGRN if self.in_monitor else C.BRED}{'ENABLED' if self.in_monitor else 'DISABLED'}{C.R}")
        print(f"{C.D}{'-'*60}{C.R}\n")

    def menu(self):
        while True:
            self.clear()
            self.banner()
            print(f"{C.BCYN}{C.B}MAIN MENU{C.R}\n")
            print(f"{C.BGRN}[1]{C.R} Enable Monitor Mode")
            print(f"{C.BBLU}[2]{C.R} Restore Managed Mode")
            print(f"{C.BGRN}[3]{C.R} Scan Network Devices")
            print(f"{C.BMAG}[4]{C.R} Monitor Selected Device (Live Traffic)")
            print(f"{C.BRED}[5]{C.R} Exit\n")
            self.status()
            try:
                c = input(f"{C.BGRN}Select [1-5]: {C.R}").strip()
                if c=='1': self.enable_monitor()
                elif c=='2': self.disable_monitor()
                elif c=='3': self.scan_devices()
                elif c=='4': self.monitor_target()
                elif c=='5':
                    if self.in_monitor and not self.restored:
                        print(f"\n{C.BYEL}[!] Monitor mode still active. Restoring...{C.R}")
                        self.disable_monitor()
                    print(f"\n{C.BCYN}Goodbye.{C.R}")
                    sys.exit(0)
                else:
                    print(f"{C.BRED}[X] Invalid option{C.R}")
                    time.sleep(1)
            except KeyboardInterrupt:
                if self.in_monitor and not self.restored:
                    print(f"\n\n{C.BYEL}[!] Restoring managed mode...{C.R}")
                    self.disable_monitor()
                print(f"\n\n{C.BCYN}Goodbye.{C.R}")
                sys.exit(0)

if __name__=='__main__':
    w = WifiAllInOne()
    w.root_check()
    w.menu()
