# WiFi Network Scanner & Traffic Monitor

Professional CLI tools for network analysis on Linux.

## Tools

### 1. wifi_scanner.py
Scans the local WiFi network to discover all connected devices showing:
- IP Address
- MAC Address  
- Device/Hostname
- Signal Strength & Distance Estimation
- Connection Quality (color-coded)

```bash
python3 wifi_scanner.py
# or for better results
sudo python3 wifi_scanner.py
```

### 2. traffic_monitor.py
After selecting a connected device, monitors its network traffic to see:
- DNS queries (website lookups)
- HTTP requests (websites visited)
- Real-time traffic analysis

```bash
sudo python3 traffic_monitor.py
# or use the helper script
./run_monitor.sh
```

## Features
- Professional color-coded CLI interface
- Automatic gateway and interface detection
- Hostname resolution (DNS + NetBIOS)
- Network distance/quality estimation
- Interactive device selection
- Real-time traffic monitoring

## Requirements
- Python 3
- tcpdump, tshark (usually pre-installed)
- Root privileges recommended for traffic monitoring

## Notes
- Traffic monitoring works best on the same network segment
- HTTPS traffic is encrypted - only DNS and HTTP Host headers are visible
- For full packet inspection, you need to be in monitor mode or MITM position
