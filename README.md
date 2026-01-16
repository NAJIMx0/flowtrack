
# FlowTrack - Advanced Network Security Monitor

A comprehensive network security monitoring tool built with Python featuring real-time threat detection, DDoS prevention, and system resource tracking with a modular architecture.

## 🚀 Features

### Network Security
- **Real-time Packet Sniffing**: Live network traffic capture and analysis
- **DDoS Attack Detection**: Automatic detection and IP blocking based on connection thresholds
- **Port Scanning**: Identify open ports and potential vulnerabilities
- **Firewall Integration**: Automatic port closing and IP blocking via system firewall

### System Monitoring
- **CPU Monitoring**: Real-time CPU usage and core information
- **Memory Tracking**: RAM usage statistics and alerts
- **Disk Analysis**: Storage usage across all partitions
- **Network Statistics**: Bytes sent/received tracking

### Alert System
- **Categorized Alerts**: System, Network, Security, Performance categories
- **Severity Levels**: Low, Medium, High, Critical
- **Alert History**: Persistent alert logging with export functionality
- **Color-Coded Display**: Visual severity indicators

## 📁 Project Structure

```
flowtrack/
├── main.py                        # Application entry point
├── install.sh                     # Installation script
├── requirements.txt               # Python dependencies
├── README.md                      # This file
├── .gitignore                    # Git ignore rules
├── src/
│   ├── __init__.py
│   ├── core/                     # Core functionality modules
│   │   ├── __init__.py
│   │   ├── security_monitor.py   # Security monitoring & DDoS detection
│   │   ├── system_monitor.py     # System resource monitoring
│   │   └── packet_sniffer.py     # Network packet capture & analysis
│   ├── gui/                      # User interface
│   │   ├── __init__.py
│   │   └── main_window.py        # Main application window
│   └── utils/                    # Utility modules
│       ├── __init__.py
│       └── alert_manager.py      # Alert handling & export
├── config/                       # Configuration files
└── logs/                         # Application logs
```

## 🔧 Architecture

FlowTrack follows a modular MVC-style architecture:

### Core Modules
- **SecurityMonitor**: Handles port scanning, DDoS detection, and firewall operations
- **SystemMonitor**: Monitors CPU, memory, disk, and network resources
- **PacketSniffer**: Captures and analyzes network packets with protocol detection
- **AlertManager**: Manages security alerts with categorization and export

### GUI Layer
- **FlowTrackApp**: Main Tkinter application with tabbed interface
- Separate tabs for: Processes, Performance, Security, Network Scan, Alerts

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- Administrator/root privileges (for packet sniffing and firewall rules)
- Nmap (for port scanning)

### Linux Installation

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install python3 python3-pip nmap

# Clone repository
git clone https://github.com/yourusername/flowtrack.git
cd flowtrack

# Run installation script
chmod +x install.sh
./install.sh

# Or install manually
pip3 install -r requirements.txt --break-system-packages
```

### Windows Installation

```powershell
# Install Python from python.org
# Install Nmap from nmap.org
# Install WinPcap or Npcap for packet capture

# Install dependencies
pip install -r requirements.txt

# Run as Administrator
python main.py
```

### macOS Installation

```bash
# Install dependencies
brew install python nmap

# Clone and install
git clone https://github.com/yourusername/flowtrack.git
cd flowtrack
pip3 install -r requirements.txt

# Run with sudo
sudo python3 main.py
```

## 🚀 Usage

### Running the Application

**Linux:**
```bash
sudo python3 main.py
```

**Windows (as Administrator):**
```powershell
python main.py
```

### Features Guide

#### 1. Process Management
- View running processes with CPU and memory usage
- Search processes by name
- Terminate processes
- Real-time process monitoring

#### 2. Performance Monitoring
- **CPU Tab**: Usage percentage, core count, model information
- **RAM Tab**: Total, used, available memory
- **Disk Tab**: Storage usage for all partitions
- **Network Tab**: Sent/received data statistics

#### 3. Security Monitoring
- **DDoS Protection**: 
  - Configurable connection threshold (default: 100/min)
  - Automatic IP blocking for attackers
  - View blocked IPs list
- **Packet Sniffing**:
  - Select network interface
  - Real-time packet capture
  - Protocol analysis (TCP, UDP, ICMP)

#### 4. Network Scanning
- Scan IP addresses or ranges
- Specify port ranges (e.g., "1-1000", "80,443,8080")
- Identify dangerous open ports
- Close ports via firewall rules
- Risk level classification

#### 5. Alert Management
- View all security and system alerts
- Filter by severity: Critical, High, Medium, Low
- Export alerts to JSON
- Color-coded alert display

### Configuration

**DDoS Threshold:**
Adjust in Security tab → DDoS Protection section

**Network Interface:**
Select in Security tab → Packet Sniffing section

## 🔒 Security Features

### DDoS Detection Algorithm
1. Tracks connections per source IP
2. Maintains 1-minute rolling window
3. Blocks IPs exceeding threshold
4. Automatic firewall rule creation

### Port Security
- Database of dangerous ports (FTP, Telnet, RDP, etc.)
- Automatic risk classification
- Alert generation for high-risk ports
- Firewall integration for port blocking

### Packet Analysis
- Protocol detection (TCP/UDP/ICMP)
- Source/destination tracking
- Timestamp logging
- Integration with DDoS detection

## 🛠️ Technology Stack

- **Language**: Python 3.8+
- **GUI Framework**: Tkinter (built-in)
- **Networking**: Scapy (packet capture)
- **Port Scanning**: python-nmap
- **System Monitoring**: psutil
- **Concurrency**: threading (built-in)

## 📋 Dependencies

```
psutil>=5.9.0          # System monitoring
scapy>=2.5.0           # Packet capture
python-nmap>=0.7.1     # Port scanning
```

## 🔐 Permissions

### Linux (iptables)
```bash
# Packet sniffing
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3

# Or run with sudo
sudo python3 main.py
```

### Windows (Firewall)
- Run Command Prompt as Administrator
- Or use "Run as Administrator" on Python script

## 🐛 Troubleshooting

### "Scapy not available"
```bash
pip install scapy
# Windows may require WinPcap/Npcap
```

### "python-nmap not available"
```bash
pip install python-nmap
# Also install nmap system package
```

### "Permission denied" errors
```bash
# Linux: Run with sudo
sudo python3 main.py

# Windows: Run as Administrator
```

### Packet sniffing not working
- **Linux**: Check interface name with `ip link` or `ifconfig`
- **Windows**: Install WinPcap or Npcap
- Verify administrator/root privileges

## 📊 Performance

- **CPU Usage**: ~2-5% idle, up to 15% during packet sniffing
- **Memory Usage**: ~50-100 MB
- **Packet Capture Rate**: Up to 10,000 packets/second
- **Port Scan Speed**: ~100 ports/second

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Follow PEP 8 style guidelines
4. Add tests for new features
5. Submit a pull request

## 📄 License

MIT License - See LICENSE file for details

## 👨‍💻 Author

**Badr-Eddine NAJIM**
- GitHub: [@Najim](https://github.com/NAJIMx0)
- LinkedIn: [najim-badr-eddine](https://linkedin.com/in/najim-badr-eddine)

## 🎓 Academic Context

Developed as a Projet de Fin d'Année (PFA) at EMSI Tanger
- Program: Cycle d'Ingénieur en Informatique et Réseaux
- Year: 2024-2025

## 🙏 Acknowledgments

- Built with open-source libraries: Scapy, python-nmap, psutil
- Inspired by network security best practices
- OWASP guidelines for security implementation

## 📝 Future Enhancements

- [ ] Machine learning for anomaly detection
- [ ] Web dashboard interface
- [ ] Database logging
- [ ] Email/SMS alerts
- [ ] Custom firewall rules
- [ ] Network topology visualization
- [ ] Encrypted packet analysis
- [ ] Multi-platform packaging (exe, deb, rpm)

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Contact via LinkedIn

---

**Note**: This tool is for educational and authorized security testing only. Always obtain proper authorization before scanning networks or analyzing traffic.
