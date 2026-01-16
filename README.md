# FlowTrack - Advanced Network Security Monitor

A comprehensive network security monitoring tool built with Python for real-time threat detection, DDoS prevention, and system resource tracking.

## Features

- **Real-time Network Monitoring**: Live packet sniffing and analysis
- **DDoS Attack Detection**: Automatic detection and IP blocking
- **Port Scanning**: Identify open ports and security vulnerabilities
- **System Resource Monitoring**: Track CPU, memory, disk, and network usage
- **Alert Management**: Categorized security alerts with severity levels
- **Firewall Integration**: Automatic port and IP blocking via firewall rules

## Architecture

```
flowtrack/
├── src/
│   ├── core/
│   │   ├── security_monitor.py    # Security monitoring and threat detection
│   │   ├── system_monitor.py      # System resource monitoring
│   │   └── packet_sniffer.py      # Network packet capture
│   ├── gui/
│   │   └── main_window.py         # GUI implementation
│   └── utils/
│       └── alert_manager.py       # Alert handling and notifications
├── config/                        # Configuration files
├── logs/                          # Application logs
├── main.py                        # Application entry point
└── requirements.txt               # Python dependencies
```

## Installation

### Prerequisites
- Python 3.8 or higher
- Administrator/root privileges (for packet sniffing and firewall rules)
- Nmap installed on system

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/flowtrack.git
cd flowtrack
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
# On Linux (requires sudo for packet sniffing)
sudo python3 main.py

# On Windows (run as Administrator)
python main.py
```

## Usage

### System Monitoring
- View real-time CPU, memory, disk, and network statistics
- Monitor system performance metrics

### Network Scanning
- Scan network ranges for open ports
- Identify potentially dangerous services
- Close vulnerable ports via firewall

### Packet Sniffing
- Capture and analyze network traffic in real-time
- Detect suspicious patterns
- Monitor specific protocols (TCP, UDP, ICMP)

### DDoS Detection
- Automatic detection of connection flooding
- Configurable threshold (default: 100 connections/minute)
- Automatic IP blocking for attackers

## Technology Stack

- **Language**: Python 3.8+
- **GUI Framework**: Tkinter
- **Networking**: Scapy
- **Port Scanning**: Python-nmap
- **System Monitoring**: psutil

## Security Features

- Real-time DDoS attack detection and prevention
- Automatic malicious IP blocking
- Port vulnerability scanning
- Network traffic analysis
- Firewall rule management

## Requirements

- **Python Packages**: Listed in `requirements.txt`
- **System Tools**: 
  - Nmap (for port scanning)
  - iptables (Linux) or Windows Firewall
  - WinPcap/Npcap (Windows, for packet capture)

## Limitations

- Requires administrator/root privileges for full functionality
- Packet sniffing depends on network interface capabilities
- Firewall modifications may require system permissions

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues.

## License

MIT License

## Author

Badr-Eddine NAJIM

## Acknowledgments

- Built as a Projet de Fin d'Année (PFA) at EMSI Tanger
- Uses open-source libraries: Scapy, python-nmap, psutil
