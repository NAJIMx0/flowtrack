# FlowTrack Project Restructuring Guide

## Original Issue
- Single monolithic file (main_flowtrack.py) with 900+ lines
- Poor code organization and maintainability
- Not suitable for version control (GitHub)
- Difficult to test and extend

## New Architecture

### Directory Structure
```
flowtrack/
├── main.py                        # Application entry point
├── requirements.txt               # Dependencies
├── README.md                      # Documentation
├── .gitignore                    # Git ignore rules
├── src/
│   ├── core/                     # Core functionality
│   │   ├── __init__.py
│   │   ├── security_monitor.py   # Security & DDoS detection
│   │   ├── system_monitor.py     # System resource monitoring  
│   │   └── packet_sniffer.py     # Network packet capture
│   ├── gui/                      # User interface
│   │   ├── __init__.py
│   │   └── main_window.py        # Main GUI (to be created from original)
│   └── utils/                    # Utilities
│       ├── __init__.py
│       └── alert_manager.py      # Alert handling
├── config/                       # Configuration files
└── logs/                         # Application logs
```

## Modules Created

### 1. security_monitor.py
- Port scanning with nmap
- DDoS attack detection
- IP blocking/unblocking
- Firewall integration
- Dangerous port database

### 2. system_monitor.py
- CPU monitoring
- Memory tracking
- Disk usage
- Network statistics
- System information

### 3. packet_sniffer.py
- Network packet capture
- Protocol analysis (TCP/UDP/ICMP)
- Real-time packet parsing
- Integration with security monitor

### 4. alert_manager.py
- Alert creation and storage
- Severity classification
- Category filtering
- JSON export functionality
- Alert statistics

## Benefits of New Structure

1. **Modularity**: Each component has a single responsibility
2. **Testability**: Individual modules can be tested independently
3. **Maintainability**: Easy to locate and modify specific functionality
4. **Scalability**: Easy to add new features without breaking existing code
5. **Version Control**: Clean Git history with logical commits
6. **Collaboration**: Multiple developers can work on different modules
7. **Documentation**: Clear structure makes documentation easier

## Next Steps

1. Copy GUI code from original file to `src/gui/main_window.py`
2. Update imports in GUI to use new modular structure
3. Test each module independently
4. Create unit tests
5. Push to GitHub

## Updated CV Description

**FlowTrack – Advanced Network Security Monitor (PFA)**

• Développement d'une application de surveillance réseau en Python avec architecture modulaire (MVC pattern)
• Détection et prévention des attaques DDoS avec blocage automatique des IP malveillantes
• Scan automatisé des ports avec python-nmap et analyse des vulnérabilités
• Capture et analyse de paquets réseau en temps réel avec Scapy (TCP/UDP/ICMP)
• Monitoring des ressources système (CPU, RAM, disque, réseau) avec psutil
• Interface graphique Tkinter avec système d'alertes catégorisées par sévérité
• Technologies : Python, Scapy, python-nmap, psutil, Tkinter, threading, iptables/Windows Firewall
