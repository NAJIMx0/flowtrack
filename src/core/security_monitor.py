"""
Security Monitor Module
Handles network security monitoring, DDoS detection, and IP blocking
"""
import platform
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timedelta

try:
    from scapy.all import IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


class SecurityMonitor:
    """Main security monitoring class for network threat detection"""
    
    def __init__(self):
        self.dangerous_ports = {
            21: "FTP - File Transfer Protocol",
            22: "SSH - Secure Shell",
            23: "Telnet - Unencrypted text communications",
            25: "SMTP - Simple Mail Transfer Protocol",
            53: "DNS - Domain Name System",
            80: "HTTP - Hypertext Transfer Protocol",
            110: "POP3 - Post Office Protocol",
            135: "RPC - Remote Procedure Call",
            139: "NetBIOS - Network Basic Input/Output System",
            143: "IMAP - Internet Message Access Protocol",
            443: "HTTPS - HTTP Secure",
            445: "SMB - Server Message Block",
            993: "IMAPS - IMAP over SSL",
            995: "POP3S - POP3 over SSL",
            1433: "MSSQL - Microsoft SQL Server",
            1521: "Oracle Database",
            3306: "MySQL Database",
            3389: "RDP - Remote Desktop Protocol",
            5432: "PostgreSQL Database",
            5900: "VNC - Virtual Network Computing"
        }
        
        self.connection_counts = defaultdict(int)
        self.connection_times = defaultdict(deque)
        self.ddos_threshold = 100  # connections per minute
        self.blocked_ips = set()

    def scan_network_ports(self, target="127.0.0.1", port_range="1-1000"):
        """Scan network ports using nmap"""
        if not NMAP_AVAILABLE:
            return []
        try:
            nm = nmap.PortScanner()
            print(f"Scanning {target} ports {port_range}...")
            
            result = nm.scan(target, port_range, arguments='-sT -T4')
            print(f"Scan completed. Hosts found: {list(result['scan'].keys())}")
            
            open_ports = []
            
            if not result['scan']:
                print(f"No hosts found or host {target} is down")
                ping_result = nm.scan(target, arguments='-sn')
                if target in ping_result['scan'] and ping_result['scan'][target]['status']['state'] == 'up':
                    print(f"Host {target} is up but no open ports found in range {port_range}")
                else:
                    print(f"Host {target} appears to be down or unreachable")
                return []
            
            for host in result['scan']:
                host_info = result['scan'][host]
                print(f"Processing host: {host}")
                print(f"Host state: {host_info.get('status', {}).get('state', 'unknown')}")
                
                if 'tcp' in host_info:
                    print(f"TCP ports found: {len(host_info['tcp'])}")
                    for port in host_info['tcp']:
                        port_info = host_info['tcp'][port]
                        if port_info['state'] == 'open':
                            port_data = {
                                'host': host,
                                'port': port,
                                'state': port_info['state'],
                                'service': port_info.get('name', 'unknown'),
                                'dangerous': port in self.dangerous_ports
                            }
                            open_ports.append(port_data)
                            print(f"Open port found: {port} - {port_info.get('name', 'unknown')}")
                
                if 'udp' in host_info:
                    print(f"UDP ports found: {len(host_info['udp'])}")
                    for port in host_info['udp']:
                        port_info = host_info['udp'][port]
                        if port_info['state'] == 'open':
                            port_data = {
                                'host': host,
                                'port': port,
                                'state': port_info['state'],
                                'service': port_info.get('name', 'unknown'),
                                'dangerous': port in self.dangerous_ports
                            }
                            open_ports.append(port_data)
                            print(f"Open UDP port found: {port} - {port_info.get('name', 'unknown')}")
            
            print(f"Total open ports found: {len(open_ports)}")
            return open_ports
            
        except Exception as e:
            print(f"Port scan error: {e}")
            print(f"Error type: {type(e).__name__}")
            import traceback
            traceback.print_exc()
            return []

    def close_port(self, port):
        """Attempt to close a port using firewall rules"""
        try:
            system = platform.system()
            if system == "Windows":
                cmd = f'netsh advfirewall firewall add rule name="Block_Port_{port}" dir=in action=block protocol=TCP localport={port}'
                subprocess.run(cmd, shell=True, check=True)
                return True
            elif system == "Linux":
                cmd = f'sudo iptables -A INPUT -p tcp --dport {port} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
                return True
            else:
                return False
        except Exception as e:
            print(f"Error closing port {port}: {e}")
            return False

    def detect_ddos(self, packet):
        """Detect potential DDoS attacks"""
        if SCAPY_AVAILABLE and IP in packet:
            src_ip = packet[IP].src
            current_time = datetime.now()

            # Clean old entries (older than 1 minute)
            cutoff_time = current_time - timedelta(minutes=1)
            while self.connection_times[src_ip] and self.connection_times[src_ip][0] < cutoff_time:
                self.connection_times[src_ip].popleft()

            # Add current connection
            self.connection_times[src_ip].append(current_time)

            # Check if threshold exceeded
            if len(self.connection_times[src_ip]) > self.ddos_threshold:
                if src_ip not in self.blocked_ips:
                    self.blocked_ips.add(src_ip)
                    self.block_ip(src_ip)
                    return True
        return False

    def block_ip(self, ip):
        """Block an IP address using firewall rules"""
        try:
            system = platform.system()
            if system == "Windows":
                cmd = f'netsh advfirewall firewall add rule name="Block_IP_{ip}" dir=in action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, check=True)
                return True
            elif system == "Linux":
                cmd = f'sudo iptables -A INPUT -s {ip} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
                return True
            else:
                return False
        except Exception as e:
            print(f"Error blocking IP {ip}: {e}")
            return False

    def unblock_ip(self, ip):
        """Unblock a previously blocked IP address"""
        try:
            system = platform.system()
            if system == "Windows":
                cmd = f'netsh advfirewall firewall delete rule name="Block_IP_{ip}"'
                subprocess.run(cmd, shell=True, check=True)
                return True
            elif system == "Linux":
                cmd = f'sudo iptables -D INPUT -s {ip} -j DROP'
                subprocess.run(cmd, shell=True, check=True)
                return True
            else:
                return False
        except Exception as e:
            print(f"Error unblocking IP {ip}: {e}")
            return False
