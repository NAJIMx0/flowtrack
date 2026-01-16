"""
Packet Sniffer Module
Handles network packet capture and analysis
"""
import threading
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketSniffer:
    """Network packet sniffer and analyzer"""
    
    def __init__(self, packet_callback=None, ddos_callback=None):
        self.is_sniffing = False
        self.sniff_thread = None
        self.packet_callback = packet_callback
        self.ddos_callback = ddos_callback
        self.security_monitor = None

    def set_security_monitor(self, monitor):
        """Set the security monitor for DDoS detection"""
        self.security_monitor = monitor

    def start_sniffing(self, interface):
        """Start packet sniffing on specified interface"""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy not available. Install with: pip install scapy")
        
        if self.is_sniffing:
            return
        
        self.is_sniffing = True
        
        def packet_handler(packet):
            if not self.is_sniffing:
                return
            
            try:
                if IP in packet:
                    packet_info = self._parse_packet(packet)
                    
                    # Check for DDoS if security monitor is set
                    if self.security_monitor and self.security_monitor.detect_ddos(packet):
                        if self.ddos_callback:
                            self.ddos_callback(packet[IP].src)
                    
                    # Call packet callback if set
                    if self.packet_callback:
                        self.packet_callback(packet_info)
                        
            except Exception as e:
                print(f"Packet processing error: {e}")

        def sniff_thread():
            try:
                sniff(iface=interface, prn=packet_handler, store=0, 
                      stop_filter=lambda x: not self.is_sniffing)
            except Exception as e:
                print(f"Sniffing error: {e}")
                self.is_sniffing = False

        self.sniff_thread = threading.Thread(target=sniff_thread, daemon=True)
        self.sniff_thread.start()

    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.is_sniffing = False

    def _parse_packet(self, packet):
        """Parse packet information"""
        current_time = datetime.now().strftime("%H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        protocol = "Unknown"
        info = ""
        
        if TCP in packet:
            protocol = "TCP"
            info = f"Port {packet[TCP].dport}"
        elif UDP in packet:
            protocol = "UDP"
            info = f"Port {packet[UDP].dport}"
        elif ICMP in packet:
            protocol = "ICMP"
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            info = f"Type {icmp_type}, Code {icmp_code}"
        
        return {
            'time': current_time,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'info': info
        }

    @staticmethod
    def get_network_interfaces():
        """Get list of available network interfaces"""
        if SCAPY_AVAILABLE:
            return get_if_list()
        return []
