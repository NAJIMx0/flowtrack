"""
FlowTrack Main Window
GUI implementation for the network security monitor
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import platform
import os
import json
from datetime import datetime

# Import core modules
from core.security_monitor import SecurityMonitor
from core.system_monitor import SystemMonitor
from core.packet_sniffer import PacketSniffer
from utils.alert_manager import AlertManager

# Import psutil for system monitoring
import psutil

# Import scapy components
try:
    from scapy.all import IP, TCP, UDP, ICMP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Import nmap
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


class FlowTrackApp:
    """Main application window for FlowTrack"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("FlowTrack - Advanced Network Security Monitor")
        self.root.geometry("1000x700")
        
        # Initialize core components
        self.security_monitor = SecurityMonitor()
        self.system_monitor = SystemMonitor()
        self.alert_manager = AlertManager()
        self.packet_sniffer = PacketSniffer(
            packet_callback=self.on_packet_received,
            ddos_callback=self.on_ddos_detected
        )
        self.packet_sniffer.set_security_monitor(self.security_monitor)
        
        # UI state
        self.packet_sniffing = False
        
        # Create UI
        self.create_tabs()
        self.setup_menu()
        
        # Start updates
        self.update_data()
        self.check_system_alerts()
    
    def create_tabs(self):
        """Create the main tab interface"""
        self.tab_control = ttk.Notebook(self.root)
        
        # Create tabs
        self.processes_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.processes_tab, text="Processes")
        self.setup_processes_tab()
        
        self.performance_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.performance_tab, text="Performance")
        self.setup_performance_tab()
        
        self.security_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.security_tab, text="Security")
        self.setup_security_tab()
        
        self.network_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.network_tab, text="Network Scan")
        self.setup_network_tab()
        
        self.alerts_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.alerts_tab, text="Alerts")
        self.setup_alerts_tab()
        
        self.tab_control.pack(expand=1, fill="both")
    
    def setup_menu(self):
        """Setup the application menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Run New Task", command=self.run_new_task)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Security menu
        security_menu = tk.Menu(menubar, tearoff=0)
        security_menu.add_command(label="Start Packet Sniffing", command=self.start_packet_sniffing)
        security_menu.add_command(label="Stop Packet Sniffing", command=self.stop_packet_sniffing)
        security_menu.add_separator()
        security_menu.add_command(label="Scan Network", command=self.scan_network)
        menubar.add_cascade(label="Security", menu=security_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def setup_processes_tab(self):
        """Setup the processes monitoring tab"""
        # Search frame
        search_frame = ttk.Frame(self.processes_tab)
        search_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side="left", padx=5)
        self.search_entry = ttk.Entry(search_frame)
        self.search_entry.pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(search_frame, text="Search", command=self.search_processes).pack(side="left", padx=5)
        
        # Button frame
        button_frame = ttk.Frame(self.processes_tab)
        button_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(button_frame, text="End Task", command=self.end_task).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Refresh", command=self.refresh_processes).pack(side="left", padx=5)
        
        # Processes tree
        columns = ("PID", "Name", "CPU %", "Memory (MB)", "Status")
        self.processes_tree = ttk.Treeview(self.processes_tab, columns=columns, show="headings")
        
        for col in columns:
            self.processes_tree.heading(col, text=col)
            self.processes_tree.column(col, width=120, anchor="center")
        
        scrollbar = ttk.Scrollbar(self.processes_tab, orient="vertical", command=self.processes_tree.yview)
        self.processes_tree.configure(yscrollcommand=scrollbar.set)
        self.processes_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar.pack(side="right", fill="y", pady=5)
        
        self.refresh_processes()
    
    def setup_performance_tab(self):
        """Setup the performance monitoring tab"""
        perf_notebook = ttk.Notebook(self.performance_tab)
        
        # CPU Tab
        cpu_frame = ttk.Frame(perf_notebook)
        perf_notebook.add(cpu_frame, text="CPU")
        
        cpu_usage_frame = ttk.LabelFrame(cpu_frame, text="CPU Usage")
        cpu_usage_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.cpu_label = ttk.Label(cpu_usage_frame, text="0%", font=("Arial", 24))
        self.cpu_label.pack(pady=20)
        
        cpu_info_frame = ttk.LabelFrame(cpu_frame, text="CPU Information")
        cpu_info_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        ttk.Label(cpu_info_frame, text="Cores:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.cpu_cores_label = ttk.Label(cpu_info_frame,
                                         text=f"{psutil.cpu_count(logical=False)} Physical, {psutil.cpu_count(logical=True)} Logical")
        self.cpu_cores_label.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        
        ttk.Label(cpu_info_frame, text="Model:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        cpu_info = platform.processor()
        self.cpu_model_label = ttk.Label(cpu_info_frame, text=cpu_info)
        self.cpu_model_label.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        
        # Memory Tab
        memory_frame = ttk.Frame(perf_notebook)
        perf_notebook.add(memory_frame, text="RAM")
        
        memory_usage_frame = ttk.LabelFrame(memory_frame, text="Memory Usage")
        memory_usage_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.memory_label = ttk.Label(memory_usage_frame, text="0%", font=("Arial", 24))
        self.memory_label.pack(pady=20)
        
        memory_info_frame = ttk.LabelFrame(memory_frame, text="Memory Information")
        memory_info_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        ttk.Label(memory_info_frame, text="Total:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.memory_total_label = ttk.Label(memory_info_frame, text="0 GB")
        self.memory_total_label.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        
        ttk.Label(memory_info_frame, text="Used:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.memory_used_label = ttk.Label(memory_info_frame, text="0 GB")
        self.memory_used_label.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        
        ttk.Label(memory_info_frame, text="Available:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.memory_avail_label = ttk.Label(memory_info_frame, text="0 GB")
        self.memory_avail_label.grid(row=2, column=1, sticky="w", padx=5, pady=2)
        
        # Disk Tab
        disk_frame = ttk.Frame(perf_notebook)
        perf_notebook.add(disk_frame, text="Disk")
        
        disk_usage_frame = ttk.LabelFrame(disk_frame, text="Disk Usage")
        disk_usage_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        columns = ("Drive", "Total", "Used", "Free", "Percent Used")
        self.disk_tree = ttk.Treeview(disk_usage_frame, columns=columns, show="headings", height=5)
        
        for col in columns:
            self.disk_tree.heading(col, text=col)
            self.disk_tree.column(col, width=100, anchor="center")
        
        self.disk_tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Network Tab
        network_frame = ttk.Frame(perf_notebook)
        perf_notebook.add(network_frame, text="Network")
        
        network_info_frame = ttk.LabelFrame(network_frame, text="Network Information")
        network_info_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        ttk.Label(network_info_frame, text="Sent:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.network_sent_label = ttk.Label(network_info_frame, text="0 KB/s")
        self.network_sent_label.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        
        ttk.Label(network_info_frame, text="Received:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.network_recv_label = ttk.Label(network_info_frame, text="0 KB/s")
        self.network_recv_label.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        
        perf_notebook.pack(fill="both", expand=True)
    
    def setup_security_tab(self):
        """Setup the security monitoring tab"""
        # DDoS Protection Frame
        ddos_frame = ttk.LabelFrame(self.security_tab, text="DDoS Protection")
        ddos_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(ddos_frame, text="Threshold (connections/min):").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.ddos_threshold_var = tk.StringVar(value=str(self.security_monitor.ddos_threshold))
        threshold_entry = ttk.Entry(ddos_frame, textvariable=self.ddos_threshold_var, width=10)
        threshold_entry.grid(row=0, column=1, padx=5, pady=2)
        ttk.Button(ddos_frame, text="Update", command=self.update_ddos_threshold).grid(row=0, column=2, padx=5, pady=2)
        
        ttk.Label(ddos_frame, text="Blocked IPs:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.blocked_ips_label = ttk.Label(ddos_frame, text="None")
        self.blocked_ips_label.grid(row=1, column=1, columnspan=2, sticky="w", padx=5, pady=2)
        
        # Packet Sniffing Frame
        sniff_frame = ttk.LabelFrame(self.security_tab, text="Packet Sniffing")
        sniff_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        control_frame = ttk.Frame(sniff_frame)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        self.sniff_button = ttk.Button(control_frame, text="Start Sniffing", command=self.toggle_packet_sniffing)
        self.sniff_button.pack(side="left", padx=5)
        
        ttk.Label(control_frame, text="Interface:").pack(side="left", padx=5)
        self.interface_var = tk.StringVar()
        interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, width=15)
        if SCAPY_AVAILABLE:
            interface_combo['values'] = get_if_list()
            if interface_combo['values']:
                interface_combo.current(0)
        interface_combo.pack(side="left", padx=5)
        
        # Packet display
        columns = ("Time", "Source", "Destination", "Protocol", "Info")
        self.packet_tree = ttk.Treeview(sniff_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=120, anchor="center")
        
        packet_scrollbar = ttk.Scrollbar(sniff_frame, orient="vertical", command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=packet_scrollbar.set)
        self.packet_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        packet_scrollbar.pack(side="right", fill="y", pady=5)
    
    def setup_network_tab(self):
        """Setup the network scanning tab"""
        # Scan controls
        scan_frame = ttk.LabelFrame(self.network_tab, text="Network Scan")
        scan_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(scan_frame, text="Target:").grid(row=0, column=0, sticky="w", padx=5, pady=2)
        self.target_var = tk.StringVar(value="127.0.0.1")
        target_entry = ttk.Entry(scan_frame, textvariable=self.target_var, width=15)
        target_entry.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(scan_frame, text="Port Range:").grid(row=0, column=2, sticky="w", padx=5, pady=2)
        self.port_range_var = tk.StringVar(value="1-1000")
        port_entry = ttk.Entry(scan_frame, textvariable=self.port_range_var, width=15)
        port_entry.grid(row=0, column=3, padx=5, pady=2)
        
        ttk.Button(scan_frame, text="Scan", command=self.scan_network).grid(row=0, column=4, padx=5, pady=2)
        
        # Results display
        results_frame = ttk.LabelFrame(self.network_tab, text="Scan Results")
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("Host", "Port", "State", "Service", "Risk Level")
        self.scan_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        
        for col in columns:
            self.scan_tree.heading(col, text=col)
            self.scan_tree.column(col, width=120, anchor="center")
        
        scan_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.scan_tree.yview)
        self.scan_tree.configure(yscrollcommand=scan_scrollbar.set)
        self.scan_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scan_scrollbar.pack(side="right", fill="y", pady=5)
        
        # Port control buttons
        button_frame = ttk.Frame(results_frame)
        button_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Close Selected Port", command=self.close_selected_port).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Refresh Scan", command=self.scan_network).pack(side="left", padx=5)
    
    def setup_alerts_tab(self):
        """Setup the alerts monitoring tab"""
        # Alerts display
        alerts_frame = ttk.LabelFrame(self.alerts_tab, text="Security Alerts")
        alerts_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("Time", "Type", "Severity", "Message", "Action")
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=columns, show="headings")
        
        for col in columns:
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=150, anchor="center")
        
        alerts_scrollbar = ttk.Scrollbar(alerts_frame, orient="vertical", command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=alerts_scrollbar.set)
        self.alerts_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        alerts_scrollbar.pack(side="right", fill="y", pady=5)
        
        # Alert controls
        control_frame = ttk.Frame(alerts_frame)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(control_frame, text="Clear Alerts", command=self.clear_alerts).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Export Alerts", command=self.export_alerts).pack(side="left", padx=5)
    
    # Process Management
    def search_processes(self):
        """Search for processes by name"""
        search_term = self.search_entry.get().lower()
        if not search_term:
            self.refresh_processes()
            return
        
        for item in self.processes_tree.get_children():
            self.processes_tree.delete(item)
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'status']):
            try:
                if search_term in proc.info['name'].lower():
                    mem_mb = proc.info['memory_info'].rss / (1024 * 1024)
                    self.processes_tree.insert("", "end", values=(
                        proc.info['pid'],
                        proc.info['name'],
                        f"{proc.info['cpu_percent']:.1f}%",
                        f"{mem_mb:.1f}",
                        proc.info['status']
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    
    def end_task(self):
        """End the selected process"""
        selected = self.processes_tree.selection()
        if not selected:
            return
        
        pid = int(self.processes_tree.item(selected[0])['values'][0])
        
        try:
            process = psutil.Process(pid)
            process_name = process.name()
            
            if messagebox.askyesno("Confirm", f"End process '{process_name}' (PID: {pid})?"):
                process.terminate()
                time.sleep(0.5)
                if process.is_running():
                    process.kill()
                messagebox.showinfo("Success", f"Process '{process_name}' ended")
                self.refresh_processes()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messagebox.showerror("Error", f"Failed to end process: {str(e)}")
    
    def refresh_processes(self):
        """Refresh the process list"""
        for item in self.processes_tree.get_children():
            self.processes_tree.delete(item)
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'status']):
            try:
                mem_mb = proc.info['memory_info'].rss / (1024 * 1024)
                processes.append((
                    proc.info['pid'],
                    proc.info['name'],
                    proc.info['cpu_percent'],
                    mem_mb,
                    proc.info['status']
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        processes.sort(key=lambda x: x[2], reverse=True)
        
        for proc in processes[:100]:
            self.processes_tree.insert("", "end", values=(
                proc[0],
                proc[1],
                f"{proc[2]:.1f}%",
                f"{proc[3]:.1f}",
                proc[4]
            ))
    
    def run_new_task(self):
        """Show dialog to run a new task"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Run New Task")
        dialog.geometry("300x150")
        
        ttk.Label(dialog, text="Enter program to run:").pack(padx=10, pady=10)
        entry = ttk.Entry(dialog, width=30)
        entry.pack(padx=10, pady=5)
        entry.focus_set()
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Run", command=lambda: self.run_command(entry.get(), dialog)).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side="left", padx=5)
    
    def run_command(self, command, dialog):
        """Execute a command"""
        dialog.destroy()
        if not command.strip():
            return
        
        try:
            if platform.system() == 'Windows':
                os.system(f'start {command}')
            else:
                os.system(f'{command} &')
            messagebox.showinfo("Success", f"Started: {command}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run: {str(e)}")
    
    # Data Updates
    def update_data(self):
        """Update all monitoring data"""
        try:
            # CPU
            cpu_info = self.system_monitor.get_cpu_info()
            self.cpu_label.config(text=f"{cpu_info['usage']}%")
            
            # Memory
            mem_info = self.system_monitor.get_memory_info()
            self.memory_label.config(text=f"{mem_info['percent']}%")
            self.memory_total_label.config(text=self.system_monitor.format_bytes(mem_info['total']))
            self.memory_used_label.config(text=self.system_monitor.format_bytes(mem_info['used']))
            self.memory_avail_label.config(text=self.system_monitor.format_bytes(mem_info['available']))
            
            # Disk
            for item in self.disk_tree.get_children():
                self.disk_tree.delete(item)
            
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    self.disk_tree.insert("", "end", values=(
                        part.device,
                        self.system_monitor.format_bytes(usage.total),
                        self.system_monitor.format_bytes(usage.used),
                        self.system_monitor.format_bytes(usage.free),
                        f"{usage.percent}%"
                    ))
                except PermissionError:
                    pass
            
            # Network
            net_info = self.system_monitor.get_network_info()
            self.network_sent_label.config(text=self.system_monitor.format_bytes(net_info['bytes_sent']))
            self.network_recv_label.config(text=self.system_monitor.format_bytes(net_info['bytes_recv']))
            
            # Blocked IPs
            blocked_ips_text = ", ".join(self.security_monitor.blocked_ips) if self.security_monitor.blocked_ips else "None"
            self.blocked_ips_label.config(text=blocked_ips_text)
            
        except Exception as e:
            print(f"Error updating data: {e}")
        
        self.root.after(1000, self.update_data)
    
    def check_system_alerts(self):
        """Check for system alerts"""
        try:
            # Check CPU usage
            for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent']):
                try:
                    if proc.info['status'] == psutil.STATUS_ZOMBIE:
                        self.add_alert("Process", "Medium",
                                     f"Zombie process detected: {proc.info['name']} (PID: {proc.info['pid']})",
                                     "Monitor")
                    
                    if proc.info['cpu_percent'] > 80:
                        self.add_alert("Performance", "High",
                                     f"High CPU usage: {proc.info['name']} using {proc.info['cpu_percent']:.1f}%",
                                     "Check Process")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Check memory
            mem = psutil.virtual_memory()
            if mem.percent > 90:
                self.add_alert("Memory", "Critical", f"Memory usage critical: {mem.percent}%", "Free Memory")
            elif mem.percent > 80:
                self.add_alert("Memory", "High", f"Memory usage high: {mem.percent}%", "Monitor")
            
            # Check disk
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    if usage.percent > 95:
                        self.add_alert("Disk", "Critical", f"Disk {part.device} almost full: {usage.percent}%", "Clean Disk")
                    elif usage.percent > 85:
                        self.add_alert("Disk", "High", f"Disk {part.device} getting full: {usage.percent}%", "Monitor")
                except PermissionError:
                    pass
        
        except Exception as e:
            print(f"Error checking alerts: {e}")
        
        self.root.after(30000, self.check_system_alerts)
    
    # Alert Management
    def add_alert(self, category, severity, message, action):
        """Add a new alert"""
        alert = self.alert_manager.add_alert(category, severity, message, action)
        self.update_alerts_display()
    
    def update_alerts_display(self):
        """Update the alerts display"""
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        for alert in self.alert_manager.get_all_alerts():
            tags = []
            if alert['severity'] == 'Critical':
                tags = ['critical']
            elif alert['severity'] == 'High':
                tags = ['high']
            elif alert['severity'] == 'Medium':
                tags = ['medium']
            
            self.alerts_tree.insert("", 0, values=(
                alert['timestamp'],
                alert['category'],
                alert['severity'],
                alert['message'],
                alert['action']
            ), tags=tags)
        
        self.alerts_tree.tag_configure('critical', background='#ffcccc')
        self.alerts_tree.tag_configure('high', background='#ffe6cc')
        self.alerts_tree.tag_configure('medium', background='#ffffcc')
    
    def clear_alerts(self):
        """Clear all alerts"""
        if messagebox.askyesno("Confirm", "Clear all alerts?"):
            self.alert_manager.clear_alerts()
            self.update_alerts_display()
    
    def export_alerts(self):
        """Export alerts to JSON file"""
        try:
            filename = self.alert_manager.export_to_json()
            messagebox.showinfo("Success", f"Alerts exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export alerts: {str(e)}")
    
    # Network Scanning
    def scan_network(self):
        """Scan network for open ports"""
        def scan_thread():
            try:
                target = self.target_var.get()
                port_range = self.port_range_var.get()
                
                print(f"Starting network scan of {target} ports {port_range}")
                
                # Clear previous results
                self.root.after(0, lambda: [self.scan_tree.delete(item) for item in self.scan_tree.get_children()])
                
                # Add scanning message
                self.root.after(0, lambda: self.scan_tree.insert("", "end", values=(
                    target, "Scanning...", "Please wait", "...", "..."
                )))
                
                open_ports = self.security_monitor.scan_network_ports(target, port_range)
                
                # Clear scanning message
                self.root.after(0, lambda: [self.scan_tree.delete(item) for item in self.scan_tree.get_children()])
                
                if not open_ports:
                    self.root.after(0, lambda: self.scan_tree.insert("", "end", values=(
                        target, "No open ports", "or host down", "N/A", "N/A"
                    )))
                else:
                    for port_info in open_ports:
                        risk_level = "High Risk" if port_info['dangerous'] else "Low Risk"
                        self.root.after(0, lambda pi=port_info, rl=risk_level: self.scan_tree.insert("", "end", values=(
                            pi['host'],
                            pi['port'],
                            pi['state'],
                            pi['service'],
                            rl
                        )))
                        
                        if port_info['dangerous']:
                            service_desc = self.security_monitor.dangerous_ports.get(port_info['port'], "Unknown service")
                            self.root.after(0, lambda pi=port_info, sd=service_desc: self.add_alert("Network", "High",
                                           f"Dangerous port {pi['port']} open on {pi['host']}: {sd}",
                                           "Consider Closing"))
                    
                    print(f"Scan completed. Found {len(open_ports)} open ports")
                    
            except Exception as e:
                print(f"Scan error: {e}")
                self.root.after(0, lambda: [self.scan_tree.delete(item) for item in self.scan_tree.get_children()])
                self.root.after(0, lambda: self.scan_tree.insert("", "end", values=(
                    target, "Error", str(e), "N/A", "N/A"
                )))
        
        if NMAP_AVAILABLE:
            threading.Thread(target=scan_thread, daemon=True).start()
        else:
            messagebox.showwarning("Warning", "Network scanning requires python-nmap")
    
    def close_selected_port(self):
        """Close selected port via firewall"""
        selected = self.scan_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a port to close")
            return
        
        port = int(self.scan_tree.item(selected[0])['values'][1])
        
        if messagebox.askyesno("Confirm", f"Close port {port}? This will add a firewall rule."):
            if self.security_monitor.close_port(port):
                messagebox.showinfo("Success", f"Port {port} has been blocked via firewall")
                self.add_alert("Security", "Medium", f"Port {port} closed via firewall rule", "Completed")
            else:
                messagebox.showerror("Error", f"Failed to close port {port}. May require administrator privileges.")
    
    # Packet Sniffing
    def start_packet_sniffing(self):
        """Start packet sniffing"""
        if not SCAPY_AVAILABLE:
            messagebox.showwarning("Warning", "Packet sniffing requires scapy. Install with: pip install scapy")
            return
        
        if self.packet_sniffing:
            return
        
        interface = self.interface_var.get()
        if not interface:
            messagebox.showwarning("Warning", "Please select a network interface")
            return
        
        self.packet_sniffing = True
        self.sniff_button.config(text="Stop Sniffing")
        
        try:
            self.packet_sniffer.start_sniffing(interface)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start sniffing: {e}")
            self.packet_sniffing = False
            self.sniff_button.config(text="Start Sniffing")
    
    def stop_packet_sniffing(self):
        """Stop packet sniffing"""
        self.packet_sniffing = False
        self.packet_sniffer.stop_sniffing()
        self.sniff_button.config(text="Start Sniffing")
    
    def toggle_packet_sniffing(self):
        """Toggle packet sniffing on/off"""
        if self.packet_sniffing:
            self.stop_packet_sniffing()
        else:
            self.start_packet_sniffing()
    
    def on_packet_received(self, packet_info):
        """Callback when packet is received"""
        # Limit packet display
        if len(self.packet_tree.get_children()) > 100:
            oldest = self.packet_tree.get_children()[0]
            self.packet_tree.delete(oldest)
        
        self.packet_tree.insert("", "end", values=(
            packet_info['time'],
            packet_info['src_ip'],
            packet_info['dst_ip'],
            packet_info['protocol'],
            packet_info['info']
        ))
    
    def on_ddos_detected(self, src_ip):
        """Callback when DDoS is detected"""
        self.add_alert("Security", "Critical", f"DDoS attack detected from {src_ip}", "IP Blocked")
    
    def update_ddos_threshold(self):
        """Update DDoS detection threshold"""
        try:
            new_threshold = int(self.ddos_threshold_var.get())
            self.security_monitor.ddos_threshold = new_threshold
            messagebox.showinfo("Success", f"DDoS threshold updated to {new_threshold} connections/minute")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for threshold")
    
    def show_about(self):
        """Show about dialog"""
        about = tk.Toplevel(self.root)
        about.title("About FlowTrack")
        about.geometry("350x200")
        
        ttk.Label(about, text="FlowTrack System Monitor", font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(about, text="Advanced Network Security Monitor").pack(pady=5)
        ttk.Label(about, text="Version 3.0.0 - Modular Architecture").pack(pady=5)
        ttk.Label(about, text="Built with Python, Scapy, and Tkinter").pack(pady=5)
        ttk.Button(about, text="OK", command=about.destroy).pack(pady=10)
    
    def run(self):
        """Run the application"""
        self.root.mainloop()
