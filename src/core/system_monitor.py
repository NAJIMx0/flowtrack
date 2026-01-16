"""
System Monitor Module
Handles system resource monitoring (CPU, Memory, Disk, Network)
"""
import psutil
import platform


class SystemMonitor:
    """Monitor system resources and performance metrics"""
    
    @staticmethod
    def get_cpu_info():
        """Get CPU usage information"""
        return {
            'usage': psutil.cpu_percent(interval=1),
            'count': psutil.cpu_count(),
            'frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 0
        }

    @staticmethod
    def get_memory_info():
        """Get memory usage information"""
        mem = psutil.virtual_memory()
        return {
            'total': mem.total,
            'available': mem.available,
            'used': mem.used,
            'percent': mem.percent
        }

    @staticmethod
    def get_disk_info():
        """Get disk usage information"""
        disk = psutil.disk_usage('/')
        return {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': disk.percent
        }

    @staticmethod
    def get_network_info():
        """Get network interface information"""
        net = psutil.net_io_counters()
        return {
            'bytes_sent': net.bytes_sent,
            'bytes_recv': net.bytes_recv,
            'packets_sent': net.packets_sent,
            'packets_recv': net.packets_recv
        }

    @staticmethod
    def get_system_info():
        """Get general system information"""
        return {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'hostname': platform.node(),
            'processor': platform.processor()
        }

    @staticmethod
    def format_bytes(bytes_value):
        """Format bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
