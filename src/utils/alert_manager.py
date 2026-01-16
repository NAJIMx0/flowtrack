"""
Alert Manager Module
Handles security alerts and notifications
"""
import json
from datetime import datetime
from typing import List, Dict


class AlertManager:
    """Manage security alerts and notifications"""
    
    SEVERITY_LEVELS = ["Low", "Medium", "High", "Critical"]
    CATEGORIES = ["System", "Network", "Security", "Performance"]
    
    def __init__(self):
        self.alerts: List[Dict] = []
        self.max_alerts = 1000

    def add_alert(self, category: str, severity: str, message: str, action: str = "Pending"):
        """Add a new alert"""
        alert = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'category': category,
            'severity': severity,
            'message': message,
            'action': action
        }
        
        self.alerts.insert(0, alert)  # Add to beginning
        
        # Limit alerts to max_alerts
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[:self.max_alerts]
        
        return alert

    def get_all_alerts(self) -> List[Dict]:
        """Get all alerts"""
        return self.alerts

    def get_alerts_by_severity(self, severity: str) -> List[Dict]:
        """Get alerts filtered by severity"""
        return [alert for alert in self.alerts if alert['severity'] == severity]

    def get_alerts_by_category(self, category: str) -> List[Dict]:
        """Get alerts filtered by category"""
        return [alert for alert in self.alerts if alert['category'] == category]

    def clear_alerts(self):
        """Clear all alerts"""
        self.alerts.clear()

    def export_to_json(self, filename: str = None):
        """Export alerts to JSON file"""
        if filename is None:
            filename = f"flowtrack_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.alerts, f, indent=2)
        
        return filename

    def get_alert_statistics(self) -> Dict:
        """Get alert statistics"""
        stats = {
            'total': len(self.alerts),
            'by_severity': {},
            'by_category': {}
        }
        
        for severity in self.SEVERITY_LEVELS:
            stats['by_severity'][severity] = len(self.get_alerts_by_severity(severity))
        
        for category in self.CATEGORIES:
            stats['by_category'][category] = len(self.get_alerts_by_category(category))
        
        return stats
