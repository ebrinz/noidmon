#!/usr/bin/env python3
import rumps
import sqlite3
import os
import time

class MonitorStatusBarApp(rumps.App):
    def __init__(self):
        super(MonitorStatusBarApp, self).__init__("🔒", quit_button=None)
        self.menu = ["Status: All Clear", None, "View Recent Alerts", "Generate Report", None, "Quit"]
        self.db_path = os.path.expanduser("~/gits/noidmon/monitor.db")
        self.timer = rumps.Timer(self.check_alerts, 60)
        self.timer.start()
        
    @rumps.clicked("View Recent Alerts")
    def view_alerts(self, _):
        alerts = self.get_recent_alerts()
        if alerts:
            alert_text = "\n".join(alerts)
            rumps.alert("Recent Alerts", alert_text)
        else:
            rumps.alert("No Recent Alerts", "No alerts detected in the last 24 hours")
            
    @rumps.clicked("Generate Report")
    def generate_report(self, _):
        os.system("cd ~/gits/noidmon && bash -c 'source monitor_env/bin/activate && python simple-report.py'")
        rumps.alert("Report Generated", "Check your noidmon directory for the latest report file")
    
    @rumps.clicked("Quit")
    def quit(self, _):
        rumps.quit_application()
        
    def check_alerts(self, _):
        alert_count = self.get_alert_count()
        if alert_count > 0:
            self.title = "⚠️"
            self.menu["Status: All Clear"].title = f"Status: {alert_count} Recent Alerts"
        else:
            self.title = "🔒"
            self.menu["Status: All Clear"].title = "Status: All Clear"
    
    def get_alert_count(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp > datetime('now', '-24 hours')")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception:
            return 0
            
    def get_recent_alerts(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, severity, description FROM alerts WHERE timestamp > datetime('now', '-24 hours') ORDER BY timestamp DESC LIMIT 10")
            alerts = [f"{row[0]} [{row[1]}] {row[2]}" for row in cursor.fetchall()]
            conn.close()
            return alerts
        except Exception:
            return []

if __name__ == "__main__":
    MonitorStatusBarApp().run()
