def network_monitoring_process(db_path, config=None):
    """Standalone function to run network monitoring in a separate process."""
    try:
        # Create a new database connection in this process
        config = config or {}
        db_manager = DatabaseManager(db_path)
        network_monitor = NetworkMonitor(db_manager)
        
        # Set up logging for this process
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("network_monitor.log"),
                logging.StreamHandler(sys.stdout)
            ]
        )
        logger = logging.getLogger("network-monitor")
        
        logger.info("Network monitoring process started.")
        network_monitor.start_sniffing()
    except Exception as e:
        logging.error(f"Error in network monitoring process: {e}")
        sys.exit(1)

"""
macOS Process and Network Monitor
================================
A monitoring agent that tracks system processes and network traffic,
detecting unusual patterns and potential security threats.
"""

import os
import sys
import time
import json
import signal
import logging
import sqlite3
import psutil
import argparse
import subprocess
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import IsolationForest
from collections import defaultdict, Counter

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("monitor.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("macos-monitor")

class DatabaseManager:
    """Manages database operations for storing and retrieving monitoring data."""
    
    def __init__(self, db_path="monitor.db"):
        """Initialize the database connection and tables."""
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self._create_tables()
        
    def _create_tables(self):
        """Create necessary tables if they don't exist."""
        # Process table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            pid INTEGER,
            name TEXT,
            username TEXT,
            cpu_percent REAL,
            memory_percent REAL,
            cmdline TEXT,
            connections INTEGER,
            status TEXT
        )
        ''')
        
        # Network table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            packet_size INTEGER,
            process_pid INTEGER,
            process_name TEXT
        )
        ''')
        
        # Alerts table
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            severity TEXT,
            description TEXT,
            process_pid INTEGER,
            process_name TEXT,
            source_ip TEXT,
            destination_ip TEXT
        )
        ''')
        
        self.conn.commit()
    
    def store_process_data(self, process_data):
        """Store process monitoring data."""
        self.cursor.execute('''
        INSERT INTO processes (
            timestamp, pid, name, username, cpu_percent, 
            memory_percent, cmdline, connections, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            process_data["timestamp"],
            process_data["pid"],
            process_data["name"],
            process_data["username"],
            process_data["cpu_percent"],
            process_data["memory_percent"],
            process_data["cmdline"],
            process_data["connections"],
            process_data["status"]
        ))
        self.conn.commit()
    
    def store_network_data(self, network_data):
        """Store network traffic data."""
        self.cursor.execute('''
        INSERT INTO network_traffic (
            timestamp, src_ip, dst_ip, src_port, dst_port,
            protocol, packet_size, process_pid, process_name
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            network_data["timestamp"],
            network_data["src_ip"],
            network_data["dst_ip"],
            network_data["src_port"],
            network_data["dst_port"],
            network_data["protocol"],
            network_data["packet_size"],
            network_data["process_pid"],
            network_data["process_name"]
        ))
        self.conn.commit()
    
    def store_alert(self, alert_data):
        """Store alert information."""
        self.cursor.execute('''
        INSERT INTO alerts (
            timestamp, alert_type, severity, description,
            process_pid, process_name, source_ip, destination_ip
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert_data["timestamp"],
            alert_data["alert_type"],
            alert_data["severity"],
            alert_data["description"],
            alert_data["process_pid"],
            alert_data["process_name"],
            alert_data["source_ip"],
            alert_data["destination_ip"]
        ))
        self.conn.commit()
        
    def get_process_history(self, pid=None, hours=24):
        """Get process history for the specified pid or all processes."""
        time_threshold = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        if pid:
            self.cursor.execute('''
            SELECT * FROM processes 
            WHERE pid = ? AND timestamp > ?
            ORDER BY timestamp DESC
            ''', (pid, time_threshold))
        else:
            self.cursor.execute('''
            SELECT * FROM processes 
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            ''', (time_threshold,))
            
        columns = [description[0] for description in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
    
    def get_network_history(self, process_name=None, hours=24):
        """Get network history for the specified process or all traffic."""
        time_threshold = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        if process_name:
            self.cursor.execute('''
            SELECT * FROM network_traffic 
            WHERE process_name = ? AND timestamp > ?
            ORDER BY timestamp DESC
            ''', (process_name, time_threshold))
        else:
            self.cursor.execute('''
            SELECT * FROM network_traffic 
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            ''', (time_threshold,))
            
        columns = [description[0] for description in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
    
    def get_alerts(self, severity=None, hours=24):
        """Get alerts filtered by severity and time."""
        time_threshold = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        if severity:
            self.cursor.execute('''
            SELECT * FROM alerts 
            WHERE severity = ? AND timestamp > ?
            ORDER BY timestamp DESC
            ''', (severity, time_threshold))
        else:
            self.cursor.execute('''
            SELECT * FROM alerts 
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            ''', (time_threshold,))
            
        columns = [description[0] for description in self.cursor.description]
        return [dict(zip(columns, row)) for row in self.cursor.fetchall()]
    
    def close(self):
        """Close the database connection."""
        self.conn.close()


class ProcessMonitor:
    """Monitors system processes and identifies unusual behavior."""
    
    def __init__(self, db_manager):
        """Initialize the process monitor."""
        self.db_manager = db_manager
        self.process_baseline = {}
        self.anomaly_detector = IsolationForest(contamination=0.05)
        self.training_data = []
        
    def collect_process_data(self):
        """Collect current process information."""
        process_list = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 
                                        'cpu_percent', 'memory_percent', 
                                        'cmdline', 'connections', 'status']):
            try:
                pinfo = proc.info
                connection_count = len(pinfo['connections']) if pinfo['connections'] else 0
                cmdline = " ".join(pinfo['cmdline']) if pinfo['cmdline'] else ""
                
                process_data = {
                    "timestamp": datetime.now().isoformat(),
                    "pid": pinfo['pid'],
                    "name": pinfo['name'],
                    "username": pinfo['username'],
                    "cpu_percent": pinfo['cpu_percent'],
                    "memory_percent": pinfo['memory_percent'],
                    "cmdline": cmdline,
                    "connections": connection_count,
                    "status": pinfo['status']
                }
                
                process_list.append(process_data)
                self.db_manager.store_process_data(process_data)
                
                # Add data for anomaly detection
                self.training_data.append([
                    pinfo['cpu_percent'], 
                    pinfo['memory_percent'],
                    connection_count
                ])
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        return process_list
    
    def train_anomaly_detector(self):
        """Train the anomaly detection model on collected process data."""
        if len(self.training_data) > 100:  # Wait until we have enough data
            logger.info("Training anomaly detection model on process data...")
            training_array = np.array(self.training_data)
            self.anomaly_detector.fit(training_array)
            logger.info("Anomaly detection model trained.")
    
    def detect_anomalies(self, processes):
        """Detect anomalous process behavior."""
        if not hasattr(self.anomaly_detector, "offset_"):
            return []  # Model not trained yet
            
        anomalies = []
        process_features = []
        
        for proc in processes:
            features = [
                proc['cpu_percent'],
                proc['memory_percent'],
                proc['connections']
            ]
            process_features.append(features)
        
        if not process_features:
            return []
            
        predictions = self.anomaly_detector.predict(np.array(process_features))
        
        for i, pred in enumerate(predictions):
            if pred == -1:  # Anomaly detected
                proc = processes[i]
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "alert_type": "process_anomaly",
                    "severity": "medium",
                    "description": f"Unusual behavior detected for process {proc['name']} (PID: {proc['pid']})",
                    "process_pid": proc['pid'],
                    "process_name": proc['name'],
                    "source_ip": "",
                    "destination_ip": ""
                }
                self.db_manager.store_alert(alert)
                anomalies.append(alert)
                logger.warning(f"Process anomaly: {alert['description']}")
                
        return anomalies


class NetworkMonitor:
    """Monitors network traffic and identifies unusual patterns."""
    
    def __init__(self, db_manager):
        """Initialize the network monitor."""
        self.db_manager = db_manager
        self.packet_count = 0
        self.ip_connections = defaultdict(Counter)
        self.port_activity = defaultdict(Counter)
        self.suspicious_ips = set()
        self.known_services = {
            80: "HTTP",
            443: "HTTPS",
            22: "SSH",
            53: "DNS",
            123: "NTP",
            25: "SMTP",
            587: "SMTP",
            110: "POP3",
            143: "IMAP",
            3306: "MySQL",
            5432: "PostgreSQL"
        }
        
        # Load suspicious IP list (could be from threat intelligence feeds)
        self.load_suspicious_ips()
    
    def load_suspicious_ips(self, file_path="suspicious_ips.txt"):
        """Load known suspicious IPs from a file."""
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith('#'):
                            self.suspicious_ips.add(ip)
                logger.info(f"Loaded {len(self.suspicious_ips)} suspicious IPs")
        except Exception as e:
            logger.error(f"Error loading suspicious IPs: {e}")
    
    def packet_callback(self, packet):
        """Process a captured network packet."""
        self.packet_count += 1
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            
            # Get source and destination ports if available
            src_port = None
            dst_port = None
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            
            # Calculate packet size
            packet_size = len(packet)
            
            # Try to find the associated process for this connection
            process_pid = None
            process_name = None
            
            if src_port or dst_port:
                for proc in psutil.process_iter(['pid', 'name', 'connections']):
                    try:
                        connections = proc.connections()
                        for conn in connections:
                            if conn.status == 'ESTABLISHED' and (
                                (conn.laddr.port == src_port and conn.raddr.ip == dst_ip) or
                                (conn.laddr.port == dst_port and conn.raddr.ip == src_ip)
                            ):
                                process_pid = proc.pid
                                process_name = proc.name()
                                break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            
            # Store the network traffic data
            network_data = {
                "timestamp": datetime.now().isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port if src_port else 0,
                "dst_port": dst_port if dst_port else 0,
                "protocol": protocol,
                "packet_size": packet_size,
                "process_pid": process_pid if process_pid else 0,
                "process_name": process_name if process_name else "unknown"
            }
            
            self.db_manager.store_network_data(network_data)
            
            # Update statistics for anomaly detection
            self.ip_connections[src_ip][dst_ip] += 1
            if dst_port:
                self.port_activity[dst_ip][dst_port] += 1
            
            # Check for suspicious activity
            self.check_for_suspicious_activity(network_data)
    
    def check_for_suspicious_activity(self, network_data):
        """Check for suspicious network activity and generate alerts."""
        src_ip = network_data["src_ip"]
        dst_ip = network_data["dst_ip"]
        dst_port = network_data["dst_port"]
        
        # Check against known suspicious IPs
        if src_ip in self.suspicious_ips or dst_ip in self.suspicious_ips:
            alert = {
                "timestamp": datetime.now().isoformat(),
                "alert_type": "suspicious_ip",
                "severity": "high",
                "description": f"Connection with known suspicious IP detected: {src_ip if src_ip in self.suspicious_ips else dst_ip}",
                "process_pid": network_data["process_pid"],
                "process_name": network_data["process_name"],
                "source_ip": src_ip,
                "destination_ip": dst_ip
            }
            self.db_manager.store_alert(alert)
            logger.warning(f"Security alert: {alert['description']}")
        
        # Check for unusual ports
        if dst_port and dst_port not in self.known_services and dst_port < 1024:
            alert = {
                "timestamp": datetime.now().isoformat(),
                "alert_type": "unusual_port",
                "severity": "medium",
                "description": f"Connection to unusual port {dst_port} detected",
                "process_pid": network_data["process_pid"],
                "process_name": network_data["process_name"],
                "source_ip": src_ip,
                "destination_ip": dst_ip
            }
            self.db_manager.store_alert(alert)
            logger.warning(f"Security alert: {alert['description']}")
        
        # Check for high connection counts (potential scanning or DoS)
        if self.ip_connections[src_ip][dst_ip] > 100:
            alert = {
                "timestamp": datetime.now().isoformat(),
                "alert_type": "high_connection_count",
                "severity": "medium",
                "description": f"High number of connections from {src_ip} to {dst_ip} detected",
                "process_pid": network_data["process_pid"],
                "process_name": network_data["process_name"],
                "source_ip": src_ip,
                "destination_ip": dst_ip
            }
            self.db_manager.store_alert(alert)
            logger.warning(f"Security alert: {alert['description']}")
    
    def start_sniffing(self):
        """Start sniffing network traffic."""
        logger.info("Starting network traffic monitoring...")
        try:
            # To run as non-root, you might need to adjust this command
            # For example, you could use tcpdump in the background
            subprocess.run(["sudo", "chmod", "+r", "/dev/bpf*"], check=True)
            sniff(prn=self.packet_callback, store=0)
        except Exception as e:
            logger.error(f"Error in network monitoring: {e}")
            logger.info("Trying alternative method for network monitoring...")
            try:
                # Alternative: use lsof to monitor connections periodically
                self.monitor_with_lsof()
            except Exception as e2:
                logger.error(f"Error in alternative network monitoring: {e2}")
    
    def monitor_with_lsof(self):
        """Monitor network connections using lsof as an alternative to packet sniffing."""
        while True:
            try:
                # Run lsof to get network connections
                output = subprocess.check_output(
                    ["sudo", "lsof", "-i", "-n", "-P"], 
                    universal_newlines=True
                )
                
                for line in output.splitlines()[1:]:  # Skip header line
                    parts = line.split()
                    if len(parts) >= 9:
                        process_name = parts[0]
                        process_pid = int(parts[1])
                        protocol = parts[7].upper()
                        
                        # Parse address information
                        addr_info = parts[8]
                        if "->" in addr_info:  # Established connection
                            local, remote = addr_info.split("->")
                            src_parts = local.split(":")
                            dst_parts = remote.split(":")
                            
                            if len(src_parts) >= 2 and len(dst_parts) >= 2:
                                src_ip = src_parts[0]
                                src_port = int(src_parts[-1])
                                dst_ip = dst_parts[0]
                                dst_port = int(dst_parts[-1])
                                
                                network_data = {
                                    "timestamp": datetime.now().isoformat(),
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "src_port": src_port,
                                    "dst_port": dst_port,
                                    "protocol": protocol,
                                    "packet_size": 0,  # Can't determine with lsof
                                    "process_pid": process_pid,
                                    "process_name": process_name
                                }
                                
                                self.db_manager.store_network_data(network_data)
                                self.check_for_suspicious_activity(network_data)
                
                # Sleep for a while before checking again
                time.sleep(10)
                
            except Exception as e:
                logger.error(f"Error in lsof monitoring: {e}")
                time.sleep(30)  # Sleep longer on error


class MonitoringAgent:
    """Main agent class coordinating process and network monitoring."""
    
    def __init__(self, config=None):
        """Initialize the monitoring agent."""
        self.config = config or {}
        self.db_path = self.config.get("db_path", "monitor.db")
        self.db_manager = DatabaseManager(self.db_path)
        self.process_monitor = ProcessMonitor(self.db_manager)
        self.running = False
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)
    
    def handle_shutdown(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info("Shutdown signal received. Stopping monitoring...")
        self.running = False
        self.db_manager.close()
        sys.exit(0)
    
    def start(self):
        """Start the monitoring agent."""
        logger.info("Starting macOS Process and Network Monitoring Agent...")
        self.running = True
        
        # Start network monitoring in a separate process
        import multiprocessing
        # Use the standalone function instead of a method
        network_process = multiprocessing.Process(
            target=network_monitoring_process,
            args=(self.db_path, self.config)
        )
        network_process.daemon = True  # Process will exit when main process exits
        network_process.start()
        
        # Set up process monitoring cycle
        try:
            process_interval = self.config.get("process_interval", 30)  # seconds
            anomaly_train_interval = self.config.get("anomaly_train_interval", 3600)  # seconds
            last_anomaly_train = 0
            
            while self.running:
                # Collect process data
                processes = self.process_monitor.collect_process_data()
                
                # Check for process anomalies
                if hasattr(self.process_monitor.anomaly_detector, "offset_"):
                    anomalies = self.process_monitor.detect_anomalies(processes)
                    if anomalies:
                        logger.info(f"Detected {len(anomalies)} process anomalies")
                
                # Train anomaly detector periodically
                current_time = time.time()
                if current_time - last_anomaly_train > anomaly_train_interval:
                    self.process_monitor.train_anomaly_detector()
                    last_anomaly_train = current_time
                
                # Sleep until next monitoring cycle
                time.sleep(process_interval)
                
        except Exception as e:
            logger.error(f"Error in monitoring agent: {e}")
        finally:
            # Clean up resources
            logger.info("Stopping monitoring agent...")
            network_process.terminate()
            self.db_manager.close()
    
    def generate_report(self, report_type="daily", output_format="html"):
        """Generate a monitoring report."""
        logger.info(f"Generating {report_type} report in {output_format} format...")
        
        if report_type == "daily":
            hours = 24
        elif report_type == "weekly":
            hours = 24 * 7
        elif report_type == "monthly":
            hours = 24 * 30
        else:
            hours = 24
        
        # Get data from database
        alerts = self.db_manager.get_alerts(hours=hours)
        processes = self.db_manager.get_process_history(hours=hours)
        network = self.db_manager.get_network_history(hours=hours)
        
        # Convert to pandas DataFrames for analysis
        df_alerts = pd.DataFrame(alerts)
        df_processes = pd.DataFrame(processes)
        df_network = pd.DataFrame(network)
        
        # Generate report based on output format
        if output_format == "html":
            return self._generate_html_report(df_alerts, df_processes, df_network, report_type)
        elif output_format == "json":
            return self._generate_json_report(df_alerts, df_processes, df_network, report_type)
        else:
            return self._generate_text_report(df_alerts, df_processes, df_network, report_type)
    
    def _generate_html_report(self, df_alerts, df_processes, df_network, report_type):
        """Generate an HTML report with graphs and tables."""
        import matplotlib.pyplot as plt
        from io import BytesIO
        import base64
        
        # Create a basic HTML template
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>macOS Monitor {report_type.capitalize()} Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2 {{ color: #333; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ text-align: left; padding: 8px; border: 1px solid #ddd; }}
                th {{ background-color: #f2f2f2; }}
                .alert-high {{ background-color: #ffdddd; }}
                .alert-medium {{ background-color: #ffffcc; }}
                .alert-low {{ background-color: #e6f3ff; }}
                .chart {{ margin: 20px 0; max-width: 800px; }}
            </style>
        </head>
        <body>
            <h1>macOS Process and Network Monitor Report</h1>
            <p>Report type: {report_type.capitalize()}</p>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <h2>Security Alerts</h2>
        """
        
        # Add alerts table
        if not df_alerts.empty:
            html += """
            <table>
                <tr>
                    <th>Timestamp</th>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Description</th>
                    <th>Process</th>
                    <th>IPs</th>
                </tr>
            """
            
            for _, alert in df_alerts.iterrows():
                severity_class = f"alert-{alert['severity']}" if alert['severity'] in ['high', 'medium', 'low'] else ""
                html += f"""
                <tr class="{severity_class}">
                    <td>{alert['timestamp']}</td>
                    <td>{alert['alert_type']}</td>
                    <td>{alert['severity']}</td>
                    <td>{alert['description']}</td>
                    <td>{alert['process_name']} ({alert['process_pid']})</td>
                    <td>{alert['source_ip']} → {alert['destination_ip']}</td>
                </tr>
                """
            
            html += "</table>"
        else:
            html += "<p>No alerts detected during this period.</p>"
        
        # Add process charts
        if not df_processes.empty:
            html += "<h2>Process Activity</h2>"
            
            # Top processes by CPU usage
            plt.figure(figsize=(10, 6))
            top_cpu = df_processes.groupby('name')['cpu_percent'].mean().nlargest(10)
            top_cpu.plot(kind='bar')
            plt.title('Top 10 Processes by CPU Usage')
            plt.ylabel('CPU %')
            plt.tight_layout()
            
            buf = BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            img_str = base64.b64encode(buf.read()).decode('utf-8')
            html += f'<div class="chart"><img src="data:image/png;base64,{img_str}" /></div>'
            plt.close()
            
            # Top processes by memory usage
            plt.figure(figsize=(10, 6))
            top_mem = df_processes.groupby('name')['memory_percent'].mean().nlargest(10)
            top_mem.plot(kind='bar')
            plt.title('Top 10 Processes by Memory Usage')
            plt.ylabel('Memory %')
            plt.tight_layout()
            
            buf = BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            img_str = base64.b64encode(buf.read()).decode('utf-8')
            html += f'<div class="chart"><img src="data:image/png;base64,{img_str}" /></div>'
            plt.close()
        
        # Add network charts
        if not df_network.empty:
            html += "<h2>Network Activity</h2>"
            
            # Top destination IPs
            plt.figure(figsize=(10, 6))
            top_ips = df_network['dst_ip'].value_counts().nlargest(10)
            top_ips.plot(kind='bar')
            plt.title('Top 10 Destination IPs')
            plt.ylabel('Packet Count')
            plt.tight_layout()
            
            buf = BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            img_str = base64.b64encode(buf.read()).decode('utf-8')
            html += f'<div class="chart"><img src="data:image/png;base64,{img_str}" /></div>'
            plt.close()
            
            # Top destination ports
            plt.figure(figsize=(10, 6))
            top_ports = df_network['dst_port'].value_counts().nlargest(10)
            top_ports.plot(kind='bar')
            plt.title('Top 10 Destination Ports')
            plt.ylabel('Connection Count')
            plt.tight_layout()
            
            buf = BytesIO()
            plt.savefig(buf, format='png')
            buf.seek(0)
            img_str = base64.b64encode(buf.read()).decode('utf-8')
            html += f'<div class="chart"><img src="data:image/png;base64,{img_str}" /></div>'
            plt.close()
        
        html += """
        </body>
        </html>
        """
        
        # Save the report to a file
        report_file = f"report_{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(report_file, 'w') as f:
            f.write(html)
        
        logger.info(f"Report saved to {report_file}")
        return report_file
    
    def _generate_json_report(self, df_alerts, df_processes, df_network, report_type):
        """Generate a JSON format report."""
        report = {
            "report_type": report_type,
            "generated_at": datetime.now().isoformat(),
            "alerts": df_alerts.to_dict('records') if not df_alerts.empty else [],
            "top_processes": {
                "by_cpu": df_processes.groupby('name')['cpu_percent'].mean().nlargest(10).to_dict() if not df_processes.empty else {},
                "by_memory": df_processes.groupby('name')['memory_percent'].mean().nlargest(10).to_dict() if not df_processes.empty else {},
                "by_connections": df_processes.groupby('name')['connections'].mean().nlargest(10).to_dict() if not df_processes.empty else {}
            },
            "network_stats": {
                "top_destination_ips": df_network['dst_ip'].value_counts().nlargest(10).to_dict() if not df_network.empty else {},
                "top_destination_ports": df_network['dst_port'].value_counts().nlargest(10).to_dict() if not df_network.empty else {},
                "top_processes": df_network['process_name'].value_counts().nlargest(10).to_dict() if not df_network.empty else {}
            }
        }
        
        # Save the report to a file
        report_file = f"report_{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to {report_file}")
        return report_file
    
    def _generate_text_report(self, df_alerts, df_processes, df_network, report_type):
        """Generate a plain text report."""
        report = [
            f"macOS Process and Network Monitor Report",
            f"Report type: {report_type.capitalize()}",
            f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"\n{'-' * 80}\n",
            
            f"SECURITY ALERTS SUMMARY",
            f"{'-' * 80}"
        ]
        
        if not df_alerts.empty:
            alert_counts = df_alerts['alert_type'].value_counts()
            severity_counts = df_alerts['severity'].value_counts()
            
            report.append(f"Total alerts: {len(df_alerts)}")
            report.append(f"By type: {', '.join([f'{k}: {v}' for k, v in alert_counts.items()])}")
            report.append(f"By severity: {', '.join([f'{k}: {v}' for k, v in severity_counts.items()])}")
            report.append("\nMost recent alerts:")
            
            for i, alert in df_alerts.sort_values('timestamp', ascending=False).head(10).iterrows():
                report.append(f"- [{alert['severity'].upper()}] {alert['timestamp']}: {alert['description']}")
        else:
            report.append("No alerts detected during this period.")
        
        report.extend([
            f"\n{'-' * 80}\n",
            f"PROCESS ACTIVITY SUMMARY",
            f"{'-' * 80}"
        ])
        
        if not df_processes.empty:
            # Top CPU processes
            top_cpu = df_processes.groupby('name')['cpu_percent'].mean().nlargest(10)
            report.append("\nTop processes by CPU usage:")
            for name, value in top_cpu.items():
                report.append(f"- {name}: {value:.2f}%")
            
            # Top memory processes
            top_mem = df_processes.groupby('name')['memory_percent'].mean().nlargest(10)
            report.append("\nTop processes by memory usage:")
            for name, value in top_mem.items():
                report.append(f"- {name}: {value:.2f}%")
        else:
            report.append("No process data available for this period.")
        
        report.extend([
            f"\n{'-' * 80}\n",
            f"NETWORK ACTIVITY SUMMARY",
            f"{'-' * 80}"
        ])
        
        if not df_network.empty:
            # Top destination IPs
            top_ips = df_network['dst_ip'].value_counts().nlargest(10)
            report.append("\nTop destination IPs:")
            for ip, count in top_ips.items():
                report.append(f"- {ip}: {count} packets")
            
            # Top destination ports
            top_ports = df_network['dst_port'].value_counts().nlargest(10)
            report.append("\nTop destination ports:")
            for port, count in top_ports.items():
                report.append(f"- {port}: {count} connections")
        else:
            report.append("No network data available for this period.")
        
        # Save the report to a file
        report_text = "\n".join(report)
        report_file = f"report_{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w') as f:
            f.write(report_text)
        
        logger.info(f"Report saved to {report_file}")
        return report_file


def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(
        description="macOS Process and Network Monitoring Agent"
    )
    parser.add_argument(
        "--config", 
        type=str, 
        help="Path to configuration file"
    )
    parser.add_argument(
        "--report", 
        choices=["daily", "weekly", "monthly"],
        help="Generate a report without starting the monitor"
    )
    parser.add_argument(
        "--format", 
        choices=["html", "json", "text"],
        default="html",
        help="Report format (only used with --report)"
    )
    
    args = parser.parse_args()
    
    # Load configuration if specified
    config = {}
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
    
    # Initialize the agent
    agent = MonitoringAgent(config)
    
    # Generate a report if requested
    if args.report:
        report_file = agent.generate_report(args.report, args.format)
        print(f"Report generated: {report_file}")
        return
    
    # Otherwise start the monitoring agent
    agent.start()


if __name__ == "__main__":
    main()