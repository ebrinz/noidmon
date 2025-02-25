#!/usr/bin/env python3
"""
macOS Process and Network Monitor (Single Process Version)
=========================================================
A simplified version that runs in a single process to avoid multiprocessing issues.
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

    def close(self):
        """Close the database connection."""
        self.conn.close()


class ProcessMonitor:
    """Monitors system processes and identifies unusual behavior."""
    
    def __init__(self, db_manager):
        """Initialize the process monitor."""
        self.db_manager = db_manager
        self.process_baseline = {}
        self.training_data = []
        # For simplified version, use a simple threshold-based approach instead of ML
        self.cpu_threshold = 80.0  # CPU percentage
        self.memory_threshold = 80.0  # Memory percentage
        self.connections_threshold = 50  # Number of connections
        
    def collect_process_data(self):
        """Collect current process information."""
        process_list = []
        
        for proc in psutil.process_iter():
            try:
                # Get basic info first
                proc.cpu_percent()  # Initialize CPU monitoring
                basic_info = proc.as_dict(attrs=['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status'])
                
                # Get connections separately (may fail for some processes)
                try:
                    connections = proc.connections()
                    connection_count = len(connections)
                except (psutil.AccessDenied, AttributeError):
                    connection_count = 0
                
                # Get cmdline separately (may fail for some processes)
                try:
                    cmdline = proc.cmdline()
                    cmdline_str = " ".join(cmdline) if cmdline else ""
                except (psutil.AccessDenied, AttributeError):
                    cmdline_str = ""
                
                process_data = {
                    "timestamp": datetime.now().isoformat(),
                    "pid": basic_info['pid'],
                    "name": basic_info['name'],
                    "username": basic_info['username'],
                    "cpu_percent": basic_info['cpu_percent'],
                    "memory_percent": basic_info['memory_percent'],
                    "cmdline": cmdline_str,
                    "connections": connection_count,
                    "status": basic_info['status']
                }
                
                process_list.append(process_data)
                self.db_manager.store_process_data(process_data)
                
                # Store data for baseline comparison
                proc_name = basic_info['name']
                if proc_name not in self.process_baseline:
                    self.process_baseline[proc_name] = {
                        'cpu_samples': [],
                        'memory_samples': [],
                        'connection_samples': []
                    }
                
                baseline = self.process_baseline[proc_name]
                baseline['cpu_samples'].append(basic_info['cpu_percent'])
                baseline['memory_samples'].append(basic_info['memory_percent'])
                baseline['connection_samples'].append(connection_count)
                
                # Keep only the most recent 100 samples
                for key in baseline:
                    if len(baseline[key]) > 100:
                        baseline[key] = baseline[key][-100:]
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        return process_list
    
    def detect_anomalies(self, processes):
        """Detect anomalous process behavior using simple thresholds."""
        anomalies = []
        
        for proc in processes:
            # Check against absolute thresholds
            if proc['cpu_percent'] > self.cpu_threshold:
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "alert_type": "high_cpu_usage",
                    "severity": "medium",
                    "description": f"High CPU usage detected for process {proc['name']} (PID: {proc['pid']}): {proc['cpu_percent']:.1f}%",
                    "process_pid": proc['pid'],
                    "process_name": proc['name'],
                    "source_ip": "",
                    "destination_ip": ""
                }
                self.db_manager.store_alert(alert)
                anomalies.append(alert)
                logger.warning(f"Process anomaly: {alert['description']}")
            
            if proc['memory_percent'] > self.memory_threshold:
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "alert_type": "high_memory_usage",
                    "severity": "medium",
                    "description": f"High memory usage detected for process {proc['name']} (PID: {proc['pid']}): {proc['memory_percent']:.1f}%",
                    "process_pid": proc['pid'],
                    "process_name": proc['name'],
                    "source_ip": "",
                    "destination_ip": ""
                }
                self.db_manager.store_alert(alert)
                anomalies.append(alert)
                logger.warning(f"Process anomaly: {alert['description']}")
            
            if proc['connections'] > self.connections_threshold:
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "alert_type": "high_connection_count",
                    "severity": "medium",
                    "description": f"High connection count detected for process {proc['name']} (PID: {proc['pid']}): {proc['connections']} connections",
                    "process_pid": proc['pid'],
                    "process_name": proc['name'],
                    "source_ip": "",
                    "destination_ip": ""
                }
                self.db_manager.store_alert(alert)
                anomalies.append(alert)
                logger.warning(f"Process anomaly: {alert['description']}")
            
            # Check against process baseline (if we have enough data)
            proc_name = proc['name']
            if proc_name in self.process_baseline:
                baseline = self.process_baseline[proc_name]
                
                if len(baseline['cpu_samples']) >= 10:
                    avg_cpu = sum(baseline['cpu_samples']) / len(baseline['cpu_samples'])
                    if proc['cpu_percent'] > avg_cpu * 3 and proc['cpu_percent'] > 30:
                        alert = {
                            "timestamp": datetime.now().isoformat(),
                            "alert_type": "unusual_cpu_spike",
                            "severity": "medium",
                            "description": f"Unusual CPU spike detected for process {proc['name']} (PID: {proc['pid']}): {proc['cpu_percent']:.1f}% (avg: {avg_cpu:.1f}%)",
                            "process_pid": proc['pid'],
                            "process_name": proc['name'],
                            "source_ip": "",
                            "destination_ip": ""
                        }
                        self.db_manager.store_alert(alert)
                        anomalies.append(alert)
                        logger.warning(f"Process anomaly: {alert['description']}")
                
                if len(baseline['connection_samples']) >= 10:
                    avg_conn = sum(baseline['connection_samples']) / len(baseline['connection_samples'])
                    if proc['connections'] > avg_conn * 3 and proc['connections'] > 10:
                        alert = {
                            "timestamp": datetime.now().isoformat(),
                            "alert_type": "unusual_connection_spike",
                            "severity": "high",
                            "description": f"Unusual connection spike detected for process {proc['name']} (PID: {proc['pid']}): {proc['connections']} connections (avg: {avg_conn:.1f})",
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
    """Monitors network traffic using lsof (no packet capture)."""
    
    def __init__(self, db_manager):
        """Initialize the network monitor."""
        self.db_manager = db_manager
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
        
        # Check for high connection counts
        self.ip_connections[src_ip][dst_ip] += 1
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
    
    def monitor_with_lsof(self):
        """Monitor network connections using lsof."""
        try:
            # Try with sudo first for better results
            try:
                output = subprocess.check_output(
                    ["sudo", "lsof", "-i", "-n", "-P"], 
                    universal_newlines=True,
                    stderr=subprocess.DEVNULL
                )
            except (subprocess.CalledProcessError, PermissionError):
                # Fall back to regular lsof if sudo fails
                output = subprocess.check_output(
                    ["lsof", "-i", "-n", "-P"], 
                    universal_newlines=True,
                    stderr=subprocess.DEVNULL
                )
            
            connection_count = 0
            
            for line in output.splitlines()[1:]:  # Skip header line
                try:
                    parts = line.split()
                    if len(parts) >= 8:
                        process_name = parts[0]
                        try:
                            process_pid = int(parts[1])
                        except ValueError:
                            process_pid = 0
                        
                        protocol = "TCP"
                        if "UDP" in parts[7].upper():
                            protocol = "UDP"
                        
                        # Parse address information
                        addr_info = parts[8] if len(parts) >= 9 else ""
                        
                        if "->" in addr_info:  # Established connection
                            local, remote = addr_info.split("->")
                            
                            # Parse local address
                            if ":" in local:
                                src_parts = local.rsplit(":", 1)  # Split at the last colon
                                src_ip = src_parts[0]
                                src_port = int(src_parts[1]) if src_parts[1].isdigit() else 0
                            else:
                                src_ip = local
                                src_port = 0
                                
                            # Clean IPv6 brackets if present
                            if src_ip.startswith("[") and src_ip.endswith("]"):
                                src_ip = src_ip[1:-1]
                                
                            # Parse remote address
                            if ":" in remote:
                                dst_parts = remote.rsplit(":", 1)  # Split at the last colon
                                dst_ip = dst_parts[0]
                                dst_port = int(dst_parts[1]) if dst_parts[1].isdigit() else 0
                            else:
                                dst_ip = remote
                                dst_port = 0
                                
                            # Clean IPv6 brackets if present
                            if dst_ip.startswith("[") and dst_ip.endswith("]"):
                                dst_ip = dst_ip[1:-1]
                            
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
                            connection_count += 1
                except Exception as e:
                    # Skip problematic lines
                    continue
                    
            logger.info(f"Network check: found {connection_count} active connections")
                            
        except Exception as e:
            logger.error(f"Error in lsof monitoring: {e}")
            # Fall back to netstat if lsof fails
            try:
                self.monitor_with_netstat()
            except Exception as e2:
                logger.error(f"Error in netstat monitoring: {e2}")
                
    def monitor_with_netstat(self):
        """Monitor network connections using netstat as fallback."""
        try:
            output = subprocess.check_output(
                ["netstat", "-n", "-p", "tcp"], 
                universal_newlines=True
            )
            
            connection_count = 0
            
            for line in output.splitlines()[2:]:  # Skip header lines
                try:
                    parts = line.split()
                    if len(parts) >= 4:
                        if parts[0] == "tcp" or parts[0] == "tcp4" or parts[0] == "tcp6":
                            protocol = "TCP"
                        elif parts[0] == "udp" or parts[0] == "udp4" or parts[0] == "udp6":
                            protocol = "UDP"
                        else:
                            continue
                        
                        # Parse local address
                        local = parts[3]
                        if "." in local:
                            src_parts = local.rsplit(".", 1)
                            src_ip = src_parts[0]
                            src_port = int(src_parts[1]) if src_parts[1].isdigit() else 0
                        else:
                            continue
                        
                        # Parse remote address
                        remote = parts[4]
                        if "." in remote:
                            dst_parts = remote.rsplit(".", 1)
                            dst_ip = dst_parts[0]
                            dst_port = int(dst_parts[1]) if dst_parts[1].isdigit() else 0
                        else:
                            continue
                        
                        # We can't get process info from netstat easily on macOS
                        network_data = {
                            "timestamp": datetime.now().isoformat(),
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": protocol,
                            "packet_size": 0,
                            "process_pid": 0,
                            "process_name": "unknown"
                        }
                        
                        self.db_manager.store_network_data(network_data)
                        self.check_for_suspicious_activity(network_data)
                        connection_count += 1
                except Exception:
                    # Skip problematic lines
                    continue
                    
            logger.info(f"Network check (netstat): found {connection_count} active connections")
                
        except Exception as e:
            logger.error(f"Error in netstat monitoring: {e}")


class MonitoringAgent:
    """Main agent class coordinating process and network monitoring."""
    
    def __init__(self, config=None):
        """Initialize the monitoring agent."""
        self.config = config or {}
        self.db_path = self.config.get("db_path", "monitor.db")
        self.db_manager = DatabaseManager(self.db_path)
        self.process_monitor = ProcessMonitor(self.db_manager)
        self.network_monitor = NetworkMonitor(self.db_manager)
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
        logger.info("Starting macOS Process and Network Monitoring Agent (single process)...")
        self.running = True
        
        try:
            process_interval = self.config.get("process_interval", 30)  # seconds
            network_interval = self.config.get("network_interval", 60)  # seconds
            
            last_network_check = 0
            
            while self.running:
                current_time = time.time()
                
                # Collect and check process data
                processes = self.process_monitor.collect_process_data()
                anomalies = self.process_monitor.detect_anomalies(processes)
                
                if anomalies:
                    logger.info(f"Detected {len(anomalies)} process anomalies")
                
                # Check network periodically
                if current_time - last_network_check > network_interval:
                    self.network_monitor.monitor_with_lsof()
                    last_network_check = current_time
                
                # Sleep until next monitoring cycle
                time.sleep(process_interval)
                
        except Exception as e:
            logger.error(f"Error in monitoring agent: {e}")
        finally:
            # Clean up resources
            logger.info("Stopping monitoring agent...")
            self.db_manager.close()
    
    def generate_report(self, report_type="daily", output_format="text"):
        """Generate a monitoring report (simplified text-only version)."""
        logger.info(f"Generating {report_type} report in {output_format} format...")
        
        if report_type == "daily":
            hours = 24
        elif report_type == "weekly":
            hours = 24 * 7
        elif report_type == "monthly":
            hours = 24 * 30
        else:
            hours = 24
        
        # Get alert data from database
        cursor = self.db_manager.conn.cursor()
        time_threshold = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        cursor.execute('''
        SELECT * FROM alerts 
        WHERE timestamp > ?
        ORDER BY timestamp DESC
        ''', (time_threshold,))
        
        alerts = cursor.fetchall()
        
        # Get process data
        cursor.execute('''
        SELECT name, AVG(cpu_percent) as avg_cpu, MAX(cpu_percent) as max_cpu,
               AVG(memory_percent) as avg_mem, MAX(memory_percent) as max_mem,
               COUNT(*) as count
        FROM processes
        WHERE timestamp > ?
        GROUP BY name
        ORDER BY avg_cpu DESC
        LIMIT 20
        ''', (time_threshold,))
        
        processes = cursor.fetchall()
        
        # Get network data
        cursor.execute('''
        SELECT process_name, src_ip, dst_ip, COUNT(*) as conn_count
        FROM network_traffic
        WHERE timestamp > ?
        GROUP BY process_name, src_ip, dst_ip
        ORDER BY conn_count DESC
        LIMIT 20
        ''', (time_threshold,))
        
        connections = cursor.fetchall()
        
        # Generate report
        report = [
            f"macOS Process and Network Monitor Report",
            f"Report type: {report_type.capitalize()}",
            f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"\n{'-' * 80}\n",
            
            f"SECURITY ALERTS SUMMARY",
            f"{'-' * 80}"
        ]
        
        if alerts:
            report.append(f"Total alerts: {len(alerts)}")
            
            # Count alerts by type
            alert_types = {}
            alert_severities = {}
            
            for alert in alerts:
                alert_type = alert[3]  # alert_type column
                severity = alert[4]    # severity column
                
                if alert_type not in alert_types:
                    alert_types[alert_type] = 0
                alert_types[alert_type] += 1
                
                if severity not in alert_severities:
                    alert_severities[severity] = 0
                alert_severities[severity] += 1
            
            report.append(f"By type: {', '.join([f'{k}: {v}' for k, v in alert_types.items()])}")
            report.append(f"By severity: {', '.join([f'{k}: {v}' for k, v in alert_severities.items()])}")
            report.append("\nMost recent alerts:")
            
            for i, alert in enumerate(alerts[:10]):
                description = alert[5]  # description column
                severity = alert[4]     # severity column
                timestamp = alert[1]    # timestamp column
                report.append(f"- [{severity.upper()}] {timestamp}: {description}")
        else:
            report.append("No alerts detected during this period.")
        
        report.extend([
            f"\n{'-' * 80}\n",
            f"PROCESS ACTIVITY SUMMARY",
            f"{'-' * 80}"
        ])
        
        if processes:
            report.append("\nTop processes by average CPU usage:")
            for proc in processes[:10]:
                name, avg_cpu, max_cpu, avg_mem, max_mem, count = proc
                report.append(f"- {name}: Avg CPU: {avg_cpu:.2f}%, Max CPU: {max_cpu:.2f}%, Avg Mem: {avg_mem:.2f}%")
        else:
            report.append("No process data available for this period.")
        
        report.extend([
            f"\n{'-' * 80}\n",
            f"NETWORK ACTIVITY SUMMARY",
            f"{'-' * 80}"
        ])
        
        if connections:
            report.append("\nTop network connections:")
            for conn in connections[:10]:
                process_name, src_ip, dst_ip, count = conn
                report.append(f"- {process_name}: {src_ip} -> {dst_ip} ({count} connections)")
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
        description="macOS Process and Network Monitoring Agent (Single Process Version)"
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
        choices=["text"],
        default="text",
        help="Report format (only text is supported in this version)"
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