#!/usr/bin/env python3
"""
██████╗  ██████╗ ██╗██████╗ ███╗   ███╗ ██████╗ ███╗   ██╗
██╔══██╗██╔═══██╗██║██╔══██╗████╗ ████║██╔═══██╗████╗  ██║
███████║██║   ██║██║██║  ██║██╔████╔██║██║   ██║██╔██╗ ██║
██╔══██║██║   ██║██║██║  ██║██║╚██╔╝██║██║   ██║██║╚██╗██║
██║  ██║╚██████╔╝██║██████╔╝██║ ╚═╝ ██║╚██████╔╝██║ ╚████║
╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝ ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

███╗   ███╗ ██████╗ ███╗   ██╗██╗████████╗ ██████╗ ██████╗ 
████╗ ████║██╔═══██╗████╗  ██║██║╚══██╔══╝██╔═══██╗██╔══██╗
██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║   ██║   ██║██████╔╝
██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║   ██║   ██║██╔══██╗
██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║   ██║   ╚██████╔╝██║  ██║
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝

- System Monitoring Tool -
v2.0 - Advanced Command Interface
"""

import os
import sys
import json
import sqlite3
import argparse
import time
import random
import platform
import traceback
import psutil
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union

# ANSI color codes for simplified cyan/orange scheme
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    BLACK = "\033[30m"
    
    # Primary colors
    CYAN = "\033[36m"           # Primary color
    ORANGE = "\033[33m"         # Secondary accent (using yellow as closest to orange)
    BRIGHT_CYAN = "\033[96m"    # Highlights
    DARK_CYAN = "\033[34m"      # Darker shade (using blue as dark cyan)
    DARK_GRAY = "\033[90m"      # Background text
    BRIGHT_WHITE = "\033[97m"   # Important text
    
    # For warnings/status
    RED = "\033[31m"            # Error/Warning
    GREEN = "\033[32m"          # Success
    
    # Background colors - used very sparingly
    BG_BLACK = "\033[40m"
    BG_CYAN = "\033[46m"

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_status(label="Loading"):
    """Display a status message without animation."""
    print(f"{Colors.CYAN}▶ {Colors.BRIGHT_WHITE}{label}...{Colors.RESET}")
    # Small pause for user to read
    time.sleep(0.5)

def print_splash_screen():
    """Display a simple splash screen with cyan/orange color scheme."""
    clear_screen()
    
    # The splash screen - extracted from module docstring
    splash_text = __doc__.split('\n')
    
    # First half in cyan, second half in orange
    mid_point = len(splash_text) // 2
    
    for i, line in enumerate(splash_text):
        color = Colors.BRIGHT_CYAN if i < mid_point else Colors.ORANGE
        print(f"{color}{line}{Colors.RESET}")
    
    print()
    print(f"{Colors.CYAN}════════════════════════════════════════{Colors.RESET}")
    print()
    
    print_status("Initializing System Monitor")
    print_status("Starting Network Monitoring")
    print()

def print_header(text):
    """Print a styled header."""
    print(f"\n{Colors.CYAN}┌{'─' * (len(text) + 2)}┐{Colors.RESET}")
    print(f"{Colors.CYAN}│ {Colors.BRIGHT_WHITE}{Colors.BOLD}{text}{Colors.CYAN} │{Colors.RESET}")
    print(f"{Colors.CYAN}└{'─' * (len(text) + 2)}┘{Colors.RESET}\n")

def print_section(title):
    """Print a clean section divider with a title."""
    width = 50
    padding = max(2, (width - len(title) - 4) // 2)
    
    print(f"\n{Colors.BRIGHT_CYAN}{'─' * padding} {Colors.ORANGE}{title} {Colors.BRIGHT_CYAN}{'─' * padding}{Colors.RESET}\n")

def get_alert_color(severity):
    """Return color based on alert severity."""
    if severity.lower() == "high":
        return Colors.RED
    elif severity.lower() == "medium":
        return Colors.ORANGE
    else:
        return Colors.GREEN

def format_percentage(value):
    """Format a percentage value with cyberpunk color coding."""
    if value > 80:
        return f"{Colors.RED}{value:.1f}%{Colors.RESET}"
    elif value > 50:
        return f"{Colors.ORANGE}{value:.1f}%{Colors.RESET}"
    else:
        return f"{Colors.GREEN}{value:.1f}%{Colors.RESET}"

def get_system_summary(db_path="monitor.db"):
    """Get current system summary from database."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get latest timestamp
        cursor.execute("SELECT MAX(timestamp) FROM processes")
        result = cursor.fetchone()
        latest_time = result[0] if result and result[0] else None
        
        if not latest_time:
            conn.close()
            return {
                "status": "No data available",
                "processes": [],
                "alerts": [],
                "network": []
            }
        
        # Get recent metrics
        hours_ago = (datetime.now() - timedelta(hours=1)).isoformat()
        
        # Top processes by CPU
        cursor.execute("""
            SELECT name, cpu_percent, memory_percent, 0 as connections
            FROM processes
            WHERE timestamp > ?
            ORDER BY cpu_percent DESC
            LIMIT 5
        """, (hours_ago,))
        top_processes = cursor.fetchall()
        
        # Recent alerts
        cursor.execute("""
            SELECT timestamp, severity, description
            FROM alerts
            ORDER BY timestamp DESC
            LIMIT 5
        """)
        recent_alerts = cursor.fetchall()
        
        # Network activity
        cursor.execute("""
            SELECT process_name, dst_ip, dst_port, COUNT(*)
            FROM network_traffic
            WHERE timestamp > ?
            GROUP BY process_name, dst_ip, dst_port
            ORDER BY COUNT(*) DESC
            LIMIT 5
        """, (hours_ago,))
        network_activity = cursor.fetchall()
        
        conn.close()
        
        return {
            "status": "Active",
            "latest_update": latest_time,
            "processes": top_processes,
            "alerts": recent_alerts,
            "network": network_activity
        }
        
    except sqlite3.Error as e:
        print(f"{Colors.RED}Database error: {e}{Colors.RESET}")
        return {
            "status": "Error",
            "error": str(e),
            "processes": [],
            "alerts": [],
            "network": []
        }

def display_system_summary(data):
    """Display system summary with cyan/orange color scheme."""
    status_color = Colors.GREEN if data["status"] == "Active" else Colors.RED
    
    print_header("SYSTEM STATUS")
    print(f"Status: {status_color}{data['status']}{Colors.RESET}")
    
    if "latest_update" in data:
        print(f"Last Update: {Colors.BRIGHT_CYAN}{data['latest_update']}{Colors.RESET}")
    
    if "error" in data:
        print(f"{Colors.RED}Error: {data['error']}{Colors.RESET}")
        return
    
    # Top processes
    print_section("TOP CPU PROCESSES")
    if data["processes"]:
        for proc in data["processes"]:
            name = proc[0]
            cpu = proc[1]
            mem = proc[2]
            conns = proc[3] or 0
            
            print(f"{Colors.BRIGHT_WHITE}{name[:20]:<20}{Colors.RESET} | "
                  f"CPU: {format_percentage(cpu)} | "
                  f"MEM: {format_percentage(mem)} | "
                  f"CONN: {Colors.BRIGHT_CYAN}{conns}{Colors.RESET}")
    else:
        print(f"{Colors.DARK_GRAY}No process data available{Colors.RESET}")
    
    # Recent alerts
    print_section("RECENT ALERTS")
    if data["alerts"]:
        for alert in data["alerts"]:
            timestamp = alert[0]
            severity = alert[1]
            description = alert[2]
            
            severity_color = get_alert_color(severity)
            print(f"{Colors.DARK_GRAY}{timestamp}{Colors.RESET} | "
                  f"{severity_color}[{severity.upper()}]{Colors.RESET} | "
                  f"{Colors.BRIGHT_WHITE}{description}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}No recent alerts detected{Colors.RESET}")
    
    # Network activity
    print_section("ACTIVE NETWORK CONNECTIONS")
    if data["network"]:
        for net in data["network"]:
            process = net[0] or "Unknown"
            dst_ip = net[1]
            dst_port = net[2]
            count = net[3]
            
            print(f"{Colors.BRIGHT_WHITE}{process[:15]:<15}{Colors.RESET} | "
                  f"{Colors.CYAN}{dst_ip:>15}{Colors.RESET}:"
                  f"{Colors.ORANGE}{dst_port:<5}{Colors.RESET} | "
                  f"Count: {Colors.BRIGHT_CYAN}{count}{Colors.RESET}")
    else:
        print(f"{Colors.DARK_GRAY}No network data available{Colors.RESET}")

def generate_report(db_path="monitor.db", report_type="daily", include_ascii=True):
    """Generate a report with cyberpunk aesthetics."""
    # Calculate time threshold based on report type
    if report_type == "daily":
        hours = 24
        title = "DAILY SYSTEM REPORT"
    elif report_type == "weekly":
        hours = 24 * 7
        title = "WEEKLY SYSTEM REPORT"
    elif report_type == "monthly":
        hours = 24 * 30
        title = "MONTHLY SYSTEM REPORT"
    else:
        hours = 24
        title = "SYSTEM REPORT"
    
    clear_screen()
    if include_ascii:
        print(f"{Colors.CYAN}┌{'─' * 46}┐{Colors.RESET}")
        print(f"{Colors.CYAN}│ {Colors.BRIGHT_CYAN}NOIDMON {Colors.ORANGE}SYSTEM {Colors.BRIGHT_CYAN}REPORT {Colors.CYAN}{' ' * 24}│{Colors.RESET}")
        print(f"{Colors.CYAN}└{'─' * 46}┘{Colors.RESET}")
    
    print_header(title)
    print(f"{Colors.BRIGHT_WHITE}Report type:{Colors.RESET} {Colors.GREEN}{report_type.capitalize()}{Colors.RESET}")
    print(f"{Colors.BRIGHT_WHITE}Generated on:{Colors.RESET} {Colors.GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print(f"{Colors.BRIGHT_WHITE}Time period:{Colors.RESET} {Colors.GREEN}Last {hours} hours{Colors.RESET}")
    print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")
    
    time_threshold = (datetime.now() - timedelta(hours=hours)).isoformat()
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # ALERTS SECTION
        print_section("SECURITY ALERTS")
        
        cursor.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp > ?", 
            (time_threshold,)
        )
        alert_count = cursor.fetchone()[0]
        
        if alert_count > 0:
            count_color = Colors.RED if alert_count > 10 else Colors.YELLOW
            print(f"Total alerts: {count_color}{alert_count}{Colors.RESET}")
            
            # Count by alert type
            cursor.execute(
                "SELECT alert_type, COUNT(*) FROM alerts WHERE timestamp > ? GROUP BY alert_type",
                (time_threshold,)
            )
            alert_types = cursor.fetchall()
            print(f"{Colors.BRIGHT_WHITE}Alert types:{Colors.RESET}")
            for t in alert_types:
                print(f"  - {Colors.YELLOW}{t[0]}{Colors.RESET}: {Colors.BRIGHT_CYAN}{t[1]}{Colors.RESET}")
            
            # Count by severity
            cursor.execute(
                "SELECT severity, COUNT(*) FROM alerts WHERE timestamp > ? GROUP BY severity",
                (time_threshold,)
            )
            severities = cursor.fetchall()
            print(f"{Colors.BRIGHT_WHITE}Alert severities:{Colors.RESET}")
            for s in severities:
                sev_color = get_alert_color(s[0])
                print(f"  - {sev_color}{s[0].upper()}{Colors.RESET}: {Colors.BRIGHT_CYAN}{s[1]}{Colors.RESET}")
            
            # Recent alerts
            print(f"\n{Colors.BRIGHT_WHITE}Most recent alerts:{Colors.RESET}")
            cursor.execute(
                """
                SELECT timestamp, severity, description 
                FROM alerts 
                WHERE timestamp > ? 
                ORDER BY timestamp DESC 
                LIMIT 10
                """,
                (time_threshold,)
            )
            recent_alerts = cursor.fetchall()
            for alert in recent_alerts:
                severity_color = get_alert_color(alert[1])
                print(f"  {Colors.DARK_GRAY}{alert[0]}{Colors.RESET} | "
                      f"{severity_color}[{alert[1].upper()}]{Colors.RESET} | "
                      f"{alert[2]}")
        else:
            print(f"{Colors.GREEN}✓ No alerts detected during this period.{Colors.RESET}")
        
        # PROCESS SECTION
        print_section("PROCESS ACTIVITY")
        
        cursor.execute(
            """
            SELECT name, AVG(cpu_percent), MAX(cpu_percent), COUNT(*)
            FROM processes
            WHERE timestamp > ?
            GROUP BY name
            ORDER BY AVG(cpu_percent) DESC
            LIMIT 10
            """,
            (time_threshold,)
        )
        top_processes = cursor.fetchall()
        
        if top_processes:
            print(f"{Colors.BRIGHT_WHITE}Top processes by average CPU usage:{Colors.RESET}")
            for proc in top_processes:
                avg_cpu = proc[1]
                max_cpu = proc[2]
                avg_color = get_alert_color("high" if avg_cpu > 80 else "medium" if avg_cpu > 50 else "low")
                max_color = get_alert_color("high" if max_cpu > 80 else "medium" if max_cpu > 50 else "low")
                
                print(f"  {Colors.GREEN}{proc[0][:20]:<20}{Colors.RESET} | "
                      f"Avg: {avg_color}{avg_cpu:.2f}%{Colors.RESET} | "
                      f"Max: {max_color}{max_cpu:.2f}%{Colors.RESET} | "
                      f"Samples: {Colors.BRIGHT_CYAN}{proc[3]}{Colors.RESET}")
        else:
            print(f"{Colors.DARK_GRAY}No process data available for this period.{Colors.RESET}")
        
        # Get memory usage
        cursor.execute(
            """
            SELECT name, AVG(memory_percent), MAX(memory_percent)
            FROM processes
            WHERE timestamp > ?
            GROUP BY name
            ORDER BY AVG(memory_percent) DESC
            LIMIT 10
            """,
            (time_threshold,)
        )
        memory_processes = cursor.fetchall()
        
        if memory_processes:
            print(f"\n{Colors.BRIGHT_WHITE}Top processes by average memory usage:{Colors.RESET}")
            for proc in memory_processes:
                avg_mem = proc[1]
                max_mem = proc[2]
                avg_color = get_alert_color("high" if avg_mem > 80 else "medium" if avg_mem > 50 else "low")
                max_color = get_alert_color("high" if max_mem > 80 else "medium" if max_mem > 50 else "low")
                
                print(f"  {Colors.GREEN}{proc[0][:20]:<20}{Colors.RESET} | "
                      f"Avg: {avg_color}{avg_mem:.2f}%{Colors.RESET} | "
                      f"Max: {max_color}{max_mem:.2f}%{Colors.RESET}")
        
        # NETWORK SECTION
        print_section("NETWORK ACTIVITY")
        
        cursor.execute(
            """
            SELECT process_name, COUNT(*)
            FROM network_traffic
            WHERE timestamp > ?
            GROUP BY process_name
            ORDER BY COUNT(*) DESC
            LIMIT 10
            """,
            (time_threshold,)
        )
        process_traffic = cursor.fetchall()
        
        if process_traffic:
            print(f"{Colors.BRIGHT_WHITE}Top processes by network activity:{Colors.RESET}")
            for proc in process_traffic:
                proc_name = proc[0] if proc[0] else "Unknown"
                print(f"  {Colors.GREEN}{proc_name[:20]:<20}{Colors.RESET} | "
                      f"Connections: {Colors.BRIGHT_CYAN}{proc[1]}{Colors.RESET}")
        else:
            print(f"{Colors.DARK_GRAY}No network data available for this period.{Colors.RESET}")
        
        # Get destination IPs
        cursor.execute(
            """
            SELECT dst_ip, COUNT(*)
            FROM network_traffic
            WHERE timestamp > ?
            GROUP BY dst_ip
            ORDER BY COUNT(*) DESC
            LIMIT 10
            """,
            (time_threshold,)
        )
        destination_ips = cursor.fetchall()
        
        if destination_ips:
            print(f"\n{Colors.BRIGHT_WHITE}Top destination IP addresses:{Colors.RESET}")
            for ip in destination_ips:
                print(f"  {Colors.YELLOW}{ip[0]:>15}{Colors.RESET} | "
                      f"Connections: {Colors.BRIGHT_CYAN}{ip[1]}{Colors.RESET}")
        
        # Get destination ports
        cursor.execute(
            """
            SELECT dst_port, COUNT(*)
            FROM network_traffic
            WHERE timestamp > ?
            GROUP BY dst_port
            ORDER BY COUNT(*) DESC
            LIMIT 10
            """,
            (time_threshold,)
        )
        destination_ports = cursor.fetchall()
        
        if destination_ports:
            print(f"\n{Colors.BRIGHT_WHITE}Top destination ports:{Colors.RESET}")
            for port in destination_ports:
                print(f"  {Colors.ORANGE}{port[0]:>5}{Colors.RESET} | "
                      f"Connections: {Colors.BRIGHT_CYAN}{port[1]}{Colors.RESET}")
        
        # Close database
        conn.close()
        
        print(f"\n{Colors.CYAN}┌{'─' * 46}┐{Colors.RESET}")
        print(f"{Colors.CYAN}│ {Colors.GREEN}Report complete! {Colors.CYAN}{' ' * 29}│{Colors.RESET}")
        print(f"{Colors.CYAN}└{'─' * 46}┘{Colors.RESET}")
        
    except sqlite3.Error as e:
        print(f"{Colors.RED}Database error: {e}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}Error generating report: {e}{Colors.RESET}")

def get_alerts(db_path="monitor.db", hours=24, severity=None):
    """Get alerts from the database with optional filtering."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        time_threshold = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        if severity:
            cursor.execute("""
            SELECT timestamp, alert_type, severity, description, process_pid, process_name, source_ip, destination_ip
            FROM alerts
            WHERE timestamp > ? AND severity = ?
            ORDER BY timestamp DESC
            LIMIT 100
            """, (time_threshold, severity))
        else:
            cursor.execute("""
            SELECT timestamp, alert_type, severity, description, process_pid, process_name, source_ip, destination_ip
            FROM alerts
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            LIMIT 100
            """, (time_threshold,))
            
        columns = [description[0] for description in cursor.description]
        alerts = [dict(zip(columns, row)) for row in cursor.fetchall()]
        conn.close()
        return alerts
    
    except sqlite3.Error as e:
        print(f"{Colors.RED}Database error: {e}{Colors.RESET}")
        return []

def get_process_details(db_path="monitor.db", name=None):
    """Get detailed information about a specific process."""
    if not name:
        return None
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Initialize with default values
        result = {
            'name': name,
            'history': [],
            'alerts': [],
            'network': [],
            'frequent_connections': [],
            'risk_assessment': {
                'score': 10,
                'factors': ["Basic risk assessment"],
                'recommended_action': "Monitor"
            }
        }
        
        # Get process history
        cursor.execute("""
        SELECT timestamp, pid, cpu_percent, memory_percent, connections, cmdline, status
        FROM processes
        WHERE name = ? AND timestamp > datetime('now', '-24 hours')
        ORDER BY timestamp DESC
        LIMIT 100
        """, (name,))
        result['history'] = [dict(row) for row in cursor.fetchall()]
        
        # Get related alerts
        cursor.execute("""
        SELECT timestamp, alert_type, severity, description, source_ip, destination_ip
        FROM alerts
        WHERE process_name = ? AND timestamp > datetime('now', '-24 hours')
        ORDER BY timestamp DESC
        """, (name,))
        result['alerts'] = [dict(row) for row in cursor.fetchall()]
        
        # Get network activity
        cursor.execute("""
        SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size
        FROM network_traffic
        WHERE process_name = ? AND timestamp > datetime('now', '-24 hours')
        ORDER BY timestamp DESC
        LIMIT 100
        """, (name,))
        result['network'] = [dict(row) for row in cursor.fetchall()]
        
        # Get most frequent connections
        cursor.execute("""
        SELECT dst_ip, COUNT(*) as count, dst_port
        FROM network_traffic
        WHERE process_name = ? AND timestamp > datetime('now', '-24 hours')
        GROUP BY dst_ip, dst_port
        ORDER BY count DESC
        LIMIT 10
        """, (name,))
        result['frequent_connections'] = [dict(row) for row in cursor.fetchall()]
        
        # Calculate risk score based on various factors
        # Start with default score
        risk_score = 0
        risk_factors = []
        
        # Add baseline risk for any process with alerts
        if result['alerts']:
            risk_score += 10
            risk_factors.append(f"Process has {len(result['alerts'])} alert(s)")
        
        # Check for high CPU usage
        if result['history']:
            max_cpu = max([h.get('cpu_percent', 0) for h in result['history']] or [0])
            if max_cpu > 80:
                risk_score += 20
                risk_factors.append(f"High CPU usage detected ({max_cpu:.2f}%)")
            elif max_cpu > 50:
                risk_score += 10
                risk_factors.append(f"Moderate CPU usage ({max_cpu:.2f}%)")
        
        # Check for unusual connections
        unique_ips = len(set([n.get('dst_ip') for n in result['network'] if n.get('dst_ip')]))
        if unique_ips > 20:
            risk_score += 15
            risk_factors.append(f"Connects to many unique IPs ({unique_ips})")
        elif unique_ips > 10:
            risk_score += 5
            risk_factors.append(f"Connects to several unique IPs ({unique_ips})")
        
        # Check for alerts
        if len(result['alerts']) > 0:
            high_severity = sum(1 for a in result['alerts'] if a.get('severity') == 'high')
            medium_severity = sum(1 for a in result['alerts'] if a.get('severity') == 'medium')
            risk_score += high_severity * 25 + medium_severity * 10
            if high_severity > 0:
                risk_factors.append(f"Has {high_severity} high severity alerts")
            if medium_severity > 0:
                risk_factors.append(f"Has {medium_severity} medium severity alerts")
        
        # Set recommended action based on risk score
        recommended_action = "Monitor"
        if risk_score > 70:
            recommended_action = "Investigate and consider terminating"
        elif risk_score > 40:
            recommended_action = "Investigate behavior"
        
        # Check for known suspicious patterns in command line
        if result['history'] and result['history'][0].get('cmdline'):
            cmdline = result['history'][0]['cmdline'].lower()
            suspicious_keywords = ['curl', 'wget', 'base64', 'exec', 'miner', 'coin', 'hash', '-xz', 'chmod']
            
            found_keywords = [kw for kw in suspicious_keywords if kw in cmdline]
            if found_keywords:
                risk_score += 15
                risk_factors.append(f"Command line contains suspicious keywords: {', '.join(found_keywords)}")
                if len(found_keywords) > 2:
                    recommended_action = "Investigate immediately"
        
        result['risk_assessment'] = {
            'score': min(risk_score, 100),  # Cap at 100
            'factors': risk_factors,
            'recommended_action': recommended_action
        }
        
        conn.close()
        return result
        
    except Exception as e:
        print(f"{Colors.RED}Error getting process details: {e}{Colors.RESET}")
        return {
            'name': name,
            'error': str(e),
            'history': [],
            'alerts': [],
            'network': [],
            'frequent_connections': [],
            'risk_assessment': {
                'score': 0,
                'factors': ["Error processing data"],
                'recommended_action': "Error occurred during assessment"
            }
        }

def investigate_process(db_path="monitor.db", name=None):
    """Perform detailed investigation of a process, including live information."""
    if not name:
        return None
    
    try:
        # Get historical data
        result = get_process_details(db_path, name)
        
        # Get live process information
        result['running'] = False
        result['instances_count'] = 0
        result['process_info'] = {}
        result['file_info'] = {}
        result['network_info'] = {}
        
        # Check whitelist status
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Create whitelist table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS whitelisted_processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            reason TEXT,
            added_by TEXT,
            timestamp TEXT
        )
        ''')
        conn.commit()
        
        cursor.execute("SELECT * FROM whitelisted_processes WHERE name = ?", (name,))
        whitelist_entry = cursor.fetchone()
        result['whitelisted'] = whitelist_entry is not None
        
        conn.close()
        
        # Get current running instances
        try:
            process_instances = []
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'] == name:
                        process_instances.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            result['instances_count'] = len(process_instances)
            result['running'] = len(process_instances) > 0
            
            # Get detailed info from the first running instance
            if process_instances:
                p = psutil.Process(process_instances[0].info['pid'])
                
                # Basic process info
                result['process_info'] = {
                    'pid': p.pid,
                    'username': p.username(),
                    'status': p.status(),
                    'created': datetime.fromtimestamp(p.create_time()).isoformat(),
                    'cpu_percent': p.cpu_percent(interval=0.1),
                    'memory_percent': p.memory_percent(),
                }
                
                # Try to get command line
                try:
                    result['process_info']['command_line'] = p.cmdline()
                except (psutil.AccessDenied, psutil.ZombieProcess) as e:
                    result['process_info']['command_line'] = []
                
                # Try to get working directory
                try:
                    result['process_info']['working_directory'] = p.cwd()
                except (psutil.AccessDenied, psutil.ZombieProcess) as e:
                    result['process_info']['working_directory'] = "Access denied"
                
                # Try to get executable path
                try:
                    result['process_info']['executable'] = p.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess) as e:
                    result['process_info']['executable'] = "Access denied"
                
                # Open files
                try:
                    open_files = []
                    for file in p.open_files():
                        file_type = "unknown"
                        if file.path.endswith(('.dll', '.so', '.dylib')):
                            file_type = "library"
                        elif file.path.endswith(('.exe', '')):
                            file_type = "executable"
                        elif file.path.startswith('/dev/'):
                            file_type = "device"
                        elif file.path.startswith('/proc/'):
                            file_type = "proc"
                        elif '.' in file.path.split('/')[-1]:
                            file_type = "data"
                        else:
                            file_type = "other"
                        
                        open_files.append({
                            'name': file.path,
                            'type': file_type,
                            'fd': file.fd
                        })
                    result['file_info']['open_files'] = open_files
                except (psutil.AccessDenied, psutil.ZombieProcess) as e:
                    result['file_info']['error'] = f"Could not access file information: {str(e)}"
                
                # Network connections
                try:
                    active_connections = []
                    for conn in p.connections(kind='all'):
                        conn_type = str(conn.type).replace('SocketKind.', '')
                        
                        # Format addresses
                        local_address = f"{conn.laddr.ip}:{conn.laddr.port}" if hasattr(conn, 'laddr') and conn.laddr else "unknown"
                        remote_address = f"{conn.raddr.ip}:{conn.raddr.port}" if hasattr(conn, 'raddr') and conn.raddr else "unknown"
                        
                        active_connections.append({
                            'type': conn_type,
                            'local_address': local_address,
                            'remote_address': remote_address,
                            'status': conn.status
                        })
                    result['network_info']['active_connections'] = active_connections
                except (psutil.AccessDenied, psutil.ZombieProcess) as e:
                    result['network_info']['error'] = f"Could not access network information: {str(e)}"
                
                # Update risk assessment with live information
                risk_score = result['risk_assessment']['score']
                risk_factors = result['risk_assessment']['factors']
                
                # Check CPU usage for risk
                if result['process_info']['cpu_percent'] > 80:
                    risk_score += 20
                    risk_factors.append(f"High CPU usage: {result['process_info']['cpu_percent']:.2f}%")
                elif result['process_info']['cpu_percent'] > 50:
                    risk_score += 10
                    risk_factors.append(f"Moderate CPU usage: {result['process_info']['cpu_percent']:.2f}%")
                
                # Check memory usage for risk
                if result['process_info']['memory_percent'] > 15:
                    risk_score += 10
                    risk_factors.append(f"High memory usage: {result['process_info']['memory_percent']:.2f}%")
                
                # Update risk assessment
                recommended_action = "Monitor"
                if risk_score > 70:
                    recommended_action = "Investigate and consider terminating"
                elif risk_score > 40:
                    recommended_action = "Investigate behavior"
                
                result['risk_assessment'] = {
                    'score': min(risk_score, 100),  # Cap at 100
                    'factors': risk_factors,
                    'recommended_action': recommended_action
                }
        
        except Exception as e:
            result['error'] = f"Error inspecting running process: {str(e)}"
        
        return result
        
    except Exception as e:
        print(f"{Colors.RED}Error investigating process: {e}{Colors.RESET}")
        return {
            'name': name,
            'error': str(e),
            'running': False
        }

def export_process_data(db_path="monitor.db", name=None, output_file=None):
    """Export detailed process data to a JSON file."""
    if not name:
        print(f"{Colors.RED}No process name specified{Colors.RESET}")
        return None
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get all process data
        cursor.execute("SELECT * FROM processes WHERE name = ? ORDER BY timestamp DESC LIMIT 1000", (name,))
        processes = [dict(row) for row in cursor.fetchall()]
        
        # Get all network data
        cursor.execute("SELECT * FROM network_traffic WHERE process_name = ? ORDER BY timestamp DESC LIMIT 1000", (name,))
        network = [dict(row) for row in cursor.fetchall()]
        
        # Get all alerts
        cursor.execute("SELECT * FROM alerts WHERE process_name = ? ORDER BY timestamp DESC", (name,))
        alerts = [dict(row) for row in cursor.fetchall()]
        
        # Create forensic report
        report = {
            "timestamp": datetime.now().isoformat(),
            "process_name": name,
            "summary": {
                "process_records": len(processes),
                "network_records": len(network),
                "alert_records": len(alerts),
                "alert_types": {},
                "alert_severities": {}
            },
            "processes": processes,
            "network": network,
            "alerts": alerts
        }
        
        # Count alert types and severities
        for alert in alerts:
            alert_type = alert["alert_type"]
            severity = alert["severity"]
            
            if alert_type not in report["summary"]["alert_types"]:
                report["summary"]["alert_types"][alert_type] = 0
            report["summary"]["alert_types"][alert_type] += 1
            
            if severity not in report["summary"]["alert_severities"]:
                report["summary"]["alert_severities"][severity] = 0
            report["summary"]["alert_severities"][severity] += 1
        
        conn.close()
        
        # Save to file
        if not output_file:
            output_file = f"{name}_forensic_data.json"
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"{Colors.GREEN}Process data exported to {output_file}{Colors.RESET}")
        return output_file
        
    except Exception as e:
        print(f"{Colors.RED}Error exporting process data: {e}{Colors.RESET}")
        return None

def get_whitelist(db_path="monitor.db"):
    """Get all whitelisted processes."""
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Create table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS whitelisted_processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            reason TEXT,
            added_by TEXT,
            timestamp TEXT
        )
        ''')
        conn.commit()
        
        cursor.execute("""
        SELECT name, reason, added_by, timestamp 
        FROM whitelisted_processes
        ORDER BY name
        """)
        
        whitelist = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return whitelist
        
    except Exception as e:
        print(f"{Colors.RED}Error getting whitelist: {e}{Colors.RESET}")
        return []

def add_to_whitelist(db_path="monitor.db", name=None, reason="Added by user", added_by="cli"):
    """Add a process to the whitelist."""
    if not name:
        print(f"{Colors.RED}No process name specified{Colors.RESET}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS whitelisted_processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            reason TEXT,
            added_by TEXT,
            timestamp TEXT
        )
        ''')
        conn.commit()
        
        cursor.execute("""
        INSERT INTO whitelisted_processes (name, reason, added_by, timestamp)
        VALUES (?, ?, ?, datetime('now'))
        """, (name, reason, added_by))
        conn.commit()
        
        success = True
        message = f"Process {name} added to whitelist"
        print(f"{Colors.GREEN}{message}{Colors.RESET}")
        
    except sqlite3.IntegrityError:
        success = False
        message = f"Process {name} is already whitelisted"
        print(f"{Colors.YELLOW}{message}{Colors.RESET}")
    except Exception as e:
        success = False
        message = f"Error adding process to whitelist: {str(e)}"
        print(f"{Colors.RED}{message}{Colors.RESET}")
    finally:
        conn.close()
    
    return success

def remove_from_whitelist(db_path="monitor.db", name=None):
    """Remove a process from the whitelist."""
    if not name:
        print(f"{Colors.RED}No process name specified{Colors.RESET}")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM whitelisted_processes WHERE name = ?", (name,))
        conn.commit()
        
        if cursor.rowcount > 0:
            success = True
            message = f"Process {name} removed from whitelist"
            print(f"{Colors.GREEN}{message}{Colors.RESET}")
        else:
            success = False
            message = f"Process {name} not found in whitelist"
            print(f"{Colors.YELLOW}{message}{Colors.RESET}")
    except Exception as e:
        success = False
        message = f"Error removing process from whitelist: {str(e)}"
        print(f"{Colors.RED}{message}{Colors.RESET}")
    finally:
        conn.close()
    
    return success

def terminate_process(name=None):
    """Terminate a running process."""
    if not name:
        print(f"{Colors.RED}No process name specified{Colors.RESET}")
        return False
    
    try:
        # Check if the process is whitelisted
        whitelist = get_whitelist()
        for entry in whitelist:
            if entry['name'] == name:
                print(f"{Colors.YELLOW}Process {name} is whitelisted and cannot be terminated{Colors.RESET}")
                return False
        
        terminated_count = 0
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] == name:
                    psutil.Process(proc.info['pid']).terminate()
                    terminated_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        if terminated_count > 0:
            print(f"{Colors.GREEN}Successfully terminated {terminated_count} instances of {name}{Colors.RESET}")
            return True
        else:
            print(f"{Colors.YELLOW}No active instances of {name} found to terminate{Colors.RESET}")
            return False
    except Exception as e:
        print(f"{Colors.RED}Error terminating process: {str(e)}{Colors.RESET}")
        return False

def display_risk_assessment(risk):
    """Display a process risk assessment."""
    score = risk['score']
    factors = risk['factors']
    action = risk['recommended_action']
    
    if score > 70:
        score_color = Colors.RED
    elif score > 40:
        score_color = Colors.ORANGE
    else:
        score_color = Colors.GREEN
    
    print(f"\n{Colors.BRIGHT_WHITE}Risk Score: {score_color}{score}/100{Colors.RESET}")
    print(f"{Colors.BRIGHT_WHITE}Recommended Action: {Colors.ORANGE}{action}{Colors.RESET}")
    
    print(f"\n{Colors.BRIGHT_WHITE}Risk Factors:{Colors.RESET}")
    if factors:
        for factor in factors:
            print(f"  - {Colors.CYAN}{factor}{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}No risk factors identified{Colors.RESET}")

def display_process_investigation(data):
    """Display detailed process investigation results."""
    clear_screen()
    
    # Header
    print(f"{Colors.CYAN}┌{'─' * 50}┐{Colors.RESET}")
    print(f"{Colors.CYAN}│ {Colors.BRIGHT_CYAN}PROCESS INVESTIGATION: {Colors.ORANGE}{data['name']:<24}{Colors.CYAN} │{Colors.RESET}")
    print(f"{Colors.CYAN}└{'─' * 50}┘{Colors.RESET}")
    
    # Status
    running_status = f"{Colors.GREEN}RUNNING ({data['instances_count']} instances){Colors.RESET}" if data['running'] else f"{Colors.RED}NOT RUNNING{Colors.RESET}"
    whitelist_status = f"{Colors.GREEN}WHITELISTED{Colors.RESET}" if data.get('whitelisted', False) else f"{Colors.RED}NOT WHITELISTED{Colors.RESET}"
    
    print(f"\n{Colors.BRIGHT_WHITE}Status:{Colors.RESET} {running_status}")
    print(f"{Colors.BRIGHT_WHITE}Whitelist:{Colors.RESET} {whitelist_status}")
    
    # Risk Assessment
    if 'risk_assessment' in data:
        print_section("RISK ASSESSMENT")
        display_risk_assessment(data['risk_assessment'])
    
    # Current Process Info
    if data['running'] and 'process_info' in data:
        print_section("CURRENT PROCESS INFORMATION")
        info = data['process_info']
        print(f"{Colors.BRIGHT_WHITE}PID:{Colors.RESET} {Colors.ORANGE}{info.get('pid', 'N/A')}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}User:{Colors.RESET} {Colors.ORANGE}{info.get('username', 'N/A')}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}Status:{Colors.RESET} {Colors.ORANGE}{info.get('status', 'N/A')}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}Started:{Colors.RESET} {Colors.ORANGE}{info.get('created', 'N/A')}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}CPU Usage:{Colors.RESET} {format_percentage(info.get('cpu_percent', 0))}")
        print(f"{Colors.BRIGHT_WHITE}Memory Usage:{Colors.RESET} {format_percentage(info.get('memory_percent', 0))}")
        
        # Command line and paths
        if 'command_line' in info and info['command_line']:
            cmdline = " ".join(info['command_line'])
            print(f"\n{Colors.BRIGHT_WHITE}Command Line:{Colors.RESET}")
            print(f"  {Colors.CYAN}{cmdline}{Colors.RESET}")
        
        if 'executable' in info and info['executable'] != "Access denied":
            print(f"\n{Colors.BRIGHT_WHITE}Executable Path:{Colors.RESET}")
            print(f"  {Colors.CYAN}{info['executable']}{Colors.RESET}")
            
        if 'working_directory' in info and info['working_directory'] != "Access denied":
            print(f"\n{Colors.BRIGHT_WHITE}Working Directory:{Colors.RESET}")
            print(f"  {Colors.CYAN}{info['working_directory']}{Colors.RESET}")
    
    # Open Files
    if data['running'] and 'file_info' in data and 'open_files' in data['file_info']:
        print_section("OPEN FILES")
        open_files = data['file_info']['open_files']
        
        if open_files:
            for file in open_files[:10]:  # Limit to 10 files
                file_type = file.get('type', 'unknown')
                type_color = Colors.GREEN if file_type in ['executable', 'library'] else Colors.CYAN
                print(f"  {type_color}[{file_type}]{Colors.RESET} {Colors.ORANGE}{file.get('name', 'N/A')}{Colors.RESET}")
            
            if len(open_files) > 10:
                print(f"  ... and {len(open_files) - 10} more files")
        else:
            print(f"  {Colors.DARK_GRAY}No open files detected{Colors.RESET}")
    
    # Active Network Connections
    if data['running'] and 'network_info' in data and 'active_connections' in data['network_info']:
        print_section("ACTIVE NETWORK CONNECTIONS")
        connections = data['network_info']['active_connections']
        
        if connections:
            for conn in connections:
                status_color = Colors.GREEN if conn['status'] == 'ESTABLISHED' else Colors.DARK_GRAY
                print(f"  {status_color}{conn['status']:<12}{Colors.RESET} | "
                      f"{Colors.CYAN}{conn['local_address']:<22}{Colors.RESET} -> "
                      f"{Colors.ORANGE}{conn['remote_address']:<22}{Colors.RESET} | "
                      f"{conn['type']}")
        else:
            print(f"  {Colors.DARK_GRAY}No active network connections{Colors.RESET}")
    
    # Historical Data
    print_section("HISTORICAL DATA")
    print(f"{Colors.BRIGHT_WHITE}Process Samples:{Colors.RESET} {Colors.ORANGE}{len(data['history'])}{Colors.RESET}")
    print(f"{Colors.BRIGHT_WHITE}Network Events:{Colors.RESET} {Colors.ORANGE}{len(data['network'])}{Colors.RESET}")
    print(f"{Colors.BRIGHT_WHITE}Alert Events:{Colors.RESET} {Colors.ORANGE}{len(data['alerts'])}{Colors.RESET}")
    
    # Recent Alerts
    if data['alerts']:
        print_section("RECENT ALERTS")
        for alert in data['alerts'][:5]:  # Show top 5 alerts
            severity = alert.get('severity', 'unknown')
            severity_color = get_alert_color(severity)
            print(f"  {Colors.DARK_GRAY}{alert['timestamp']}{Colors.RESET} | "
                  f"{severity_color}[{severity.upper()}]{Colors.RESET} | "
                  f"{Colors.BRIGHT_WHITE}{alert['description']}{Colors.RESET}")
    
    # Frequent Network Connections
    if data['frequent_connections']:
        print_section("FREQUENT NETWORK CONNECTIONS")
        for conn in data['frequent_connections'][:5]:  # Show top 5 connections
            print(f"  {Colors.CYAN}{conn['dst_ip']:>15}{Colors.RESET}:"
                  f"{Colors.ORANGE}{conn['dst_port']:<5}{Colors.RESET} | "
                  f"Count: {Colors.BRIGHT_CYAN}{conn['count']}{Colors.RESET}")

def display_process_list(db_path="monitor.db", hours=24, sort_by="cpu"):
    """Display a list of processes with additional details."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        time_threshold = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        # Different sorting options
        if sort_by == "cpu":
            order_by = "avg_cpu DESC"
        elif sort_by == "memory":
            order_by = "avg_mem DESC"
        elif sort_by == "connections":
            order_by = "total_connections DESC"
        else:
            order_by = "avg_cpu DESC"
        
        cursor.execute(f"""
        SELECT name, AVG(cpu_percent) as avg_cpu, MAX(cpu_percent) as max_cpu,
               AVG(memory_percent) as avg_mem, MAX(memory_percent) as max_mem,
               COUNT(*) as samples, 
               SUM(connections) as total_connections
        FROM processes
        WHERE timestamp > ?
        GROUP BY name
        ORDER BY {order_by}
        LIMIT 30
        """, (time_threshold,))
        
        processes = cursor.fetchall()
        
        # Get alert counts for each process
        process_alerts = {}
        cursor.execute("""
        SELECT process_name, COUNT(*) as alert_count
        FROM alerts
        WHERE timestamp > ?
        GROUP BY process_name
        """, (time_threshold,))
        
        for row in cursor.fetchall():
            if row[0]:  # Ensure process_name is not None
                process_alerts[row[0]] = row[1]
        
        conn.close()
        
        # Display the processes
        clear_screen()
        print(f"{Colors.CYAN}┌{'─' * 60}┐{Colors.RESET}")
        print(f"{Colors.CYAN}│ {Colors.BRIGHT_CYAN}PROCESS MONITOR - TOP PROCESSES {Colors.ORANGE}(LAST {hours}H){Colors.CYAN}{' ' * 14}│{Colors.RESET}")
        print(f"{Colors.CYAN}└{'─' * 60}┘{Colors.RESET}")
        
        # Table header
        print(f"\n{Colors.BRIGHT_WHITE}{'PROCESS':<20} | {'CPU AVG':>7} | {'MEM AVG':>7} | {'CONN':>6} | {'ALERTS':>6} | {'SAMPLES':>7}{Colors.RESET}")
        print(f"{Colors.DARK_GRAY}{'─' * 70}{Colors.RESET}")
        
        # Table rows
        for proc in processes:
            name = proc[0]
            avg_cpu = proc[1]
            avg_mem = proc[3] 
            connections = proc[6] or 0
            samples = proc[5]
            alerts = process_alerts.get(name, 0)
            
            # Color coding
            name_color = Colors.BRIGHT_WHITE
            alert_color = Colors.GREEN if alerts == 0 else Colors.ORANGE if alerts < 5 else Colors.RED
            
            print(f"{name_color}{name[:19]:<20}{Colors.RESET} | "
                  f"{format_percentage(avg_cpu):>7} | "
                  f"{format_percentage(avg_mem):>7} | "
                  f"{Colors.BRIGHT_CYAN}{connections:>6}{Colors.RESET} | "
                  f"{alert_color}{alerts:>6}{Colors.RESET} | "
                  f"{Colors.DARK_GRAY}{samples:>7}{Colors.RESET}")
        
        return processes
        
    except sqlite3.Error as e:
        print(f"{Colors.RED}Database error: {e}{Colors.RESET}")
        return []
    except Exception as e:
        print(f"{Colors.RED}Error displaying process list: {e}{Colors.RESET}")
        return []

def display_network_activity(db_path="monitor.db", hours=24, limit=20):
    """Display network activity summary."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        time_threshold = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        # Get top connections by process
        cursor.execute("""
        SELECT process_name, dst_ip, COUNT(*) as connection_count
        FROM network_traffic
        WHERE timestamp > ?
        GROUP BY process_name, dst_ip
        ORDER BY connection_count DESC
        LIMIT ?
        """, (time_threshold, limit))
        
        connections = cursor.fetchall()
        
        # Get top destination IPs overall
        cursor.execute("""
        SELECT dst_ip, COUNT(*) as connection_count
        FROM network_traffic
        WHERE timestamp > ?
        GROUP BY dst_ip
        ORDER BY connection_count DESC
        LIMIT ?
        """, (time_threshold, limit))
        
        ips = cursor.fetchall()
        
        # Get top destination ports
        cursor.execute("""
        SELECT dst_port, COUNT(*) as connection_count
        FROM network_traffic
        WHERE timestamp > ?
        GROUP BY dst_port
        ORDER BY connection_count DESC
        LIMIT ?
        """, (time_threshold, limit))
        
        ports = cursor.fetchall()
        
        conn.close()
        
        # Display the network activity
        clear_screen()
        print(f"{Colors.CYAN}┌{'─' * 60}┐{Colors.RESET}")
        print(f"{Colors.CYAN}│ {Colors.BRIGHT_CYAN}NETWORK ACTIVITY MONITOR {Colors.ORANGE}(LAST {hours}H){Colors.CYAN}{' ' * 22}│{Colors.RESET}")
        print(f"{Colors.CYAN}└{'─' * 60}┘{Colors.RESET}")
        
        # Top processes and destinations
        print_section("TOP PROCESS-DESTINATION COMBINATIONS")
        
        if connections:
            for conn in connections[:10]:  # Limit to 10 for cleaner display
                process = conn[0] or "Unknown"
                dst_ip = conn[1]
                count = conn[2]
                
                print(f"{Colors.BRIGHT_WHITE}{process[:15]:<15}{Colors.RESET} | "
                      f"{Colors.CYAN}{dst_ip:>15}{Colors.RESET} | "
                      f"Count: {Colors.BRIGHT_CYAN}{count}{Colors.RESET}")
        else:
            print(f"{Colors.DARK_GRAY}No network data available{Colors.RESET}")
        
        # Top destination IPs
        print_section("TOP DESTINATION IPs")
        
        if ips:
            for ip in ips[:10]:
                dst_ip = ip[0]
                count = ip[1]
                
                print(f"{Colors.CYAN}{dst_ip:>15}{Colors.RESET} | "
                      f"Connections: {Colors.BRIGHT_CYAN}{count}{Colors.RESET}")
        
        # Top destination ports
        print_section("TOP DESTINATION PORTS")
        
        if ports:
            for port in ports[:10]:
                dst_port = port[0]
                count = port[1]
                
                # Add common service names for well-known ports
                service_name = ""
                if dst_port == 80:
                    service_name = "HTTP"
                elif dst_port == 443:
                    service_name = "HTTPS"
                elif dst_port == 22:
                    service_name = "SSH"
                elif dst_port == 53:
                    service_name = "DNS"
                
                port_info = f"{dst_port}"
                if service_name:
                    port_info += f" ({service_name})"
                
                print(f"{Colors.ORANGE}{port_info:<15}{Colors.RESET} | "
                      f"Connections: {Colors.BRIGHT_CYAN}{count}{Colors.RESET}")
        
        return {
            "connections": connections,
            "ips": ips,
            "ports": ports
        }
        
    except sqlite3.Error as e:
        print(f"{Colors.RED}Database error: {e}{Colors.RESET}")
        return None
    except Exception as e:
        print(f"{Colors.RED}Error displaying network activity: {e}{Colors.RESET}")
        return None

def display_alert_dashboard(db_path="monitor.db", hours=24, severity=None, limit=50):
    """Display security alerts dashboard."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        time_threshold = (datetime.now() - timedelta(hours=hours)).isoformat()
        
        # Get alert counts by type
        cursor.execute("""
        SELECT alert_type, COUNT(*) as count 
        FROM alerts 
        WHERE timestamp > ?
        GROUP BY alert_type
        ORDER BY count DESC
        """, (time_threshold,))
        
        alert_types = cursor.fetchall()
        
        # Get alert counts by severity
        cursor.execute("""
        SELECT severity, COUNT(*) as count 
        FROM alerts 
        WHERE timestamp > ?
        GROUP BY severity
        ORDER BY count DESC
        """, (time_threshold,))
        
        severities = cursor.fetchall()
        
        # Get recent alerts, filtered by severity if specified
        if severity:
            cursor.execute("""
            SELECT timestamp, alert_type, severity, description, process_name, source_ip, destination_ip
            FROM alerts
            WHERE timestamp > ? AND severity = ?
            ORDER BY timestamp DESC
            LIMIT ?
            """, (time_threshold, severity, limit))
        else:
            cursor.execute("""
            SELECT timestamp, alert_type, severity, description, process_name, source_ip, destination_ip
            FROM alerts
            WHERE timestamp > ?
            ORDER BY timestamp DESC
            LIMIT ?
            """, (time_threshold, limit))
        
        alerts = cursor.fetchall()
        
        # Get top processes with alerts
        cursor.execute("""
        SELECT process_name, COUNT(*) as count
        FROM alerts
        WHERE timestamp > ? AND process_name IS NOT NULL
        GROUP BY process_name
        ORDER BY count DESC
        LIMIT 10
        """, (time_threshold,))
        
        processes = cursor.fetchall()
        
        conn.close()
        
        # Display the alerts dashboard
        clear_screen()
        print(f"{Colors.CYAN}┌{'─' * 60}┐{Colors.RESET}")
        print(f"{Colors.CYAN}│ {Colors.BRIGHT_CYAN}SECURITY ALERTS DASHBOARD {Colors.ORANGE}(LAST {hours}H){Colors.CYAN}{' ' * 19}│{Colors.RESET}")
        print(f"{Colors.CYAN}└{'─' * 60}┘{Colors.RESET}")
        
        # Summary statistics
        print_section("ALERT SUMMARY")
        
        total_alerts = sum(count for _, count in alert_types)
        severity_counts = {sev: count for sev, count in severities}
        
        # Format total with color based on count
        total_color = Colors.GREEN if total_alerts == 0 else Colors.ORANGE if total_alerts < 10 else Colors.RED
        print(f"{Colors.BRIGHT_WHITE}Total Alerts:{Colors.RESET} {total_color}{total_alerts}{Colors.RESET}")
        
        # Show filtered message if using severity filter
        if severity:
            print(f"{Colors.BRIGHT_WHITE}Filter:{Colors.RESET} {get_alert_color(severity)}Showing {severity.upper()} severity alerts only{Colors.RESET}")
        
        # Alert breakdown by severity
        print(f"\n{Colors.BRIGHT_WHITE}By Severity:{Colors.RESET}")
        for sev in ["high", "medium", "low"]:
            count = severity_counts.get(sev, 0)
            sev_color = get_alert_color(sev)
            print(f"  {sev_color}{sev.upper():<10}{Colors.RESET}: {Colors.BRIGHT_CYAN}{count}{Colors.RESET}")
        
        # Alert breakdown by type
        if alert_types:
            print(f"\n{Colors.BRIGHT_WHITE}By Type:{Colors.RESET}")
            for alert_type, count in alert_types[:5]:  # Show top 5 types
                print(f"  {Colors.YELLOW}{alert_type:<20}{Colors.RESET}: {Colors.BRIGHT_CYAN}{count}{Colors.RESET}")
        
        # Top processes with alerts
        if processes:
            print_section("TOP PROCESSES WITH ALERTS")
            for process, count in processes[:5]:  # Show top 5 processes
                print(f"{Colors.BRIGHT_WHITE}{process[:20]:<20}{Colors.RESET} | "
                      f"Alerts: {Colors.BRIGHT_CYAN}{count}{Colors.RESET}")
        
        # Recent alerts
        print_section("RECENT ALERTS")
        
        if alerts:
            for alert in alerts[:15]:  # Limit to 15 most recent alerts
                timestamp = alert[0]
                alert_type = alert[1]
                severity = alert[2]
                description = alert[3]
                process = alert[4] or "Unknown"
                
                severity_color = get_alert_color(severity)
                
                print(f"{Colors.DARK_GRAY}{timestamp}{Colors.RESET} | "
                      f"{severity_color}[{severity.upper()}]{Colors.RESET} | "
                      f"{Colors.ORANGE}{alert_type:<15}{Colors.RESET} | "
                      f"{Colors.BRIGHT_WHITE}{description}{Colors.RESET}")
                print(f"  {Colors.DARK_GRAY}Process: {process}{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}✓ No alerts detected during this period.{Colors.RESET}")
        
        return {
            "total": total_alerts,
            "by_severity": severities,
            "by_type": alert_types,
            "recent": alerts
        }
        
    except sqlite3.Error as e:
        print(f"{Colors.RED}Database error: {e}{Colors.RESET}")
        return None
    except Exception as e:
        print(f"{Colors.RED}Error displaying alerts: {e}{Colors.RESET}")
        return None

def display_stats(db_path="monitor.db"):
    """Display system-wide statistics."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Alert stats
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE timestamp > datetime('now', '-24 hours')")
        alert_count = cursor.fetchone()[0]
        
        cursor.execute("""
        SELECT severity, COUNT(*) as count 
        FROM alerts 
        WHERE timestamp > datetime('now', '-24 hours')
        GROUP BY severity
        """)
        severity_counts = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Process stats
        cursor.execute("SELECT COUNT(DISTINCT name) FROM processes WHERE timestamp > datetime('now', '-24 hours')")
        process_count = cursor.fetchone()[0]
        
        # Network stats
        cursor.execute("SELECT COUNT(*) FROM network_traffic WHERE timestamp > datetime('now', '-24 hours')")
        connection_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT dst_ip) FROM network_traffic WHERE timestamp > datetime('now', '-24 hours')")
        destination_count = cursor.fetchone()[0]
        
        conn.close()
        
        # Display stats
        clear_screen()
        print(f"{Colors.CYAN}┌{'─' * 46}┐{Colors.RESET}")
        print(f"{Colors.CYAN}│ {Colors.BRIGHT_CYAN}SYSTEM STATISTICS {Colors.ORANGE}(LAST 24H){Colors.CYAN}{' ' * 18}│{Colors.RESET}")
        print(f"{Colors.CYAN}└{'─' * 46}┘{Colors.RESET}")
        
        print_section("SECURITY")
        
        # Color alerts based on counts
        alert_color = Colors.GREEN if alert_count == 0 else Colors.ORANGE if alert_count < 10 else Colors.RED
        high_color = Colors.RED if severity_counts.get("high", 0) > 0 else Colors.GREEN
        
        print(f"{Colors.BRIGHT_WHITE}Total Alerts:{Colors.RESET} {alert_color}{alert_count}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}High Severity:{Colors.RESET} {high_color}{severity_counts.get('high', 0)}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}Medium Severity:{Colors.RESET} {Colors.ORANGE}{severity_counts.get('medium', 0)}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}Low Severity:{Colors.RESET} {Colors.GREEN}{severity_counts.get('low', 0)}{Colors.RESET}")
        
        print_section("SYSTEM")
        print(f"{Colors.BRIGHT_WHITE}Monitored Processes:{Colors.RESET} {Colors.BRIGHT_CYAN}{process_count}{Colors.RESET}")
        
        print_section("NETWORK")
        print(f"{Colors.BRIGHT_WHITE}Total Connections:{Colors.RESET} {Colors.BRIGHT_CYAN}{connection_count}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}Unique Destinations:{Colors.RESET} {Colors.BRIGHT_CYAN}{destination_count}{Colors.RESET}")
        
        # Current system status if available
        try:
            print_section("CURRENT STATUS")
            
            # CPU and memory
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            
            # Disk usage for root
            disk = psutil.disk_usage('/')
            
            # Network IO
            net_io = psutil.net_io_counters()
            
            # Format and display
            print(f"{Colors.BRIGHT_WHITE}CPU Usage:{Colors.RESET} {format_percentage(cpu_percent)}")
            print(f"{Colors.BRIGHT_WHITE}Memory Usage:{Colors.RESET} {format_percentage(memory.percent)}")
            print(f"{Colors.BRIGHT_WHITE}Disk Usage:{Colors.RESET} {format_percentage(disk.percent)}")
            print(f"{Colors.BRIGHT_WHITE}Network IO:{Colors.RESET} "
                  f"{Colors.ORANGE}↑{net_io.bytes_sent / (1024*1024):.2f} MB{Colors.RESET} / "
                  f"{Colors.CYAN}↓{net_io.bytes_recv / (1024*1024):.2f} MB{Colors.RESET}")
        except:
            # If psutil functions fail, skip this section
            pass
        
        return {
            "alerts": {
                "total": alert_count,
                "by_severity": severity_counts
            },
            "processes": {
                "total": process_count
            },
            "network": {
                "connections": connection_count,
                "destinations": destination_count
            }
        }
        
    except sqlite3.Error as e:
        print(f"{Colors.RED}Database error: {e}{Colors.RESET}")
        return None
    except Exception as e:
        print(f"{Colors.RED}Error displaying system stats: {e}{Colors.RESET}")
        return None

def interactive_menu(db_path="monitor.db"):
    """Display an enhanced interactive menu with drill-down options."""
    while True:
        clear_screen()
        print(f"""
{Colors.CYAN}┌────────────────────────────────────────┐
{Colors.CYAN}│ {Colors.BRIGHT_CYAN}NOIDMON {Colors.ORANGE}SYSTEM {Colors.BRIGHT_CYAN}MONITOR {Colors.CYAN}           │
{Colors.CYAN}└────────────────────────────────────────┘

{Colors.BRIGHT_CYAN}SELECT OPTION:{Colors.RESET}

{Colors.CYAN}  1) {Colors.BRIGHT_WHITE}System Summary{Colors.RESET}
{Colors.CYAN}  2) {Colors.BRIGHT_WHITE}Process Monitor{Colors.RESET}
{Colors.CYAN}  3) {Colors.BRIGHT_WHITE}Network Monitor{Colors.RESET}
{Colors.CYAN}  4) {Colors.BRIGHT_WHITE}Security Alerts{Colors.RESET}
{Colors.CYAN}  5) {Colors.BRIGHT_WHITE}System Statistics{Colors.RESET}
{Colors.CYAN}  6) {Colors.BRIGHT_WHITE}Process Investigator{Colors.RESET}
{Colors.CYAN}  7) {Colors.BRIGHT_WHITE}Real-time Monitor{Colors.RESET}
{Colors.CYAN}  8) {Colors.BRIGHT_WHITE}Whitelist Manager{Colors.RESET}
{Colors.CYAN}  9) {Colors.BRIGHT_WHITE}Reports{Colors.RESET}
{Colors.ORANGE}  0) {Colors.BRIGHT_WHITE}Exit{Colors.RESET}

{Colors.CYAN}──────────────────────────────────────────
""")
        
        choice = input(f"{Colors.CYAN}> {Colors.RESET}")
        
        if choice == "1":
            clear_screen()
            print_status("Loading System Summary")
            data = get_system_summary(db_path)
            display_system_summary(data)
            print(f"\n{Colors.ORANGE}[ Press Enter to return to menu ]{Colors.RESET}")
            input()
        
        elif choice == "2":
            # Process Monitor submenu
            while True:
                clear_screen()
                print(f"""
{Colors.CYAN}┌────────────────────────────────────────┐
{Colors.CYAN}│ {Colors.BRIGHT_CYAN}PROCESS {Colors.ORANGE}MONITOR {Colors.CYAN}                  │
{Colors.CYAN}└────────────────────────────────────────┘

{Colors.BRIGHT_CYAN}SELECT VIEW:{Colors.RESET}

{Colors.CYAN}  1) {Colors.BRIGHT_WHITE}Top Processes by CPU{Colors.RESET}
{Colors.CYAN}  2) {Colors.BRIGHT_WHITE}Top Processes by Memory{Colors.RESET}
{Colors.CYAN}  3) {Colors.BRIGHT_WHITE}Top Processes by Network Activity{Colors.RESET}
{Colors.CYAN}  4) {Colors.BRIGHT_WHITE}Last 24 Hours{Colors.RESET}
{Colors.CYAN}  5) {Colors.BRIGHT_WHITE}Last 7 Days{Colors.RESET}
{Colors.ORANGE}  0) {Colors.BRIGHT_WHITE}Back to Main Menu{Colors.RESET}

{Colors.CYAN}──────────────────────────────────────────
""")
                
                sub_choice = input(f"{Colors.CYAN}> {Colors.RESET}")
                
                if sub_choice == "1":
                    processes = display_process_list(db_path, 24, "cpu")
                    
                    print(f"\n{Colors.BRIGHT_CYAN}Enter process name to investigate (or Enter to return):{Colors.RESET}")
                    process_name = input(f"{Colors.CYAN}> {Colors.RESET}")
                    
                    if process_name.strip():
                        process_data = investigate_process(db_path, process_name)
                        display_process_investigation(process_data)
                        print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                        input()
                    
                elif sub_choice == "2":
                    processes = display_process_list(db_path, 24, "memory")
                    
                    print(f"\n{Colors.BRIGHT_CYAN}Enter process name to investigate (or Enter to return):{Colors.RESET}")
                    process_name = input(f"{Colors.CYAN}> {Colors.RESET}")
                    
                    if process_name.strip():
                        process_data = investigate_process(db_path, process_name)
                        display_process_investigation(process_data)
                        print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                        input()
                    
                elif sub_choice == "3":
                    processes = display_process_list(db_path, 24, "connections")
                    
                    print(f"\n{Colors.BRIGHT_CYAN}Enter process name to investigate (or Enter to return):{Colors.RESET}")
                    process_name = input(f"{Colors.CYAN}> {Colors.RESET}")
                    
                    if process_name.strip():
                        process_data = investigate_process(db_path, process_name)
                        display_process_investigation(process_data)
                        print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                        input()
                    
                elif sub_choice == "4":
                    processes = display_process_list(db_path, 24)
                    print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                    input()
                    
                elif sub_choice == "5":
                    processes = display_process_list(db_path, 168)  # 7 days = 168 hours
                    print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                    input()
                    
                elif sub_choice == "0":
                    break
        
        elif choice == "3":
            # Network Monitor submenu
            while True:
                clear_screen()
                print(f"""
{Colors.CYAN}┌────────────────────────────────────────┐
{Colors.CYAN}│ {Colors.BRIGHT_CYAN}NETWORK {Colors.ORANGE}MONITOR {Colors.CYAN}                  │
{Colors.CYAN}└────────────────────────────────────────┘

{Colors.BRIGHT_CYAN}SELECT VIEW:{Colors.RESET}

{Colors.CYAN}  1) {Colors.BRIGHT_WHITE}Last Hour Activity{Colors.RESET}
{Colors.CYAN}  2) {Colors.BRIGHT_WHITE}Last 24 Hours Activity{Colors.RESET}
{Colors.CYAN}  3) {Colors.BRIGHT_WHITE}Last 7 Days Activity{Colors.RESET}
{Colors.ORANGE}  0) {Colors.BRIGHT_WHITE}Back to Main Menu{Colors.RESET}

{Colors.CYAN}──────────────────────────────────────────
""")
                
                sub_choice = input(f"{Colors.CYAN}> {Colors.RESET}")
                
                if sub_choice == "1":
                    display_network_activity(db_path, 1)
                    print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                    input()
                    
                elif sub_choice == "2":
                    display_network_activity(db_path, 24)
                    print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                    input()
                    
                elif sub_choice == "3":
                    display_network_activity(db_path, 168)  # 7 days = 168 hours
                    print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                    input()
                    
                elif sub_choice == "0":
                    break
        
        elif choice == "4":
            # Security Alerts submenu
            while True:
                clear_screen()
                print(f"""
{Colors.CYAN}┌────────────────────────────────────────┐
{Colors.CYAN}│ {Colors.BRIGHT_CYAN}SECURITY {Colors.ORANGE}ALERTS {Colors.CYAN}                  │
{Colors.CYAN}└────────────────────────────────────────┘

{Colors.BRIGHT_CYAN}SELECT VIEW:{Colors.RESET}

{Colors.CYAN}  1) {Colors.BRIGHT_WHITE}All Alerts{Colors.RESET}
{Colors.CYAN}  2) {Colors.RED}High Severity Alerts{Colors.RESET}
{Colors.CYAN}  3) {Colors.ORANGE}Medium Severity Alerts{Colors.RESET}
{Colors.CYAN}  4) {Colors.GREEN}Low Severity Alerts{Colors.RESET}
{Colors.CYAN}  5) {Colors.BRIGHT_WHITE}Last Hour Alerts{Colors.RESET}
{Colors.CYAN}  6) {Colors.BRIGHT_WHITE}Last 7 Days Alerts{Colors.RESET}
{Colors.ORANGE}  0) {Colors.BRIGHT_WHITE}Back to Main Menu{Colors.RESET}

{Colors.CYAN}──────────────────────────────────────────
""")
                
                sub_choice = input(f"{Colors.CYAN}> {Colors.RESET}")
                
                if sub_choice == "1":
                    display_alert_dashboard(db_path, 24)
                    print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                    input()
                    
                elif sub_choice == "2":
                    display_alert_dashboard(db_path, 24, "high")
                    print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                    input()
                    
                elif sub_choice == "3":
                    display_alert_dashboard(db_path, 24, "medium")
                    print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                    input()
                    
                elif sub_choice == "4":
                    display_alert_dashboard(db_path, 24, "low")
                    print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                    input()
                    
                elif sub_choice == "5":
                    display_alert_dashboard(db_path, 1)
                    print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                    input()
                    
                elif sub_choice == "6":
                    display_alert_dashboard(db_path, 168)  # 7 days
                    print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                    input()
                    
                elif sub_choice == "0":
                    break
        
        elif choice == "5":
            # System Statistics
            display_stats(db_path)
            print(f"\n{Colors.ORANGE}[ Press Enter to return to menu ]{Colors.RESET}")
            input()
        
        elif choice == "6":
            # Process Investigator
            clear_screen()
            print(f"{Colors.CYAN}┌────────────────────────────────────────┐{Colors.RESET}")
            print(f"{Colors.CYAN}│ {Colors.BRIGHT_CYAN}PROCESS {Colors.ORANGE}INVESTIGATOR {Colors.CYAN}               │{Colors.RESET}")
            print(f"{Colors.CYAN}└────────────────────────────────────────┘{Colors.RESET}")
            
            print(f"\n{Colors.BRIGHT_CYAN}Enter process name to investigate:{Colors.RESET}")
            process_name = input(f"{Colors.CYAN}> {Colors.RESET}")
            
            if process_name.strip():
                print_status(f"Investigating process {process_name}")
                process_data = investigate_process(db_path, process_name)
                display_process_investigation(process_data)
                
                # Process actions submenu
                if process_data['running']:
                    print(f"\n{Colors.BRIGHT_CYAN}ACTIONS:{Colors.RESET}")
                    print(f"{Colors.CYAN}  1) {Colors.BRIGHT_WHITE}Export Process Data{Colors.RESET}")
                    print(f"{Colors.CYAN}  2) {Colors.BRIGHT_WHITE}Add to Whitelist{Colors.RESET}")
                    print(f"{Colors.CYAN}  3) {Colors.RED}Terminate Process{Colors.RESET}")
                    print(f"{Colors.ORANGE}  0) {Colors.BRIGHT_WHITE}Return to Menu{Colors.RESET}")
                    
                    action = input(f"\n{Colors.CYAN}> {Colors.RESET}")
                    
                    if action == "1":
                        export_process_data(db_path, process_name)
                        print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                        input()
                    elif action == "2":
                        reason = input(f"{Colors.CYAN}Enter reason for whitelisting: {Colors.RESET}")
                        add_to_whitelist(db_path, process_name, reason)
                        print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                        input()
                    elif action == "3":
                        confirm = input(f"{Colors.RED}Are you sure you want to terminate {process_name}? (y/n): {Colors.RESET}")
                        if confirm.lower() == 'y':
                            terminate_process(process_name)
                        print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                        input()
                else:
                    print(f"\n{Colors.ORANGE}[ Press Enter to return to menu ]{Colors.RESET}")
                    input()
            
        elif choice == "7":
            # Real-time Monitor
            try:
                clear_screen()
                print(f"{Colors.CYAN}┌─ {Colors.ORANGE}REAL-TIME MONITOR {Colors.CYAN}─┐{Colors.RESET}")
                print(f"{Colors.DARK_GRAY}Press Ctrl+C to exit{Colors.RESET}")
                print()
                
                while True:
                    clear_screen()
                    data = get_system_summary(db_path)
                    display_system_summary(data)
                    print(f"\n{Colors.DARK_GRAY}Auto-refresh in 5 seconds... (Press Ctrl+C to exit){Colors.RESET}")
                    time.sleep(5)
            except KeyboardInterrupt:
                pass
        
        elif choice == "8":
            # Whitelist Manager
            while True:
                clear_screen()
                print(f"{Colors.CYAN}┌────────────────────────────────────────┐{Colors.RESET}")
                print(f"{Colors.CYAN}│ {Colors.BRIGHT_CYAN}WHITELIST {Colors.ORANGE}MANAGER {Colors.CYAN}                │{Colors.RESET}")
                print(f"{Colors.CYAN}└────────────────────────────────────────┘{Colors.RESET}")
                
                whitelist = get_whitelist(db_path)
                
                if whitelist:
                    print(f"\n{Colors.BRIGHT_WHITE}{'PROCESS':<20} | {'REASON':<25} | {'ADDED BY':<10} | {'TIMESTAMP'}{Colors.RESET}")
                    print(f"{Colors.DARK_GRAY}{'─' * 80}{Colors.RESET}")
                    
                    for entry in whitelist:
                        name = entry['name']
                        reason = entry['reason']
                        added_by = entry['added_by']
                        timestamp = entry['timestamp']
                        
                        print(f"{Colors.GREEN}{name[:19]:<20}{Colors.RESET} | "
                              f"{Colors.BRIGHT_WHITE}{reason[:24]:<25}{Colors.RESET} | "
                              f"{Colors.CYAN}{added_by[:9]:<10}{Colors.RESET} | "
                              f"{Colors.DARK_GRAY}{timestamp}{Colors.RESET}")
                else:
                    print(f"\n{Colors.DARK_GRAY}No whitelisted processes found.{Colors.RESET}")
                
                print(f"\n{Colors.BRIGHT_CYAN}ACTIONS:{Colors.RESET}")
                print(f"{Colors.CYAN}  1) {Colors.BRIGHT_WHITE}Add Process to Whitelist{Colors.RESET}")
                print(f"{Colors.CYAN}  2) {Colors.BRIGHT_WHITE}Remove Process from Whitelist{Colors.RESET}")
                print(f"{Colors.ORANGE}  0) {Colors.BRIGHT_WHITE}Return to Menu{Colors.RESET}")
                
                action = input(f"\n{Colors.CYAN}> {Colors.RESET}")
                
                if action == "1":
                    name = input(f"{Colors.CYAN}Enter process name to whitelist: {Colors.RESET}")
                    if name.strip():
                        reason = input(f"{Colors.CYAN}Enter reason for whitelisting: {Colors.RESET}")
                        add_to_whitelist(db_path, name, reason)
                        print(f"\n{Colors.ORANGE}[ Press Enter to continue ]{Colors.RESET}")
                        input()
                
                elif action == "2":
                    name = input(f"{Colors.CYAN}Enter process name to remove from whitelist: {Colors.RESET}")
                    if name.strip():
                        remove_from_whitelist(db_path, name)
                        print(f"\n{Colors.ORANGE}[ Press Enter to continue ]{Colors.RESET}")
                        input()
                
                elif action == "0":
                    break
        
        elif choice == "9":
            # Reports submenu
            while True:
                clear_screen()
                print(f"""
{Colors.CYAN}┌────────────────────────────────────────┐
{Colors.CYAN}│ {Colors.BRIGHT_CYAN}REPORTS {Colors.ORANGE}MENU {Colors.CYAN}                     │
{Colors.CYAN}└────────────────────────────────────────┘

{Colors.BRIGHT_CYAN}SELECT REPORT:{Colors.RESET}

{Colors.CYAN}  1) {Colors.BRIGHT_WHITE}Daily Report{Colors.RESET}
{Colors.CYAN}  2) {Colors.BRIGHT_WHITE}Weekly Report{Colors.RESET}
{Colors.CYAN}  3) {Colors.BRIGHT_WHITE}Monthly Report{Colors.RESET}
{Colors.CYAN}  4) {Colors.BRIGHT_WHITE}Export Process Data{Colors.RESET}
{Colors.ORANGE}  0) {Colors.BRIGHT_WHITE}Back to Main Menu{Colors.RESET}

{Colors.CYAN}──────────────────────────────────────────
""")
                
                sub_choice = input(f"{Colors.CYAN}> {Colors.RESET}")
                
                if sub_choice == "1":
                    generate_report(db_path, "daily")
                    print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                    input()
                    
                elif sub_choice == "2":
                    generate_report(db_path, "weekly")
                    print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                    input()
                    
                elif sub_choice == "3":
                    generate_report(db_path, "monthly")
                    print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                    input()
                    
                elif sub_choice == "4":
                    name = input(f"{Colors.CYAN}Enter process name to export data: {Colors.RESET}")
                    if name.strip():
                        export_process_data(db_path, name)
                        print(f"\n{Colors.ORANGE}[ Press Enter to return ]{Colors.RESET}")
                        input()
                    
                elif sub_choice == "0":
                    break
        
        elif choice == "0":
            clear_screen()
            print(f"""
{Colors.CYAN}┌────────────────────────────────────────┐
{Colors.CYAN}│ {Colors.ORANGE}SESSION TERMINATED                  {Colors.CYAN}│
{Colors.CYAN}└────────────────────────────────────────┘
            """)
            time.sleep(0.5)
            clear_screen()
            break

def main():
    parser = argparse.ArgumentParser(
        description="Noidmon System Monitor CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  coolcli.py                      # Start interactive menu
  coolcli.py --summary            # Show current system summary
  coolcli.py --report daily       # Generate a daily report
  coolcli.py --process-list       # Show top processes
  coolcli.py --investigate firefox # Investigate a specific process
  coolcli.py --alerts             # View security alerts
  coolcli.py --network            # View network activity
  coolcli.py --stats              # Show system statistics
  coolcli.py --whitelist          # Manage process whitelist
  coolcli.py --export-process chrome # Export process data to JSON
        """
    )
    parser.add_argument(
        "--db", 
        type=str,
        default="monitor.db",
        help="Path to the database file (default: monitor.db)"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show current system summary"
    )
    parser.add_argument(
        "--report",
        choices=["daily", "weekly", "monthly"],
        help="Generate a report"
    )
    parser.add_argument(
        "--realtime",
        action="store_true",
        help="Show real-time monitor"
    )
    parser.add_argument(
        "--no-splash",
        action="store_true",
        help="Skip splash screen"
    )
    parser.add_argument(
        "--process-list",
        action="store_true",
        help="Show list of processes"
    )
    parser.add_argument(
        "--sort-by",
        choices=["cpu", "memory", "connections"],
        default="cpu",
        help="Sort process list by this metric (default: cpu)"
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Time period in hours for data analysis (default: 24)"
    )
    parser.add_argument(
        "--investigate",
        metavar="PROCESS_NAME",
        help="Investigate a specific process"
    )
    parser.add_argument(
        "--terminate",
        metavar="PROCESS_NAME",
        help="Terminate a process (must be running)"
    )
    parser.add_argument(
        "--alerts",
        action="store_true",
        help="View security alerts dashboard"
    )
    parser.add_argument(
        "--severity",
        choices=["high", "medium", "low"],
        help="Filter alerts by severity"
    )
    parser.add_argument(
        "--network",
        action="store_true",
        help="View network activity"
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show system statistics"
    )
    parser.add_argument(
        "--whitelist",
        action="store_true",
        help="View whitelisted processes"
    )
    parser.add_argument(
        "--add-to-whitelist",
        metavar="PROCESS_NAME",
        help="Add a process to whitelist"
    )
    parser.add_argument(
        "--reason",
        default="Added via CLI",
        help="Reason for whitelisting (used with --add-to-whitelist)"
    )
    parser.add_argument(
        "--remove-from-whitelist",
        metavar="PROCESS_NAME",
        help="Remove a process from whitelist"
    )
    parser.add_argument(
        "--export-process",
        metavar="PROCESS_NAME",
        help="Export process data to JSON file"
    )
    parser.add_argument(
        "--output-file",
        help="Output file for process data export"
    )
    
    args = parser.parse_args()
    
    if not args.no_splash:
        print_splash_screen()
    
    if args.summary:
        print_status("Loading System Summary")
        data = get_system_summary(args.db)
        display_system_summary(data)
        
    elif args.report:
        print_status(f"Generating {args.report.capitalize()} Report")
        generate_report(args.db, args.report)
        
    elif args.realtime:
        try:
            clear_screen()
            print(f"{Colors.CYAN}┌─ {Colors.ORANGE}REAL-TIME MONITOR {Colors.CYAN}─┐{Colors.RESET}")
            print(f"{Colors.DARK_GRAY}Press Ctrl+C to exit{Colors.RESET}")
            print()
            
            while True:
                clear_screen()
                data = get_system_summary(args.db)
                display_system_summary(data)
                print(f"\n{Colors.DARK_GRAY}Auto-refresh in 5 seconds... (Press Ctrl+C to exit){Colors.RESET}")
                time.sleep(5)
        except KeyboardInterrupt:
            print(f"\n{Colors.GREEN}Exiting real-time monitor{Colors.RESET}")
            
    elif args.process_list:
        display_process_list(args.db, args.hours, args.sort_by)
        
    elif args.investigate:
        print_status(f"Investigating process {args.investigate}")
        process_data = investigate_process(args.db, args.investigate)
        display_process_investigation(process_data)
        
    elif args.terminate:
        print_status(f"Attempting to terminate process {args.terminate}")
        terminate_process(args.terminate)
        
    elif args.alerts:
        display_alert_dashboard(args.db, args.hours, args.severity)
        
    elif args.network:
        display_network_activity(args.db, args.hours)
        
    elif args.stats:
        display_stats(args.db)
        
    elif args.whitelist:
        whitelist = get_whitelist(args.db)
        if whitelist:
            print(f"{Colors.CYAN}┌────────────────────────────────────────┐{Colors.RESET}")
            print(f"{Colors.CYAN}│ {Colors.BRIGHT_CYAN}WHITELISTED {Colors.ORANGE}PROCESSES {Colors.CYAN}              │{Colors.RESET}")
            print(f"{Colors.CYAN}└────────────────────────────────────────┘{Colors.RESET}")
            
            print(f"\n{Colors.BRIGHT_WHITE}{'PROCESS':<20} | {'REASON':<25} | {'ADDED BY':<10} | {'TIMESTAMP'}{Colors.RESET}")
            print(f"{Colors.DARK_GRAY}{'─' * 80}{Colors.RESET}")
            
            for entry in whitelist:
                name = entry['name']
                reason = entry['reason']
                added_by = entry['added_by']
                timestamp = entry['timestamp']
                
                print(f"{Colors.GREEN}{name[:19]:<20}{Colors.RESET} | "
                      f"{Colors.BRIGHT_WHITE}{reason[:24]:<25}{Colors.RESET} | "
                      f"{Colors.CYAN}{added_by[:9]:<10}{Colors.RESET} | "
                      f"{Colors.DARK_GRAY}{timestamp}{Colors.RESET}")
        else:
            print(f"{Colors.DARK_GRAY}No whitelisted processes found.{Colors.RESET}")
            
    elif args.add_to_whitelist:
        add_to_whitelist(args.db, args.add_to_whitelist, args.reason)
        
    elif args.remove_from_whitelist:
        remove_from_whitelist(args.db, args.remove_from_whitelist)
        
    elif args.export_process:
        export_process_data(args.db, args.export_process, args.output_file)
        
    else:
        interactive_menu(args.db)

if __name__ == "__main__":
    main()