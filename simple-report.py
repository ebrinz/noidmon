#!/usr/bin/env python3
"""
Simple Report Generator for macOS Monitor
-----------------------------------------
Generates reports from the monitoring database without pandas dependency.
"""

import os
import sys
import sqlite3
import argparse
from datetime import datetime, timedelta

def generate_report(db_path="monitor.db", report_type="daily", output_file=None):
    """Generate a simple text report from the monitoring database."""
    
    # Calculate time threshold based on report type
    if report_type == "daily":
        hours = 24
    elif report_type == "weekly":
        hours = 24 * 7
    elif report_type == "monthly":
        hours = 24 * 30
    else:
        hours = 24
    
    time_threshold = (datetime.now() - timedelta(hours=hours)).isoformat()
    
    # Connect to the database
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Build the report
        report = [
            f"macOS Process and Network Monitor Report",
            f"Report type: {report_type.capitalize()}",
            f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"\n{'-' * 80}\n",
        ]
        
        # Get alerts summary
        report.append("SECURITY ALERTS SUMMARY")
        report.append("-" * 80)
        
        cursor.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp > ?", 
            (time_threshold,)
        )
        alert_count = cursor.fetchone()[0]
        
        if alert_count > 0:
            report.append(f"Total alerts: {alert_count}")
            
            # Count by alert type
            cursor.execute(
                "SELECT alert_type, COUNT(*) FROM alerts WHERE timestamp > ? GROUP BY alert_type",
                (time_threshold,)
            )
            alert_types = cursor.fetchall()
            types_str = ", ".join([f"{t[0]}: {t[1]}" for t in alert_types])
            report.append(f"By type: {types_str}")
            
            # Count by severity
            cursor.execute(
                "SELECT severity, COUNT(*) FROM alerts WHERE timestamp > ? GROUP BY severity",
                (time_threshold,)
            )
            severities = cursor.fetchall()
            sev_str = ", ".join([f"{s[0]}: {s[1]}" for s in severities])
            report.append(f"By severity: {sev_str}")
            
            # Recent alerts
            report.append("\nMost recent alerts:")
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
                report.append(f"- [{alert[1].upper()}] {alert[0]}: {alert[2]}")
        else:
            report.append("No alerts detected during this period.")
        
        # Get process information
        report.append(f"\n{'-' * 80}\n")
        report.append("PROCESS ACTIVITY SUMMARY")
        report.append("-" * 80)
        
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
            report.append("\nTop processes by average CPU usage:")
            for proc in top_processes:
                report.append(f"- {proc[0]}: Avg: {proc[1]:.2f}%, Max: {proc[2]:.2f}%, Samples: {proc[3]}")
        else:
            report.append("No process data available for this period.")
        
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
            report.append("\nTop processes by average memory usage:")
            for proc in memory_processes:
                report.append(f"- {proc[0]}: Avg: {proc[1]:.2f}%, Max: {proc[2]:.2f}%")
        
        # Get network information
        report.append(f"\n{'-' * 80}\n")
        report.append("NETWORK ACTIVITY SUMMARY")
        report.append("-" * 80)
        
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
            report.append("\nTop processes by network activity:")
            for proc in process_traffic:
                report.append(f"- {proc[0]}: {proc[1]} connections")
        else:
            report.append("No network data available for this period.")
        
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
            report.append("\nTop destination IP addresses:")
            for ip in destination_ips:
                report.append(f"- {ip[0]}: {ip[1]} connections")
        
        # Close database
        conn.close()
        
        # Write report to file or stdout
        report_text = "\n".join(report)
        
        if output_file:
            output_path = output_file
        else:
            output_path = f"report_{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(output_path, 'w') as f:
            f.write(report_text)
        
        print(f"Report generated: {output_path}")
        return output_path
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    except Exception as e:
        print(f"Error generating report: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description="Generate reports from macOS Monitor database"
    )
    parser.add_argument(
        "--db", 
        type=str,
        default="monitor.db",
        help="Path to the database file (default: monitor.db)"
    )
    parser.add_argument(
        "--type", 
        choices=["daily", "weekly", "monthly"],
        default="daily",
        help="Report time period (default: daily)"
    )
    parser.add_argument(
        "--output", 
        type=str,
        help="Output file path (default: auto-generated filename)"
    )
    
    args = parser.parse_args()
    generate_report(args.db, args.type, args.output)

if __name__ == "__main__":
    main()