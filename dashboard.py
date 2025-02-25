#!/usr/bin/env python3
import sqlite3
import os
from flask import Flask, render_template, jsonify, request, Response
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['DATABASE'] = '/Users/crashy/gits/noidmon/monitor.db'

# Create templates directory if it doesn't exist
os.makedirs('/Users/crashy/gits/noidmon/templates', exist_ok=True)

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/alerts')
def get_alerts():
    hours = request.args.get('hours', 24, type=int)
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT timestamp, alert_type, severity, description, process_pid, process_name, source_ip, destination_ip
    FROM alerts
    WHERE timestamp > datetime('now', '-' || ? || ' hours')
    ORDER BY timestamp DESC
    LIMIT 100
    """, (hours,))
    
    alerts = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(alerts)

@app.route('/api/processes')
def get_processes():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT name, AVG(cpu_percent) as avg_cpu, MAX(cpu_percent) as max_cpu,
           AVG(memory_percent) as avg_mem, MAX(memory_percent) as max_mem,
           COUNT(*) as samples, 
           SUM(connections) as total_connections
    FROM processes
    WHERE timestamp > datetime('now', '-24 hours')
    GROUP BY name
    ORDER BY avg_cpu DESC
    LIMIT 20
    """)
    
    processes = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(processes)

@app.route('/api/process/<name>')
def get_process_details(name):
    if __name__ == '__main__':
        logger.debug(f"Process details requested for: {name}")
    
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Initialize with default values in case of error
        history = []
        alerts = []
        network = []
        connections = []
        risk_score = 10
        risk_factors = ["Basic risk assessment"]
        recommended_action = "Monitor"
        
        # Get process history
        try:
            cursor.execute("""
            SELECT timestamp, pid, cpu_percent, memory_percent, connections, cmdline, status
            FROM processes
            WHERE name = ? AND timestamp > datetime('now', '-24 hours')
            ORDER BY timestamp DESC
            LIMIT 100
            """, (name,))
            history = [dict(row) for row in cursor.fetchall()]
            if __name__ == '__main__':
                logger.debug(f"Process history records: {len(history)}")
        except Exception as e:
            if __name__ == '__main__':
                logger.error(f"Error getting process history: {str(e)}")
            risk_factors.append("Error retrieving process history")
        
        # Get related alerts
        try:
            cursor.execute("""
            SELECT timestamp, alert_type, severity, description, source_ip, destination_ip
            FROM alerts
            WHERE process_name = ? AND timestamp > datetime('now', '-24 hours')
            ORDER BY timestamp DESC
            """, (name,))
            alerts = [dict(row) for row in cursor.fetchall()]
            if __name__ == '__main__':
                logger.debug(f"Process alerts records: {len(alerts)}")
        except Exception as e:
            if __name__ == '__main__':
                logger.error(f"Error getting process alerts: {str(e)}")
            risk_factors.append("Error retrieving alerts")
        
        # Get network activity
        try:
            cursor.execute("""
            SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size
            FROM network_traffic
            WHERE process_name = ? AND timestamp > datetime('now', '-24 hours')
            ORDER BY timestamp DESC
            LIMIT 100
            """, (name,))
            network = [dict(row) for row in cursor.fetchall()]
            if __name__ == '__main__':
                logger.debug(f"Process network records: {len(network)}")
        except Exception as e:
            if __name__ == '__main__':
                logger.error(f"Error getting network activity: {str(e)}")
            risk_factors.append("Error retrieving network activity")
        
        # Get most frequent connections
        try:
            cursor.execute("""
            SELECT dst_ip, COUNT(*) as count, dst_port
            FROM network_traffic
            WHERE process_name = ? AND timestamp > datetime('now', '-24 hours')
            GROUP BY dst_ip, dst_port
            ORDER BY count DESC
            LIMIT 10
            """, (name,))
            connections = [dict(row) for row in cursor.fetchall()]
            if __name__ == '__main__':
                logger.debug(f"Frequent connections: {len(connections)}")
        except Exception as e:
            if __name__ == '__main__':
                logger.error(f"Error getting frequent connections: {str(e)}")
            risk_factors.append("Error retrieving connection data")
        
        # Calculate risk score based on various factors
        try:
            # Start with default score
            risk_score = 0
            risk_factors = []
            
            # Add baseline risk for any process with alerts
            if alerts:
                risk_score += 10
                risk_factors.append(f"Process has {len(alerts)} alert(s)")
            
            # Check for high CPU usage
            if history:
                max_cpu = max([h.get('cpu_percent', 0) for h in history] or [0])
                if max_cpu > 80:
                    risk_score += 20
                    risk_factors.append(f"High CPU usage detected ({max_cpu:.2f}%)")
                elif max_cpu > 50:
                    risk_score += 10
                    risk_factors.append(f"Moderate CPU usage ({max_cpu:.2f}%)")
            
            # Check for unusual connections
            unique_ips = len(set([n.get('dst_ip') for n in network if n.get('dst_ip')]))
            if unique_ips > 20:
                risk_score += 15
                risk_factors.append(f"Connects to many unique IPs ({unique_ips})")
            elif unique_ips > 10:
                risk_score += 5
                risk_factors.append(f"Connects to several unique IPs ({unique_ips})")
            
            # Check for alerts
            if len(alerts) > 0:
                high_severity = sum(1 for a in alerts if a.get('severity') == 'high')
                medium_severity = sum(1 for a in alerts if a.get('severity') == 'medium')
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
            
            # Check for known suspicious patterns in command line (simplified)
            if history and history[0].get('cmdline'):
                cmdline = history[0]['cmdline'].lower()
                suspicious_keywords = ['curl', 'wget', 'base64', 'exec', 'miner', 'coin', 'hash', '-xz', 'chmod']
                
                found_keywords = [kw for kw in suspicious_keywords if kw in cmdline]
                if found_keywords:
                    risk_score += 15
                    risk_factors.append(f"Command line contains suspicious keywords: {', '.join(found_keywords)}")
                    if len(found_keywords) > 2:
                        recommended_action = "Investigate immediately"
        
        except Exception as e:
            if __name__ == '__main__':
                logger.error(f"Error in risk assessment: {str(e)}")
            risk_score = 25
            risk_factors = ["Error during risk assessment", str(e)]
            recommended_action = "Unable to assess risk properly, monitor closely"
        
        conn.close()
        
        result = {
            'name': name,
            'history': history,
            'alerts': alerts,
            'network': network,
            'frequent_connections': connections,
            'risk_assessment': {
                'score': min(risk_score, 100),  # Cap at 100
                'factors': risk_factors,
                'recommended_action': recommended_action
            }
        }
        
        if __name__ == '__main__':
            logger.debug(f"Returning process details with risk score: {risk_score}")
        
        return jsonify(result)
        
    except Exception as e:
        if __name__ == '__main__':
            logger.error(f"Error in get_process_details: {str(e)}")
        return jsonify({
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
        })

@app.route('/api/network')
def get_network():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT process_name, src_ip, dst_ip, COUNT(*) as connection_count
    FROM network_traffic
    WHERE timestamp > datetime('now', '-24 hours')
    GROUP BY process_name, src_ip, dst_ip
    ORDER BY connection_count DESC
    LIMIT 20
    """)
    
    connections = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(connections)

@app.route('/api/stats')
def get_stats():
    conn = get_db()
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
    severity_counts = {row['severity']: row['count'] for row in cursor.fetchall()}
    
    # Process stats
    cursor.execute("SELECT COUNT(DISTINCT name) FROM processes WHERE timestamp > datetime('now', '-24 hours')")
    process_count = cursor.fetchone()[0]
    
    # Network stats
    cursor.execute("SELECT COUNT(*) FROM network_traffic WHERE timestamp > datetime('now', '-24 hours')")
    connection_count = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(DISTINCT dst_ip) FROM network_traffic WHERE timestamp > datetime('now', '-24 hours')")
    destination_count = cursor.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'alerts': {
            'total': alert_count,
            'by_severity': severity_counts
        },
        'processes': {
            'total': process_count
        },
        'network': {
            'connections': connection_count,
            'destinations': destination_count
        }
    })

@app.route('/api/ping')
def ping():
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

@app.route('/api/process/<name>/terminate', methods=['POST'])
def terminate_process(name):
    # Check if the process is whitelisted
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM whitelisted_processes WHERE name = ?", (name,))
    whitelist_entry = cursor.fetchone()
    conn.close()
    
    if whitelist_entry:
        return jsonify({
            "success": False,
            "message": f"Process {name} is whitelisted and cannot be terminated",
            "whitelisted": True
        })
    
    try:
        import psutil
        terminated_count = 0
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] == name:
                    psutil.Process(proc.info['pid']).terminate()
                    terminated_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        if terminated_count > 0:
            return jsonify({
                "success": True,
                "message": f"Successfully terminated {terminated_count} instances of {name}"
            })
        else:
            return jsonify({
                "success": False,
                "message": f"No active instances of {name} found to terminate"
            })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error terminating process: {str(e)}"
        })

@app.route('/api/process/<name>/export')
def export_process_data(name):
    conn = get_db()
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
    
    from flask import make_response
    import json
    
    # Create response with JSON data
    response = make_response(json.dumps(report, indent=2))
    response.headers["Content-Disposition"] = f"attachment; filename={name}_forensic_data.json"
    response.headers["Content-Type"] = "application/json"
    
    return response

@app.route('/api/whitelist')
def get_whitelist():
    """Get all whitelisted processes."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT name, reason, added_by, timestamp 
    FROM whitelisted_processes
    ORDER BY name
    """)
    
    whitelist = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(whitelist)

@app.route('/api/whitelist/<process_name>', methods=['POST'])
def add_to_whitelist(process_name):
    """Add a process to the whitelist."""
    reason = request.json.get('reason', 'Added by user')
    added_by = request.json.get('added_by', 'admin')
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
        INSERT INTO whitelisted_processes (name, reason, added_by, timestamp)
        VALUES (?, ?, ?, datetime('now'))
        """, (process_name, reason, added_by))
        conn.commit()
        success = True
        message = f"Process {process_name} added to whitelist"
    except sqlite3.IntegrityError:
        success = False
        message = f"Process {process_name} is already whitelisted"
    except Exception as e:
        success = False
        message = f"Error adding process to whitelist: {str(e)}"
    finally:
        conn.close()
    
    return jsonify({
        "success": success,
        "message": message
    })

@app.route('/api/whitelist/<process_name>', methods=['DELETE'])
def remove_from_whitelist(process_name):
    """Remove a process from the whitelist."""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM whitelisted_processes WHERE name = ?", (process_name,))
        conn.commit()
        
        if cursor.rowcount > 0:
            success = True
            message = f"Process {process_name} removed from whitelist"
        else:
            success = False
            message = f"Process {process_name} not found in whitelist"
    except Exception as e:
        success = False
        message = f"Error removing process from whitelist: {str(e)}"
    finally:
        conn.close()
    
    return jsonify({
        "success": success,
        "message": message
    })

@app.route('/api/process/<name>/investigate')
def investigate_process(name):
    """Detailed process investigation with system-level information."""
    if __name__ == '__main__':
        logger.debug(f"Process investigation requested for: {name}")
    
    try:
        import psutil
        import platform
        
        # Initialize the result structure
        result = {
            'name': name,
            'running': False,
            'instances_count': 0,
            'process_info': {},
            'file_info': {},
            'network_info': {},
            'can_use_claude': False,
            'history': [],
            'alerts': [],
            'network_history': [],
            'frequent_connections': [],
            'risk_assessment': {
                'score': 0,
                'factors': [],
                'recommended_action': "Monitor"
            }
        }
        
        # Get historical data from database
        conn = get_db()
        cursor = conn.cursor()
        
        # History
        cursor.execute("""
            SELECT timestamp, pid, cpu_percent, memory_percent, connections, cmdline, status
            FROM processes
            WHERE name = ? AND timestamp > datetime('now', '-24 hours')
            ORDER BY timestamp DESC
            LIMIT 100
        """, (name,))
        result['history'] = [dict(row) for row in cursor.fetchall()]
        
        # Alerts
        cursor.execute("""
            SELECT timestamp, alert_type, severity, description, source_ip, destination_ip
            FROM alerts
            WHERE process_name = ? AND timestamp > datetime('now', '-24 hours')
            ORDER BY timestamp DESC
        """, (name,))
        result['alerts'] = [dict(row) for row in cursor.fetchall()]
        
        # Network
        cursor.execute("""
            SELECT timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size
            FROM network_traffic
            WHERE process_name = ? AND timestamp > datetime('now', '-24 hours')
            ORDER BY timestamp DESC
            LIMIT 100
        """, (name,))
        result['network_history'] = [dict(row) for row in cursor.fetchall()]
        
        # Frequent connections
        cursor.execute("""
            SELECT dst_ip, COUNT(*) as count, dst_port
            FROM network_traffic
            WHERE process_name = ? AND timestamp > datetime('now', '-24 hours')
            GROUP BY dst_ip, dst_port
            ORDER BY count DESC
            LIMIT 10
        """, (name,))
        result['frequent_connections'] = [dict(row) for row in cursor.fetchall()]
        
        # Whitelist check
        cursor.execute("SELECT * FROM whitelisted_processes WHERE name = ?", (name,))
        whitelist_entry = cursor.fetchone()
        result['whitelisted'] = whitelist_entry is not None
        
        conn.close()
        
        # Calculate risk assessment
        risk_score = 0
        risk_factors = []
        
        # Risk from alerts
        if result['alerts']:
            risk_score += 10
            risk_factors.append(f"Process has {len(result['alerts'])} alert(s)")
            
            high_severity = sum(1 for a in result['alerts'] if a.get('severity') == 'high')
            medium_severity = sum(1 for a in result['alerts'] if a.get('severity') == 'medium')
            risk_score += high_severity * 25 + medium_severity * 10
            
            if high_severity > 0:
                risk_factors.append(f"Has {high_severity} high severity alerts")
            if medium_severity > 0:
                risk_factors.append(f"Has {medium_severity} medium severity alerts")
        
        # Risk from connections
        if len(result['frequent_connections']) > 5:
            risk_score += 10
            risk_factors.append(f"Connects to multiple endpoints ({len(result['frequent_connections'])})")
        
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
            else:
                # Not currently running
                risk_factors.append("Process is not currently running")
        except Exception as e:
            if __name__ == '__main__':
                logger.error(f"Error inspecting running process: {str(e)}")
            result['error'] = f"Error inspecting process: {str(e)}"
        
        # Set risk assessment
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
        
        return jsonify(result)
    except Exception as e:
        if __name__ == '__main__':
            logger.error(f"Error in investigate_process: {str(e)}")
        return jsonify({
            'name': name,
            'error': f"Error investigating process: {str(e)}",
            'running': False
        })

if __name__ == '__main__':
    # Add basic logging for troubleshooting API endpoints
    import logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("dashboard.log"),
            logging.StreamHandler()
        ]
    )
    logger = logging.getLogger("dashboard")
    
    # Create the whitelist table if it doesn't exist
    conn = get_db()
    cursor = conn.cursor()
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
    conn.close()
    
    # Create the HTML template
    template_path = '/Users/crashy/gits/noidmon/templates/index.html'
    
    app.run(host='127.0.0.1', port=8080, debug=True)