# macOS Process and Network Monitor Setup Guide

This guide will help you set up and run the macOS Process and Network Monitoring Agent on your system.

## Prerequisites

- macOS 10.15 (Catalina) or newer
- Python 3.8 or newer
- Administrator access (for network monitoring)

## Installation

1. **Clone or download the project files**

   Download or copy all the provided files into a directory on your Mac.

2. **Create a virtual environment (recommended)**

   ```bash
   python3 -m venv monitor_env
   source monitor_env/bin/activate
   ```

3. **Install the required dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Set up permissions for network monitoring**

   The network monitoring component requires elevated privileges to capture network packets. You can either:
   
   - Run the application with `sudo` when needed
   - Grant persistent permissions to Python to access packet capture devices:
   
   ```bash
   sudo chmod +r /dev/bpf*
   ```
   
   You might need to repeat this command after system reboots.

5. **Create a suspicious IPs list (optional)**

   Create a file named `suspicious_ips.txt` in the same directory as the main script. Add one IP address per line for known malicious IPs you want to monitor for.

## Configuration

You can create a configuration file (JSON format) to customize the monitoring agent's behavior. Here's a sample configuration:

```json
{
  "db_path": "monitor.db",
  "process_interval": 30,
  "anomaly_train_interval": 3600
}
```

- `db_path`: Path to the SQLite database file (default: "monitor.db")
- `process_interval`: How often to collect process data in seconds (default: 30)
- `anomaly_train_interval`: How often to train the anomaly detection model in seconds (default: 3600)

## Usage

### Starting the Monitor

To start monitoring your system:

```bash
python macos-monitor.py
```

Or if you have a custom configuration file:

```bash
python macos-monitor.py --config my_config.json
```

The program will begin collecting data on processes and network traffic, and will log any detected anomalies to both the console and a log file named `monitor.log`.

### Generating Reports

You can generate reports on collected data without running the full monitoring system:

```bash
python macos-monitor.py --report daily --format html
```

Report options:
- `--report`: Choose from `daily`, `weekly`, or `monthly` to specify the time period
- `--format`: Choose from `html`, `json`, or `text` for the report format

### Advanced Usage

#### Running in the background

To run the monitor in the background:

```bash
nohup python macos-monitor.py > /dev/null 2>&1 &
```

#### Setting up as a startup service

The monitoring system consists of several components that can be set up as LaunchAgents to run automatically when you log in. The repository includes several plist files that can be used to set this up:

1. **Main Monitor** - Collects process and network data:

   Copy `com.user.macosmonitor.plist` to `~/Library/LaunchAgents/`:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>Label</key>
       <string>com.user.macosmonitor</string>
       <key>ProgramArguments</key>
       <array>
           <string>/bin/bash</string>
           <string>-c</string>
           <string>cd /PATH/TO/noidmon && source monitor_env/bin/activate && python macos-monitor.py</string>
       </array>
       <key>RunAtLoad</key>
       <true/>
       <key>KeepAlive</key>
       <true/>
       <key>StandardOutPath</key>
       <string>/PATH/TO/noidmon/monitor.log</string>
       <key>StandardErrorPath</key>
       <string>/PATH/TO/noidmon/monitor.err</string>
   </dict>
   </plist>
   ```

2. **Web Dashboard** - Provides web interface for monitoring data:

   Copy `com.user.macosmonitor.dashboard.plist` to `~/Library/LaunchAgents/`:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>Label</key>
       <string>com.user.macosmonitor.dashboard</string>
       <key>ProgramArguments</key>
       <array>
           <string>/bin/bash</string>
           <string>-c</string>
           <string>cd /PATH/TO/noidmon && source monitor_env/bin/activate && python dashboard.py</string>
       </array>
       <key>RunAtLoad</key>
       <true/>
       <key>KeepAlive</key>
       <true/>
       <key>StandardOutPath</key>
       <string>/PATH/TO/noidmon/dashboard.log</string>
       <key>StandardErrorPath</key>
       <string>/PATH/TO/noidmon/dashboard.err</string>
   </dict>
   </plist>
   ```

3. **Status Bar App** - Provides menubar notifications:

   Copy `com.user.macosmonitor.statusbar.plist` to `~/Library/LaunchAgents/`:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>Label</key>
       <string>com.user.macosmonitor.statusbar</string>
       <key>ProgramArguments</key>
       <array>
           <string>/bin/bash</string>
           <string>-c</string>
           <string>cd /PATH/TO/noidmon && source monitor_env/bin/activate && python statusbar_monitor.py</string>
       </array>
       <key>RunAtLoad</key>
       <true/>
       <key>KeepAlive</key>
       <true/>
   </dict>
   </plist>
   ```

4. **Alert Handler** - Periodically checks for and handles new alerts:

   Copy `com.user.macosmonitor.alerthandler.plist` to `~/Library/LaunchAgents/`:

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>Label</key>
       <string>com.user.macosmonitor.alerts</string>
       <key>ProgramArguments</key>
       <array>
           <string>/bin/bash</string>
           <string>/PATH/TO/noidmon/alert_handler.sh</string>
       </array>
       <key>StartInterval</key>
       <integer>300</integer>
   </dict>
   </plist>
   ```

For each of these files:

1. Replace `/PATH/TO/noidmon` with the actual path to your installation directory
2. Copy each file to `~/Library/LaunchAgents/`
3. Load each agent with:

```bash
launchctl load ~/Library/LaunchAgents/com.user.macosmonitor.plist
launchctl load ~/Library/LaunchAgents/com.user.macosmonitor.dashboard.plist
launchctl load ~/Library/LaunchAgents/com.user.macosmonitor.statusbar.plist
launchctl load ~/Library/LaunchAgents/com.user.alerthandler.plist
```

To stop any of these services:

```bash
launchctl unload ~/Library/LaunchAgents/com.user.macosmonitor.plist
```

To check their status:

```bash
launchctl list | grep macosmonitor
```

## Accessing the Monitor

The macOS Process and Network Monitor includes several interfaces:

### Web Dashboard

Access the cyberpunk-themed web dashboard by visiting:
```
http://localhost:8080
```

The dashboard provides:
- Real-time statistics on processes, network traffic, and security alerts
- Detailed process investigation with risk assessment
- Network connection analysis
- Forensic tools for suspicious processes

### Status Bar App

The status bar app shows a small indicator in your Mac's menu bar:
- 🔒 (Green lock): No alerts detected
- ⚠️ (Warning): Security alerts detected

Click on the icon to:
- View recent alerts
- Generate a security report
- Access quick monitoring tools

### Alert Notifications

The system generates macOS notifications for high-severity alerts when configured.

## Advanced Security Features

### Process Investigation

The system includes deep inspection capabilities for suspicious processes:

1. **Detailed Process Analysis**:
   - View complete process information (executable path, command line, working directory)
   - Examine open files and active network connections
   - Get comprehensive insights about what the process is doing

2. **AI-Powered Analysis** (Optional):
   - Connect to Claude API for intelligent process assessment
   - Get risk evaluation and explanations about suspicious indicators
   - Receive actionable recommendations for securing your system
   - To enable this feature, set your Claude API key as an environment variable:
     ```bash
     export CLAUDE_API_KEY="your_api_key_here"
     ```
   - The API key is only accessed from the environment variable, never stored in files

3. **Process Control**:
   - Terminate suspicious processes directly from the dashboard
   - Export detailed forensic data for further investigation

### Process Whitelisting

To prevent false positives and protect legitimate system processes:

1. **Whitelist Management**:
   - Add trusted processes to the whitelist through the dashboard
   - Whitelisted processes are protected from accidental termination
   - Document reasons for whitelisting for future reference

2. **Whitelist API**:
   - `/api/whitelist` - View, add, and remove whitelisted processes
   - Programmatically manage allowed processes

## Understanding the Data

### Database Structure

The system stores all collected data in an SQLite database with the following tables:

1. **processes**: Information on running processes
2. **network_traffic**: Details of network connections
3. **alerts**: Security alerts generated by the system
4. **whitelisted_processes**: Processes that have been marked as trusted

### Alert Types

The system generates several types of alerts:

- **process_anomaly**: Unusual behavior detected in a process (high CPU, memory, or connection count)
- **suspicious_ip**: Connection with a known suspicious IP address
- **unusual_port**: Connection to an uncommon port number
- **high_connection_count**: Excessive connections between the same IP addresses

### Customizing Alerts

To add your own alert types or modify detection thresholds, you can edit the following:

- `ProcessMonitor.detect_anomalies()` - For process-related anomalies
- `NetworkMonitor.check_for_suspicious_activity()` - For network-related anomalies

## Troubleshooting

### Permission Issues

If you encounter permission errors with network monitoring:

```
Error in network monitoring: [Errno 1] Operation not permitted
```

Try running the script with `sudo` or ensure proper permissions on BPF devices.

### Performance Impact

If the monitoring agent is consuming too many resources:

1. Increase the `process_interval` value in your configuration
2. Use the alternative network monitoring method that uses `lsof` instead of packet capture

### Database Growth

The database can grow large over time. To manage this:

1. Back up your database periodically
2. Create a cron job to remove old entries from the database


