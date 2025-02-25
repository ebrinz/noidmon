#!/bin/bash
echo "Checking macOS Monitor status..."
echo "---------------------------------"

# Check LaunchAgent registration
echo "LaunchAgent registration:"
launchctl list | grep macosmonitor

# Check process
echo -e "\nProcess status:"
ps aux | grep "[m]acos-monitor"

# Check database
echo -e "\nDatabase status:"
if [ -f monitor.db ]; then
  echo "Database exists: $(ls -lh monitor.db)"
  echo "Last modified: $(stat -f '%Sm' monitor.db)"
  echo "Size: $(du -h monitor.db | cut -f1)"
else
  echo "Database not found!"
fi

# Check log file
LOG_FILE="./monitor.log"
echo -e "\nLog file status:"
if [ -f "$LOG_FILE" ]; then
  echo "Log exists: $(ls -lh $LOG_FILE)"
  echo "Last 5 log entries:"
  tail -5 "$LOG_FILE"
else
  echo "Log file not found!"
fi