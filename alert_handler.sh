#!/bin/bash

# Script to check for recent alerts and send notifications
cd /Users/crashy/gits/noidmon
source monitor_env/bin/activate

# Get recent high-severity alerts from the database
ALERTS=$(sqlite3 monitor.db "SELECT description FROM alerts WHERE severity='high' AND timestamp > datetime('now', '-5 minutes') LIMIT 5;")

# Send notification for each alert
if [ ! -z "$ALERTS" ]; then
  while IFS= read -r alert; do
    osascript -e "display notification \"$alert\" with title \"Security Alert\" subtitle \"macOS Monitor\""
  done <<< "$ALERTS"
fi