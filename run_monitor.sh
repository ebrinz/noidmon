#!/bin/bash

# Change to the project directory
cd /Users/crashy/gits/noidmon

# Activate the virtual environment
source monitor_env/bin/activate

# Run the monitoring agent (single process version)
python macos-monitor-single-process.py

# Exit with the same code
exit $?

