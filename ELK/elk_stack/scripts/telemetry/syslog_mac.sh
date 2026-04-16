#!/bin/bash

# Cybersecurity MVP Telemetry Script
# Focuses on key security indicators for Mac systems
#
# Usage: ./syslog_mac.sh [HOST] [PORT]
# Examples:
#   ./syslog_mac.sh                    # Uses localhost:514 (default)
#   ./syslog_mac.sh 192.168.1.100 514  # Custom host and port

# Accept optional command-line arguments, fallback to defaults
HOST="${1:-localhost}"
PORT="${2:-514}"
HOSTNAME=$(hostname -s)

function send_syslog() {
    local program=$1
    local message=$2
    
    timestamp=$(date '+%b %d %H:%M:%S')
    # Using facility 13 (security), severity 6 (info)
    syslog_msg="<110>$timestamp $HOSTNAME $program: $message"
    echo "$syslog_msg" | nc -u -w 1 $HOST $PORT
    echo "Security telemetry: $program - $message"
}

echo "Collecting cybersecurity telemetry..."

# 1. Failed Login Attempts (recent)
failed_logins=$(log show --predicate 'eventMessage contains "authentication failure"' --last 1h 2>/dev/null | wc -l | xargs)
send_syslog "auth-monitor" "Failed login attempts last hour: $failed_logins"

# 2. New Network Connections (active TCP connections)
active_connections=$(netstat -an | grep ESTABLISHED | wc -l | xargs)
send_syslog "network-monitor" "Active TCP connections: $active_connections"

# 3. Suspicious Process Activity (processes with network connections)
network_processes=$(lsof -i -n | grep -v LISTEN | wc -l | xargs)
send_syslog "process-monitor" "Processes with network activity: $network_processes"

# 4. File System Changes (new files in /tmp in last hour)
tmp_files=$(find /tmp -type f -mtime -1h 2>/dev/null | wc -l | xargs)
send_syslog "file-monitor" "New files in /tmp last hour: $tmp_files"

# 5. System Load (potential indicator of crypto mining or DoS)
load_avg=$(uptime | awk -F'load averages:' '{print $2}' | awk '{print $1}' | xargs)
send_syslog "load-monitor" "1-minute load average: $load_avg"

echo "Cybersecurity telemetry sent to ELK stack"