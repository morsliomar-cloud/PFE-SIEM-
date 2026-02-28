#!/bin/bash

# Linux Cybersecurity MVP Telemetry Script
# Focuses on key security indicators for Linux systems (Ubuntu/Debian/CentOS/RHEL)
# Works with systemd-based distributions

HOST="${1:-localhost}"
PORT="${2:-514}"
HOSTNAME=$(hostname -s)

function send_syslog() {
    local program=$1
    local message=$2
    
    timestamp=$(date '+%b %d %H:%M:%S')
    # Using facility 13 (security), severity 6 (info) - priority 110
    syslog_msg="<110>$timestamp $HOSTNAME $program: $message"
    echo "$syslog_msg" | nc -u -w 1 $HOST $PORT 2>/dev/null || \
    echo "$syslog_msg" > /dev/udp/$HOST/$PORT 2>/dev/null
    echo "Security telemetry: $program - $message"
}

echo "Collecting Linux cybersecurity telemetry..."
echo "Target: $HOST:$PORT"
echo ""

# 1. Failed Login Attempts (last hour)
# Check both auth.log (Debian/Ubuntu) and secure (RHEL/CentOS)
if [ -f /var/log/auth.log ]; then
    failed_logins=$(grep -c "Failed password\|authentication failure" /var/log/auth.log 2>/dev/null | tail -1)
elif [ -f /var/log/secure ]; then
    failed_logins=$(grep -c "Failed password\|authentication failure" /var/log/secure 2>/dev/null | tail -1)
else
    # Fallback to journalctl for systemd systems
    failed_logins=$(journalctl -u sshd --since "1 hour ago" 2>/dev/null | grep -c "Failed password" || echo "0")
fi
send_syslog "auth-monitor" "Failed login attempts detected: $failed_logins"

# 2. Active Network Connections
active_connections=$(ss -tun state established 2>/dev/null | wc -l || netstat -an 2>/dev/null | grep -c ESTABLISHED)
# Subtract 1 for header row if using ss
active_connections=$((active_connections > 0 ? active_connections - 1 : 0))
send_syslog "network-monitor" "Active TCP/UDP connections: $active_connections"

# 3. Processes with Network Activity
if command -v ss &> /dev/null; then
    network_processes=$(ss -tunp 2>/dev/null | awk 'NR>1 {print $7}' | cut -d'"' -f2 | sort -u | wc -l)
else
    network_processes=$(netstat -tunp 2>/dev/null | awk 'NR>2 {print $7}' | cut -d'/' -f2 | sort -u | wc -l)
fi
send_syslog "process-monitor" "Unique processes with network activity: $network_processes"

# 4. New Files in /tmp (last hour)
tmp_files=$(find /tmp -type f -mmin -60 2>/dev/null | wc -l)
send_syslog "file-monitor" "New files in /tmp last hour: $tmp_files"

# 5. System Load Average
load_avg=$(cat /proc/loadavg | awk '{print $1}')
send_syslog "load-monitor" "1-minute load average: $load_avg"

# 6. SSH Sessions (Linux-specific security indicator)
ssh_sessions=$(who | grep -c pts/ 2>/dev/null || echo "0")
send_syslog "session-monitor" "Active SSH sessions: $ssh_sessions"

# 7. Sudo Usage (last hour) - important for privilege escalation monitoring
if [ -f /var/log/auth.log ]; then
    sudo_commands=$(grep -c "sudo:" /var/log/auth.log 2>/dev/null || echo "0")
elif [ -f /var/log/secure ]; then
    sudo_commands=$(grep -c "sudo:" /var/log/secure 2>/dev/null || echo "0")
else
    sudo_commands=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "sudo:" || echo "0")
fi
send_syslog "privilege-monitor" "Sudo commands in logs: $sudo_commands"

# 8. Listening Ports (potential backdoor indicator)
listening_ports=$(ss -tlun 2>/dev/null | wc -l || netstat -tlun 2>/dev/null | wc -l)
listening_ports=$((listening_ports > 0 ? listening_ports - 1 : 0))
send_syslog "port-monitor" "Listening ports: $listening_ports"

echo ""
echo "Linux cybersecurity telemetry sent to ELK stack at $HOST:$PORT"
echo ""
echo "Tip: Run this script periodically with cron:"
echo "  */5 * * * * /path/to/linux_telemetry.sh $HOST $PORT >> /var/log/telemetry.log 2>&1"
