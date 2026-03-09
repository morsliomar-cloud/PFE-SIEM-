#!/bin/bash
# CNAS - WSUS Security Telemetry v2
# Emits: syslog (port 514) + JSON log file (for Logstash)

HOST="${1:-logstash01}"
PORT="${2:-514}"
HOSTNAME="WSUS-CNAS-KOLEA"
JSON_LOG="/var/log/wsus-telemetry.json"

function send_syslog() {
    local program=$1
    local message=$2
    local timestamp
    timestamp=$(date '+%b %d %H:%M:%S')
    local syslog_msg="<110>$timestamp $HOSTNAME $program: $message"
    echo "$syslog_msg" | nc -u -w 1 "$HOST" "$PORT" 2>/dev/null
    echo "[$HOSTNAME] $program: $message"
}

function emit_json() {
    local event_code=$1 category=$2 outcome=$3 message=$4
    local ts; ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
    echo "{\"@timestamp\":\"$ts\",\"event\":{\"code\":\"$event_code\",\"category\":\"$category\",\"outcome\":\"$outcome\",\"module\":\"wsus_telemetry\"},\"host\":{\"name\":\"$HOSTNAME\"},\"message\":\"$message\",\"labels\":{\"dataset\":\"wsus-cnas\",\"source\":\"telemetry-script\"}}" >> "$JSON_LOG"
}

echo "=== WSUS-CNAS Telemetry v2 ==="

# 1. Failed logins
if [ -f /var/log/auth.log ]; then
    failed_logins=$(grep -c "Failed password\|authentication failure" /var/log/auth.log 2>/dev/null | tail -1)
else
    failed_logins=$(journalctl -u sshd --since "1 hour ago" 2>/dev/null | grep -c "Failed password" || true)
fi
send_syslog "auth-monitor" "Failed login attempts detected: $failed_logins"
emit_json "4625" "authentication" "failure" "Failed login attempts detected: $failed_logins"

# 2. Active connections
active_connections=$(ss -tun state established 2>/dev/null | wc -l)
active_connections=$((active_connections > 0 ? active_connections - 1 : 0))
send_syslog "network-monitor" "Active TCP/UDP connections: $active_connections"
emit_json "3" "network" "unknown" "Active TCP/UDP connections: $active_connections"

# 3. Network processes
if command -v ss &> /dev/null; then
    network_processes=$(ss -tunp 2>/dev/null | awk 'NR>1 {print $7}' | cut -d'"' -f2 | sort -u | wc -l)
else
    network_processes=0
fi
send_syslog "process-monitor" "Unique processes with network activity: $network_processes"
emit_json "1" "process" "unknown" "Unique processes with network activity: $network_processes"

# 4. Temp files
tmp_files=$(find /tmp -type f -mmin -60 2>/dev/null | wc -l)
send_syslog "file-monitor" "New files in /tmp last hour: $tmp_files"
emit_json "11" "file" "unknown" "New files in /tmp last hour: $tmp_files"

# 5. Load average
load_avg=$(cat /proc/loadavg | awk '{print $1}')
send_syslog "load-monitor" "1-minute load average: $load_avg"
emit_json "8003" "host" "unknown" "1-minute load average: $load_avg"

# 6. SSH sessions
ssh_sessions=$(who | grep -c pts/ 2>/dev/null || true)
send_syslog "session-monitor" "Active SSH sessions: $ssh_sessions"
emit_json "4624" "authentication" "success" "Active SSH sessions: $ssh_sessions"

# 7. Sudo commands
if [ -f /var/log/auth.log ]; then
    sudo_commands=$(grep -c "sudo:" /var/log/auth.log 2>/dev/null || true)
else
    sudo_commands=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "sudo:" || true)
fi
send_syslog "privilege-monitor" "Sudo commands in logs: $sudo_commands"
emit_json "4728" "iam" "unknown" "Sudo commands in logs: $sudo_commands"

# 8. Listening ports
listening_ports=$(ss -tlun 2>/dev/null | wc -l)
listening_ports=$((listening_ports > 0 ? listening_ports - 1 : 0))
send_syslog "port-monitor" "Listening ports: $listening_ports"
emit_json "3" "network" "unknown" "Listening ports: $listening_ports"

# ── WSUS-SPECIFIC ────────────────────────────────────────────────

# 9. WSUS client connections
wsus_clients=$(ss -tun 2>/dev/null | grep -c ":8530\|:8531" || true)
send_syslog "wsus-client-monitor" "Active WSUS client connections: $wsus_clients"
emit_json "8001" "network" "success" "Active WSUS client connections: $wsus_clients"

# 10. Download volume
download_files=$(find /var/cache -type f -mmin -60 2>/dev/null | wc -l)
send_syslog "wsus-download-monitor" "Update files downloaded last hour: $download_files"
emit_json "8002" "file" "success" "Update files downloaded last hour: $download_files"

# 11. Pending updates
pending_updates=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || true)
send_syslog "wsus-patch-monitor" "Pending system updates: $pending_updates"
emit_json "8003" "configuration" "unknown" "Pending system updates: $pending_updates"

# 12. Update errors
update_errors=$(journalctl --since "1 hour ago" 2>/dev/null | \
    grep -c "update.*error\|apt.*error\|failed.*install" || true)
send_syslog "wsus-error-monitor" "Update distribution errors: $update_errors"
emit_json "8004" "configuration" "failure" "Update distribution errors: $update_errors"

# 13. Outbound MS Update connections
ms_connections=$(ss -tun 2>/dev/null | grep -c ":443\|:80" || true)
send_syslog "wsus-upstream-monitor" "Outbound connections (Microsoft Update sync): $ms_connections"
emit_json "8005" "network" "unknown" "Outbound connections to Microsoft Update: $ms_connections"

# 14. Disk usage
disk_usage=$(df /var 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%' || echo "0")
send_syslog "wsus-disk-monitor" "Disk usage on update partition: $disk_usage%"
emit_json "8006" "host" "unknown" "Disk usage on update partition: $disk_usage%"

echo ""
echo "WSUS-CNAS telemetry sent to ELK at $HOST:$PORT | JSON log: $JSON_LOG"