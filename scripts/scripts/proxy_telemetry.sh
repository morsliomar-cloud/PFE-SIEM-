#!/bin/bash
# CNAS - Proxy Server Security Telemetry
# Emits: syslog (port 514) + JSON log file (for Logstash)

HOST="${1:-logstash01}"
PORT="${2:-514}"
HOSTNAME="PROXY-CNAS-KOLEA"
JSON_LOG="/var/log/proxy-telemetry.json"

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
    echo "{\"@timestamp\":\"$ts\",\"event\":{\"code\":\"$event_code\",\"category\":\"$category\",\"outcome\":\"$outcome\",\"module\":\"proxy_telemetry\"},\"host\":{\"name\":\"$HOSTNAME\"},\"message\":\"$message\",\"labels\":{\"dataset\":\"proxy-cnas\",\"source\":\"telemetry-script\"}}" >> "$JSON_LOG"
}

echo "=== PROXY-CNAS Telemetry ==="
echo "Target: $HOST:$PORT"
echo ""

# 1. Failed logins
if [ -f /var/log/auth.log ]; then
    failed_logins=$(grep -c "Failed password\|authentication failure" /var/log/auth.log 2>/dev/null | tail -1)
elif [ -f /var/log/secure ]; then
    failed_logins=$(grep -c "Failed password\|authentication failure" /var/log/secure 2>/dev/null | tail -1)
else
    failed_logins=$(journalctl -u sshd --since "1 hour ago" 2>/dev/null | grep -c "Failed password" || true)
fi
send_syslog "auth-monitor" "Failed login attempts detected: $failed_logins"
emit_json "4625" "authentication" "failure" "Failed login attempts detected: $failed_logins"

# 2. Active connections
active_connections=$(ss -tun state established 2>/dev/null | wc -l || netstat -an 2>/dev/null | grep -c ESTABLISHED)
active_connections=$((active_connections > 0 ? active_connections - 1 : 0))
send_syslog "network-monitor" "Active TCP/UDP connections: $active_connections"
emit_json "3" "network" "unknown" "Active TCP/UDP connections: $active_connections"

# 3. Network processes
if command -v ss &> /dev/null; then
    network_processes=$(ss -tunp 2>/dev/null | awk 'NR>1 {print $7}' | cut -d'"' -f2 | sort -u | wc -l)
else
    network_processes=$(netstat -tunp 2>/dev/null | awk 'NR>2 {print $7}' | cut -d'/' -f2 | sort -u | wc -l)
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
listening_ports=$(ss -tlun 2>/dev/null | wc -l || netstat -tlun 2>/dev/null | wc -l)
listening_ports=$((listening_ports > 0 ? listening_ports - 1 : 0))
send_syslog "port-monitor" "Listening ports: $listening_ports"
emit_json "3" "network" "unknown" "Listening ports: $listening_ports"

# ── PROXY-SPECIFIC ──────────────────────────────────────────────

proxy_log="/var/log/squid/access.log"

# 9. HTTP/HTTPS requests
if [ -f "$proxy_log" ]; then
    http_requests=$(grep -c "$(date '+%Y/%m/%d')" "$proxy_log" 2>/dev/null || true)
else
    http_requests=$(ss -tun 2>/dev/null | grep -c ":80\|:443\|:8080" || true)
fi
send_syslog "proxy-traffic-monitor" "HTTP/HTTPS requests processed: $http_requests"
emit_json "5156" "network" "unknown" "HTTP/HTTPS requests processed: $http_requests"

# 10. Blocked requests
if [ -f "$proxy_log" ]; then
    blocked_requests=$(grep -c "TCP_DENIED\|DENIED\|407\|403" "$proxy_log" 2>/dev/null || true)
else
    blocked_requests=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "DENIED\|blocked\|filtered" || true)
fi
send_syslog "proxy-filter-monitor" "Requests blocked by content filter: $blocked_requests"
emit_json "5157" "network" "failure" "Requests blocked by content filter: $blocked_requests"

# 11. Outbound data volume
if [ -f "$proxy_log" ]; then
    outbound_bytes=$(awk '{sum+=$5} END {print int(sum/1024/1024)}' "$proxy_log" 2>/dev/null || echo "0")
else
    outbound_bytes=$(cat /proc/net/dev 2>/dev/null | awk '/eth0|ens|enp/{print int($10/1024/1024)}' | head -1 || echo "0")
fi
send_syslog "proxy-exfil-monitor" "Outbound data volume MB last hour: $outbound_bytes"
emit_json "5158" "network" "unknown" "Outbound data volume MB last hour: $outbound_bytes"

# 12. Suspicious domains
if [ -f "$proxy_log" ]; then
    suspicious_domains=$(grep -c "NONE/\|DIRECT/\|ERR_DNS\|ERR_CONNECT" "$proxy_log" 2>/dev/null || true)
else
    suspicious_domains=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "NXDOMAIN\|dns.*fail\|connect.*refused" || true)
fi
send_syslog "proxy-threat-monitor" "Connections to suspicious/uncategorized domains: $suspicious_domains"
emit_json "5159" "network" "failure" "Connections to suspicious/uncategorized domains: $suspicious_domains"

# 13. DNS queries
dns_queries=$(ss -tun 2>/dev/null | grep -c ":53" || \
              journalctl --since "1 hour ago" 2>/dev/null | grep -c "named\|dnsmasq\|unbound" || true)
send_syslog "proxy-dns-monitor" "DNS queries/connections observed: $dns_queries"
emit_json "5160" "network" "unknown" "DNS queries/connections observed: $dns_queries"

# 14. Suspicious user agents
if [ -f "$proxy_log" ]; then
    suspicious_ua=$(grep -ciE "curl|python-requests|nmap|nikto|sqlmap|masscan|zgrab" "$proxy_log" 2>/dev/null || true)
else
    suspicious_ua="0"
fi
send_syslog "proxy-ua-monitor" "Suspicious user agents detected: $suspicious_ua"
emit_json "5161" "network" "failure" "Suspicious user agents detected: $suspicious_ua"

echo ""
echo "PROXY-CNAS telemetry sent to ELK at $HOST:$PORT | JSON log: $JSON_LOG"