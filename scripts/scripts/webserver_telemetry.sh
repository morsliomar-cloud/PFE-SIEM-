#!/bin/bash
# CNAS - Web Server Security Telemetry
# Emits: syslog (port 514) + JSON log file (for Logstash)

HOST="${1:-logstash01}"
PORT="${2:-514}"
HOSTNAME="WEBSRV-CNAS-KOLEA"
JSON_LOG="/var/log/websrv-telemetry.json"

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
    echo "{\"@timestamp\":\"$ts\",\"event\":{\"code\":\"$event_code\",\"category\":\"$category\",\"outcome\":\"$outcome\",\"module\":\"websrv_telemetry\"},\"host\":{\"name\":\"$HOSTNAME\"},\"message\":\"$message\",\"labels\":{\"dataset\":\"websrv-cnas\",\"source\":\"telemetry-script\"}}" >> "$JSON_LOG"
}

echo "=== WEBSRV-CNAS Telemetry ==="
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

# ── WEBSRV-SPECIFIC ─────────────────────────────────────────────

WEB_ACCESS_LOG=""
if [ -f /var/log/apache2/access.log ]; then
    WEB_ACCESS_LOG="/var/log/apache2/access.log"
elif [ -f /var/log/nginx/access.log ]; then
    WEB_ACCESS_LOG="/var/log/nginx/access.log"
elif [ -f /var/log/httpd/access_log ]; then
    WEB_ACCESS_LOG="/var/log/httpd/access_log"
fi

WEB_ERROR_LOG=""
if [ -f /var/log/apache2/error.log ]; then
    WEB_ERROR_LOG="/var/log/apache2/error.log"
elif [ -f /var/log/nginx/error.log ]; then
    WEB_ERROR_LOG="/var/log/nginx/error.log"
fi

# 9. Total HTTP requests
if [ -n "$WEB_ACCESS_LOG" ]; then
    http_requests=$(wc -l < "$WEB_ACCESS_LOG" 2>/dev/null || echo "0")
else
    http_requests=$(ss -tun 2>/dev/null | grep -c ":80\|:443" || true)
fi
send_syslog "web-traffic-monitor" "Total HTTP requests in log: $http_requests"
emit_json "5156" "network" "unknown" "Total HTTP requests in log: $http_requests"

# 10. HTTP 4xx errors
if [ -n "$WEB_ACCESS_LOG" ]; then
    errors_4xx=$(grep -cE '" 4[0-9]{2} ' "$WEB_ACCESS_LOG" 2>/dev/null || true)
else
    errors_4xx="0"
fi
send_syslog "web-error-monitor" "HTTP 4xx errors (scan/unauthorized access): $errors_4xx"
emit_json "4625" "authentication" "failure" "HTTP 4xx errors (scan/unauthorized access): $errors_4xx"

# 11. HTTP 5xx errors
if [ -n "$WEB_ACCESS_LOG" ]; then
    errors_5xx=$(grep -cE '" 5[0-9]{2} ' "$WEB_ACCESS_LOG" 2>/dev/null || true)
else
    errors_5xx="0"
fi
send_syslog "web-error-monitor" "HTTP 5xx errors (server crash/exploitation): $errors_5xx"
emit_json "5001" "network" "failure" "HTTP 5xx errors (server crash/exploitation): $errors_5xx"

# 12. Web attack attempts (SQLi/XSS/LFI)
if [ -n "$WEB_ACCESS_LOG" ]; then
    web_attacks=$(grep -ciE \
        "union.*select|select.*from|drop.*table|<script|alert\(|onerror=|\.\./\.\./|etc/passwd|/proc/self|eval\(|base64_decode|cmd=|exec=" \
        "$WEB_ACCESS_LOG" 2>/dev/null || echo "0")
else
    web_attacks="0"
fi
send_syslog "web-attack-monitor" "SQLi/XSS/LFI attack attempts in URLs: $web_attacks"
emit_json "5002" "network" "failure" "SQLi/XSS/LFI attack attempts in URLs: $web_attacks"

# 13. Webshell candidates
webshell_candidates=$(find /var/www 2>/dev/null \
    -type f \( -name "*.php" -o -name "*.sh" -o -name "*.py" \) \
    -mmin -60 | wc -l || echo "0")
send_syslog "web-upload-monitor" "New executable files in webroot last hour: $webshell_candidates"
emit_json "11" "file" "unknown" "New executable files in webroot last hour: $webshell_candidates"

# 14. HTTP 401 auth failures
if [ -n "$WEB_ACCESS_LOG" ]; then
    http_auth_fail=$(grep -cE '" 401 ' "$WEB_ACCESS_LOG" 2>/dev/null || true)
else
    http_auth_fail="0"
fi
send_syslog "web-auth-monitor" "HTTP 401 auth failures (brute force indicator): $http_auth_fail"
emit_json "4625" "authentication" "failure" "HTTP 401 auth failures (brute force indicator): $http_auth_fail"

# 15. Large HTTP responses (data exfiltration)
if [ -n "$WEB_ACCESS_LOG" ]; then
    large_responses=$(awk '{if($NF+0 > 10000000) count++} END {print count+0}' \
        "$WEB_ACCESS_LOG" 2>/dev/null || echo "0")
else
    large_responses="0"
fi
send_syslog "web-exfil-monitor" "HTTP responses >10MB (data exfiltration indicator): $large_responses"
emit_json "5003" "network" "unknown" "HTTP responses >10MB (data exfiltration indicator): $large_responses"

echo ""
echo "WEBSRV-CNAS telemetry sent to ELK at $HOST:$PORT | JSON log: $JSON_LOG"