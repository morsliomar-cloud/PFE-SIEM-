#!/bin/bash
# CNAS - Active Directory Security Telemetry v2
# Emits: syslog (port 514) + JSON log file (for Logstash)

HOST="${1:-logstash01}"
PORT="${2:-514}"
HOSTNAME="AD-CNAS-KOLEA"
JSON_LOG="/var/log/ad-telemetry.json"

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
    echo "{\"@timestamp\":\"$ts\",\"event\":{\"code\":\"$event_code\",\"category\":\"$category\",\"outcome\":\"$outcome\",\"module\":\"ad_telemetry\"},\"host\":{\"name\":\"$HOSTNAME\"},\"message\":\"$message\",\"labels\":{\"dataset\":\"ad-cnas\",\"source\":\"telemetry-script\"}}" >> "$JSON_LOG"
}

# 1. Failed logins
if [ -f /var/log/auth.log ]; then
    failed_logins=$(grep -c "Failed password\|authentication failure" /var/log/auth.log 2>/dev/null || true)
else
    failed_logins=$(journalctl -u sshd --since "1 hour ago" 2>/dev/null | grep -c "Failed password" || true)
fi
send_syslog "auth-monitor" "Failed login attempts detected: $failed_logins"
emit_json "4625" "authentication" "failure" "Failed login attempts: $failed_logins"

# 2. Active connections
active_connections=$(ss -tun state established 2>/dev/null | wc -l)
active_connections=$((active_connections > 0 ? active_connections - 1 : 0))
send_syslog "network-monitor" "Active TCP/UDP connections: $active_connections"
emit_json "3001" "network" "success" "Active connections: $active_connections"

# 3. Processes with network activity
if command -v ss &> /dev/null; then
    network_processes=$(ss -tunp 2>/dev/null | awk 'NR>1 {print $7}' | cut -d'"' -f2 | sort -u | wc -l)
else
    network_processes=0
fi
send_syslog "process-monitor" "Unique processes with network activity: $network_processes"

# 4. /tmp files
tmp_files=$(find /tmp -type f -mmin -60 2>/dev/null | wc -l)
send_syslog "file-monitor" "New files in /tmp last hour: $tmp_files"

# 5. Load avg
load_avg=$(cat /proc/loadavg | awk '{print $1}')
send_syslog "load-monitor" "1-minute load average: $load_avg"

# 6. SSH sessions
ssh_sessions=$(who | grep -c pts/ 2>/dev/null || true)
send_syslog "session-monitor" "Active SSH sessions: $ssh_sessions"
emit_json "4624" "authentication" "success" "Active SSH sessions: $ssh_sessions"

# 7. Sudo usage
if [ -f /var/log/auth.log ]; then
    sudo_commands=$(grep -c "sudo:" /var/log/auth.log 2>/dev/null || true)
else
    sudo_commands=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "sudo:" || true)
fi
send_syslog "privilege-monitor" "Sudo commands in logs: $sudo_commands"
emit_json "4672" "iam" "success" "Privilege use count: $sudo_commands"

# 8. Listening ports
listening_ports=$(ss -tlun 2>/dev/null | wc -l)
listening_ports=$((listening_ports > 0 ? listening_ports - 1 : 0))
send_syslog "port-monitor" "Listening ports: $listening_ports"

# 9. Account lockouts
if [ -f /var/log/auth.log ]; then
    lockouts=$(grep -c "FAILED LOGIN\|account.*lock\|too many failures" /var/log/auth.log 2>/dev/null || true)
else
    lockouts=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "pam_tally\|account locked" || true)
fi
send_syslog "ad-lockout-monitor" "Account lockouts (EventID 4740): $lockouts"
emit_json "4740" "iam" "failure" "Account lockout count: $lockouts"

# 10. Group membership changes
if [ -f /var/log/auth.log ]; then
    group_changes=$(grep -c "new group\|groupadd\|usermod\|gpasswd" /var/log/auth.log 2>/dev/null || true)
else
    group_changes=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "groupadd\|usermod\|gpasswd" || true)
fi
send_syslog "ad-privilege-monitor" "Group membership changes (EventID 4728): $group_changes"
emit_json "4728" "iam" "success" "Group changes: $group_changes"

# 11. LDAP/Kerberos connections
ldap_connections=$(ss -tun 2>/dev/null | grep -c ":389\|:636\|:88" || true)
send_syslog "ad-ldap-monitor" "LDAP/Kerberos connections (ports 389/636/88): $ldap_connections"
emit_json "4769" "authentication" "success" "LDAP/Kerberos connections: $ldap_connections"

# 12. Password resets
if [ -f /var/log/auth.log ]; then
    pwd_resets=$(grep -c "password.*change\|passwd\|chpasswd" /var/log/auth.log 2>/dev/null || true)
else
    pwd_resets=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "passwd\|password changed" || true)
fi
send_syslog "ad-password-monitor" "Password change/reset attempts (EventID 4723): $pwd_resets"
emit_json "4723" "iam" "unknown" "Password reset attempts: $pwd_resets"

# 13. Replication errors (DCSync indicator)
repl_errors=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "replication\|sync.*error\|dcsync" || true)
send_syslog "ad-replication-monitor" "Replication/sync errors (DCSync indicator): $repl_errors"
emit_json "4662" "file" "success" "DCSync/replication activity: $repl_errors"

echo ""
echo "AD-CNAS telemetry sent to ELK at $HOST:$PORT | JSON log: $JSON_LOG"