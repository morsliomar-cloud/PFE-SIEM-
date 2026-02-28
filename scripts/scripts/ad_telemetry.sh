#!/bin/bash
# CNAS - Active Directory Security Telemetry
# Sources: auth logs, AD events, Kerberos, LDAP, privilege changes

HOST="${1:-localhost}"
PORT="${2:-514}"
HOSTNAME="AD-CNAS-KOLEA"   

function send_syslog() {
    local program=$1
    local message=$2
    timestamp=$(date '+%b %d %H:%M:%S')
    syslog_msg="<110>$timestamp $HOSTNAME $program: $message"
    echo "$syslog_msg" | nc -u -w 1 $HOST $PORT 2>/dev/null || \
    echo "$syslog_msg" > /dev/udp/$HOST/$PORT 2>/dev/null
    echo "[$HOSTNAME] $program: $message"
}

echo "=== AD-CNAS Telemetry ==="
echo "Target: $HOST:$PORT"
echo ""


# 1. Failed Login Attempts
if [ -f /var/log/auth.log ]; then
    failed_logins=$(grep -c "Failed password\|authentication failure" /var/log/auth.log 2>/dev/null | tail -1)
elif [ -f /var/log/secure ]; then
    failed_logins=$(grep -c "Failed password\|authentication failure" /var/log/secure 2>/dev/null | tail -1)
else
    failed_logins=$(journalctl -u sshd --since "1 hour ago" 2>/dev/null | grep -c "Failed password" || echo "0")
fi
send_syslog "auth-monitor" "Failed login attempts detected: $failed_logins"

# 2. Active Network Connections
active_connections=$(ss -tun state established 2>/dev/null | wc -l || netstat -an 2>/dev/null | grep -c ESTABLISHED)
active_connections=$((active_connections > 0 ? active_connections - 1 : 0))
send_syslog "network-monitor" "Active TCP/UDP connections: $active_connections"

# 3. Processes with Network Activity
if command -v ss &> /dev/null; then
    network_processes=$(ss -tunp 2>/dev/null | awk 'NR>1 {print $7}' | cut -d'"' -f2 | sort -u | wc -l)
else
    network_processes=$(netstat -tunp 2>/dev/null | awk 'NR>2 {print $7}' | cut -d'/' -f2 | sort -u | wc -l)
fi
send_syslog "process-monitor" "Unique processes with network activity: $network_processes"

# 4. New Files in /tmp
tmp_files=$(find /tmp -type f -mmin -60 2>/dev/null | wc -l)
send_syslog "file-monitor" "New files in /tmp last hour: $tmp_files"

# 5. System Load
load_avg=$(cat /proc/loadavg | awk '{print $1}')
send_syslog "load-monitor" "1-minute load average: $load_avg"

# 6. SSH Sessions
ssh_sessions=$(who | grep -c pts/ 2>/dev/null || echo "0")
send_syslog "session-monitor" "Active SSH sessions: $ssh_sessions"

# 7. Sudo Usage
if [ -f /var/log/auth.log ]; then
    sudo_commands=$(grep -c "sudo:" /var/log/auth.log 2>/dev/null || echo "0")
elif [ -f /var/log/secure ]; then
    sudo_commands=$(grep -c "sudo:" /var/log/secure 2>/dev/null || echo "0")
else
    sudo_commands=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "sudo:" || echo "0")
fi
send_syslog "privilege-monitor" "Sudo commands in logs: $sudo_commands"

# 8. Listening Ports
listening_ports=$(ss -tlun 2>/dev/null | wc -l || netstat -tlun 2>/dev/null | wc -l)
listening_ports=$((listening_ports > 0 ? listening_ports - 1 : 0))
send_syslog "port-monitor" "Listening ports: $listening_ports"

# ============================================================
# BLOC 2 — SPÉCIFIQUE : ACTIVE DIRECTORY
# Simule les événements critiques d'un contrôleur de domaine
# ============================================================

# 9. Account Lockouts (EventID 4740 sur vrai AD)
# Détecte les comptes verrouillés après trop d'échecs d'auth
if [ -f /var/log/auth.log ]; then
    lockouts=$(grep -c "FAILED LOGIN\|account.*lock\|too many failures" /var/log/auth.log 2>/dev/null || echo "0")
else
    lockouts=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "pam_tally\|account locked" || echo "0")
fi
send_syslog "ad-lockout-monitor" "Account lockouts (EventID 4740): $lockouts"

# 10. Privilege Escalation — Group Membership Changes (EventID 4728/4732)
# Surveille les ajouts de comptes dans les groupes sensibles (Domain Admins, etc.)
if [ -f /var/log/auth.log ]; then
    group_changes=$(grep -c "new group\|groupadd\|usermod\|gpasswd" /var/log/auth.log 2>/dev/null || echo "0")
else
    group_changes=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "groupadd\|usermod\|gpasswd" || echo "0")
fi
send_syslog "ad-privilege-monitor" "Group membership changes (EventID 4728): $group_changes"

# 11. Active Domain Sessions (utilisateurs connectés au domaine)
domain_sessions=$(who | wc -l 2>/dev/null || echo "0")
send_syslog "ad-session-monitor" "Active domain user sessions: $domain_sessions"

# 12. Kerberos / LDAP Activity — Authentifications au service d'annuaire
# Sur un vrai AD: requêtes LDAP sur port 389/636, Kerberos sur 88
ldap_connections=$(ss -tun 2>/dev/null | grep -c ":389\|:636\|:88" || echo "0")
send_syslog "ad-ldap-monitor" "LDAP/Kerberos connections (ports 389/636/88): $ldap_connections"

# 13. Password Reset Attempts (EventID 4723/4724)
# Indicateur d'attaque: reset de mot de passe non autorisé
if [ -f /var/log/auth.log ]; then
    pwd_resets=$(grep -c "password.*change\|passwd\|chpasswd" /var/log/auth.log 2>/dev/null || echo "0")
else
    pwd_resets=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "passwd\|password changed" || echo "0")
fi
send_syslog "ad-password-monitor" "Password change/reset attempts (EventID 4723): $pwd_resets"

# 14. Replication / Sync Errors — Critique pour la santé de l'AD
# Sur un vrai AD, les erreurs de réplication indiquent une attaque DCSync possible
repl_errors=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "replication\|sync.*error\|dcsync" || echo "0")
send_syslog "ad-replication-monitor" "Replication/sync errors (DCSync indicator): $repl_errors"

echo ""
echo "AD-CNAS telemetry sent to ELK at $HOST:$PORT"