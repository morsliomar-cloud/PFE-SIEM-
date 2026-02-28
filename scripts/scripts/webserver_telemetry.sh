#!/bin/bash
# CNAS - Web Server Security Telemetry
# Sources: Apache/Nginx access logs, error logs, WAF events, file integrity

HOST="${1:-localhost}"
PORT="${2:-514}"
HOSTNAME="WEBSRV-CNAS-KOLEA"   # Nom fixe - représente le Web Server

function send_syslog() {
    local program=$1
    local message=$2
    timestamp=$(date '+%b %d %H:%M:%S')
    syslog_msg="<110>$timestamp $HOSTNAME $program: $message"
    echo "$syslog_msg" | nc -u -w 1 $HOST $PORT 2>/dev/null || \
    echo "$syslog_msg" > /dev/udp/$HOST/$PORT 2>/dev/null
    echo "[$HOSTNAME] $program: $message"
}

echo "=== WEBSRV-CNAS Telemetry ==="
echo "Target: $HOST:$PORT"
echo ""



if [ -f /var/log/auth.log ]; then
    failed_logins=$(grep -c "Failed password\|authentication failure" /var/log/auth.log 2>/dev/null | tail -1)
elif [ -f /var/log/secure ]; then
    failed_logins=$(grep -c "Failed password\|authentication failure" /var/log/secure 2>/dev/null | tail -1)
else
    failed_logins=$(journalctl -u sshd --since "1 hour ago" 2>/dev/null | grep -c "Failed password" || echo "0")
fi
send_syslog "auth-monitor" "Failed login attempts detected: $failed_logins"

active_connections=$(ss -tun state established 2>/dev/null | wc -l || netstat -an 2>/dev/null | grep -c ESTABLISHED)
active_connections=$((active_connections > 0 ? active_connections - 1 : 0))
send_syslog "network-monitor" "Active TCP/UDP connections: $active_connections"

if command -v ss &> /dev/null; then
    network_processes=$(ss -tunp 2>/dev/null | awk 'NR>1 {print $7}' | cut -d'"' -f2 | sort -u | wc -l)
else
    network_processes=$(netstat -tunp 2>/dev/null | awk 'NR>2 {print $7}' | cut -d'/' -f2 | sort -u | wc -l)
fi
send_syslog "process-monitor" "Unique processes with network activity: $network_processes"

tmp_files=$(find /tmp -type f -mmin -60 2>/dev/null | wc -l)
send_syslog "file-monitor" "New files in /tmp last hour: $tmp_files"

load_avg=$(cat /proc/loadavg | awk '{print $1}')
send_syslog "load-monitor" "1-minute load average: $load_avg"

ssh_sessions=$(who | grep -c pts/ 2>/dev/null || echo "0")
send_syslog "session-monitor" "Active SSH sessions: $ssh_sessions"

if [ -f /var/log/auth.log ]; then
    sudo_commands=$(grep -c "sudo:" /var/log/auth.log 2>/dev/null || echo "0")
else
    sudo_commands=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "sudo:" || echo "0")
fi
send_syslog "privilege-monitor" "Sudo commands in logs: $sudo_commands"

listening_ports=$(ss -tlun 2>/dev/null | wc -l || netstat -tlun 2>/dev/null | wc -l)
listening_ports=$((listening_ports > 0 ? listening_ports - 1 : 0))
send_syslog "port-monitor" "Listening ports: $listening_ports"

# ============================================================
# BLOC 2 — SPÉCIFIQUE : WEB SERVER
# Surveille les attaques applicatives: SQLi, XSS, LFI, RFI, brute force HTTP
# ============================================================

# Détecter le serveur web installé
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

# 9. Volume total de requêtes HTTP
if [ -n "$WEB_ACCESS_LOG" ]; then
    http_requests=$(wc -l < "$WEB_ACCESS_LOG" 2>/dev/null || echo "0")
else
    http_requests=$(ss -tun 2>/dev/null | grep -c ":80\|:443" || echo "0")
fi
send_syslog "web-traffic-monitor" "Total HTTP requests in log: $http_requests"

# 10. Erreurs HTTP 4xx (scans, tentatives d'accès non autorisés)
# Un pic de 4xx = scan de vulnérabilités ou tentative de force brute HTTP
if [ -n "$WEB_ACCESS_LOG" ]; then
    errors_4xx=$(grep -cE '" 4[0-9]{2} ' "$WEB_ACCESS_LOG" 2>/dev/null || echo "0")
else
    errors_4xx="0"
fi
send_syslog "web-error-monitor" "HTTP 4xx errors (scan/unauthorized access): $errors_4xx"

# 11. Erreurs HTTP 5xx (exploitation provoquant des crashs serveur)
if [ -n "$WEB_ACCESS_LOG" ]; then
    errors_5xx=$(grep -cE '" 5[0-9]{2} ' "$WEB_ACCESS_LOG" 2>/dev/null || echo "0")
else
    errors_5xx="0"
fi
send_syslog "web-error-monitor" "HTTP 5xx errors (server crash/exploitation): $errors_5xx"

# 12. Tentatives SQLi/XSS/LFI/RFI détectées dans les URLs
# Indicateur d'attaque applicative directe sur le portail CNAS
if [ -n "$WEB_ACCESS_LOG" ]; then
    web_attacks=$(grep -ciE \
        "union.*select|select.*from|drop.*table|\
        <script|alert\(|onerror=|\
        \.\./\.\./|etc/passwd|/proc/self|\
        eval\(|base64_decode|cmd=|exec=" \
        "$WEB_ACCESS_LOG" 2>/dev/null || echo "0")
else
    web_attacks="0"
fi
send_syslog "web-attack-monitor" "SQLi/XSS/LFI attack attempts in URLs: $web_attacks"

# 13. Fichiers uploadés dans les dossiers web (webshell possible)
# Un fichier .php ou .sh uploadé dans /var/www = webshell potentiel
webshell_candidates=$(find /var/www 2>/dev/null \
    -type f \( -name "*.php" -o -name "*.sh" -o -name "*.py" \) \
    -mmin -60 | wc -l || echo "0")
send_syslog "web-upload-monitor" "New executable files in webroot last hour: $webshell_candidates"

# 14. Erreurs d'authentification HTTP (Basic Auth / formulaires)
# Indicateur de brute-force sur l'interface d'administration web
if [ -n "$WEB_ACCESS_LOG" ]; then
    http_auth_fail=$(grep -cE '" 401 ' "$WEB_ACCESS_LOG" 2>/dev/null || echo "0")
else
    http_auth_fail="0"
fi
send_syslog "web-auth-monitor" "HTTP 401 auth failures (brute force indicator): $http_auth_fail"

# 15. Taille de la réponse anormalement grande (exfiltration de données via HTTP)
# Une réponse > 10MB sur une requête GET est suspecte
if [ -n "$WEB_ACCESS_LOG" ]; then
    large_responses=$(awk '{if($NF+0 > 10000000) count++} END {print count+0}' \
        "$WEB_ACCESS_LOG" 2>/dev/null || echo "0")
else
    large_responses="0"
fi
send_syslog "web-exfil-monitor" "HTTP responses >10MB (data exfiltration indicator): $large_responses"

echo ""
echo "WEBSRV-CNAS telemetry sent to ELK at $HOST:$PORT"