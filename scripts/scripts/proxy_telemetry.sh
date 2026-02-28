#!/bin/bash
# CNAS - Proxy Server Security Telemetry
# Sources: Squid/nginx logs, outbound traffic, blocked categories, data exfiltration indicators

HOST="${1:-localhost}"
PORT="${2:-514}"
HOSTNAME="PROXY-CNAS-KOLEA"   

function send_syslog() {
    local program=$1
    local message=$2
    timestamp=$(date '+%b %d %H:%M:%S')
    syslog_msg="<110>$timestamp $HOSTNAME $program: $message"
    echo "$syslog_msg" | nc -u -w 1 $HOST $PORT 2>/dev/null || \
    echo "$syslog_msg" > /dev/udp/$HOST/$PORT 2>/dev/null
    echo "[$HOSTNAME] $program: $message"
}

echo "=== PROXY-CNAS Telemetry ==="
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
# BLOC 2 — SPÉCIFIQUE : PROXY
# Surveille le trafic web sortant — vecteur principal d'exfiltration et C2
# ============================================================

# 9. Volume de requêtes HTTP/HTTPS sortantes
# Un proxy CNAS traite typiquement les requêtes des postes de travail vers internet
proxy_log="/var/log/squid/access.log"
if [ -f "$proxy_log" ]; then
    http_requests=$(grep -c "$(date '+%Y/%m/%d')" "$proxy_log" 2>/dev/null || echo "0")
else
    # Fallback: connexions sur ports web
    http_requests=$(ss -tun 2>/dev/null | grep -c ":80\|:443\|:8080" || echo "0")
fi
send_syslog "proxy-traffic-monitor" "HTTP/HTTPS requests processed: $http_requests"

# 10. Requêtes bloquées par le filtre de contenu
# Indicateur: tentatives d'accès à des catégories malveillantes (malware, phishing)
if [ -f "$proxy_log" ]; then
    blocked_requests=$(grep -c "TCP_DENIED\|DENIED\|407\|403" "$proxy_log" 2>/dev/null || echo "0")
else
    blocked_requests=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "DENIED\|blocked\|filtered" || echo "0")
fi
send_syslog "proxy-filter-monitor" "Requests blocked by content filter: $blocked_requests"

# 11. Volume de données sortantes (exfiltration de données)
# Alerte si le volume upload dépasse un seuil anormal
if [ -f "$proxy_log" ]; then
    # Squid log format: champ 5 = bytes envoyés
    outbound_bytes=$(awk '{sum+=$5} END {print int(sum/1024/1024)}' "$proxy_log" 2>/dev/null || echo "0")
else
    outbound_bytes=$(cat /proc/net/dev 2>/dev/null | awk '/eth0|ens|enp/{print int($10/1024/1024)}' | head -1 || echo "0")
fi
send_syslog "proxy-exfil-monitor" "Outbound data volume MB last hour: $outbound_bytes"

# 12. Connexions vers domaines suspects / non catégorisés
# Indicateur C2: communications avec des domaines générés aléatoirement (DGA)
if [ -f "$proxy_log" ]; then
    suspicious_domains=$(grep -c "NONE/\|DIRECT/\|ERR_DNS\|ERR_CONNECT" "$proxy_log" 2>/dev/null || echo "0")
else
    suspicious_domains=$(journalctl --since "1 hour ago" 2>/dev/null | grep -c "NXDOMAIN\|dns.*fail\|connect.*refused" || echo "0")
fi
send_syslog "proxy-threat-monitor" "Connections to suspicious/uncategorized domains: $suspicious_domains"

# 13. Tunneling DNS / requêtes DNS anormales
# Un proxy voit aussi les requêtes DNS — indicateur de tunneling ou beacon C2
dns_queries=$(ss -tun 2>/dev/null | grep -c ":53" || \
              journalctl --since "1 hour ago" 2>/dev/null | grep -c "named\|dnsmasq\|unbound" || echo "0")
send_syslog "proxy-dns-monitor" "DNS queries/connections observed: $dns_queries"

# 14. User Agents suspects (outils de scan, malware connus)
# Indicateur: user agents de type curl/python/nmap dans les logs proxy
if [ -f "$proxy_log" ]; then
    suspicious_ua=$(grep -ciE "curl|python-requests|nmap|nikto|sqlmap|masscan|zgrab" "$proxy_log" 2>/dev/null || echo "0")
else
    suspicious_ua="0"
fi
send_syslog "proxy-ua-monitor" "Suspicious user agents detected: $suspicious_ua"

echo ""
echo "PROXY-CNAS telemetry sent to ELK at $HOST:$PORT"