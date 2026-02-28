#!/bin/bash
# CNAS - WSUS (Windows Server Update Services) Security Telemetry
# Sources: update logs, client connections, patch status, suspicious downloads

HOST="${1:-localhost}"
PORT="${2:-514}"
HOSTNAME="WSUS-CNAS-KOLEA"   

function send_syslog() {
    local program=$1
    local message=$2
    timestamp=$(date '+%b %d %H:%M:%S')
    syslog_msg="<110>$timestamp $HOSTNAME $program: $message"
    echo "$syslog_msg" | nc -u -w 1 $HOST $PORT 2>/dev/null || \
    echo "$syslog_msg" > /dev/udp/$HOST/$PORT 2>/dev/null
    echo "[$HOSTNAME] $program: $message"
}

echo "=== WSUS-CNAS Telemetry ==="
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
# BLOC 2 — SPÉCIFIQUE : WSUS
# Surveille la distribution des mises à jour et les anomalies
# ============================================================

# 9. Clients WSUS connectés (port 8530 HTTP ou 8531 HTTPS)
# Un pic anormal peut indiquer un scan ou une attaque de type "WSUS hijacking"
wsus_clients=$(ss -tun 2>/dev/null | grep -c ":8530\|:8531" || echo "0")
send_syslog "wsus-client-monitor" "Active WSUS client connections (ports 8530/8531): $wsus_clients"

# 10. Volume de téléchargements (indicateur de charge normale vs anormale)
# Un gros téléchargement inattendu peut indiquer une mise à jour malveillante injectée
download_dir="/var/lib/wsus/updates"   # chemin simulé
if [ -d "$download_dir" ]; then
    download_files=$(find "$download_dir" -type f -mmin -60 2>/dev/null | wc -l)
else
    # Fallback: nouveaux fichiers dans /var/cache (équivalent Linux)
    download_files=$(find /var/cache -type f -mmin -60 2>/dev/null | wc -l)
fi
send_syslog "wsus-download-monitor" "Update files downloaded last hour: $download_files"

# 11. Paquets en attente de déploiement
# Sur un vrai WSUS: nombre de patches approuvés mais non encore appliqués
pending_updates=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" || \
                  yum check-update 2>/dev/null | grep -c "^[a-zA-Z]" || echo "0")
send_syslog "wsus-patch-monitor" "Pending system updates available: $pending_updates"

# 12. Erreurs de distribution (clients qui n'ont pas reçu les MAJ)
# Indicateur d'attaque: un attaquant bloque les mises à jour pour maintenir des vulnérabilités
update_errors=$(journalctl --since "1 hour ago" 2>/dev/null | \
                grep -c "update.*error\|apt.*error\|yum.*error\|failed.*install" || echo "0")
send_syslog "wsus-error-monitor" "Update distribution errors: $update_errors"

# 13. Connexions sortantes vers Microsoft Update (normales vs suspectes)
# Un serveur WSUS ne devrait se connecter qu'à windowsupdate.microsoft.com
ms_connections=$(ss -tun 2>/dev/null | grep -c ":443\|:80" || echo "0")
send_syslog "wsus-upstream-monitor" "Outbound connections (Microsoft Update sync): $ms_connections"

# 14. Espace disque utilisé (le cache WSUS peut être volumineux)
# Un disque plein empêche les MAJ de sécurité critiques
disk_usage=$(df /var 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%' || echo "0")
send_syslog "wsus-disk-monitor" "Disk usage on update partition: $disk_usage%"

echo ""
echo "WSUS-CNAS telemetry sent to ELK at $HOST:$PORT"