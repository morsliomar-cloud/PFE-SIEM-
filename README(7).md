# PFE-SIEM — ELK Stack 9.1.3 · CNAS Lab

A containerised SIEM lab built on **Elastic Stack 9.1.3**, simulating four CNAS agency nodes (AD, WSUS, Proxy, WebSrv), shipping live telemetry through Elastic Agent and Logstash, and running real-time attack detection via Elastic Security — all normalised to the **Elastic Common Schema (ECS)** and secured end-to-end with TLS.

> Built as a final-year project (PFE) to demonstrate a production-grade SIEM workflow on a single host. Detection rules written against this lab fire unchanged on real CNAS infrastructure — the only thing that changes is the data source.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Data Tiers — Production vs Lab](#3-data-tiers--production-vs-lab)
4. [Component Responsibilities](#4-component-responsibilities)
5. [ECS Normalisation](#5-ecs-normalisation)
6. [Prerequisites](#6-prerequisites)
7. [Repository Layout](#7-repository-layout)
8. [Phase 1 — Core Stack (Elasticsearch, Kibana, Logstash)](#8-phase-1--core-stack)
9. [Phase 2 — Fleet Server & Agent Enrollment](#9-phase-2--fleet-server--agent-enrollment)
10. [Phase 3 — Logstash Syslog Pipeline](#10-phase-3--logstash-syslog-pipeline)
11. [Phase 4 — CNAS Service Containers (Squid & Nginx)](#11-phase-4--cnas-service-containers)
12. [Phase 5 — Windows VMs (AD & WSUS)](#12-phase-5--windows-vms)
13. [Phase 6 — VirtualBox Networking for VM ↔ Docker](#13-phase-6--virtualbox-networking)
14. [Phase 7 — Detection Rules & Elastic Security](#14-phase-7--detection-rules)
15. [Post-Deployment Hardening](#15-post-deployment-hardening)
16. [Operations & Verification](#16-operations--verification)
17. [Troubleshooting](#17-troubleshooting)
18. [Credentials & Quick Reference](#18-credentials--quick-reference)

---

## 1. Project Overview

**Goal.** Build a fully working SIEM that ingests real Windows Event Logs, real proxy access logs, real web-server access logs, and arbitrary syslog — then detects attacks against all of them with prebuilt and custom rules.

**What's running.**

| Layer | Component | Version | Role |
|---|---|---|---|
| Storage & search | Elasticsearch | 9.1.3 | Indexes all telemetry, hosts detection engine |
| Visualisation | Kibana + Elastic Security | 9.1.3 | Dashboards, alerting, SOC workflow |
| Stream processor | Logstash | 9.1.3 | Receives raw syslog on UDP/TCP 514 |
| Agent fleet | Fleet Server | 9.1.3 | Manages agent policies and enrollment |
| Endpoints | Elastic Agent | 9.1.3 | Ships logs from Windows VMs and Linux containers |
| Service nodes | Squid (Proxy), Nginx (WebSrv) | latest | Real services generating real access logs |

**Security posture.** TLS on every channel, secrets in `.env`, dropped Linux capabilities on agents, dedicated `logstash_writer` role with no superuser usage.

---

## 2. Architecture

```
┌───────────────────────────────── HOST PC ─────────────────────────────────┐
│                                                                            │
│  Docker Desktop (WSL2)                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────────────┐   │
│  │     es01     │  │   kibana01   │  │           logstash01           │   │
│  │  HTTPS :9200 │  │     :5601    │  │   syslog UDP/TCP :514 · :9600  │   │
│  └──────────────┘  └──────────────┘  └────────────────────────────────┘   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │ fleet-server │  │ proxy-cnas   │  │ websrv-cnas  │  │   agent-*    │   │
│  │ HTTPS :8220  │  │ Squid :3128  │  │  Nginx :80   │  │   (Linux)    │   │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘   │
│                                                                            │
│  VirtualBox Host-Only Adapter: 10.10.10.1   ◄──── VMs reach Docker here   │
└────────────────────────────────────────────────────────────────────────────┘

┌───────────────────────────── VirtualBox VMs ──────────────────────────────┐
│                                                                            │
│  AD-CNAS-KOLEA          (Windows Server 2025 · Elastic Agent installed)   │
│  WSUS-CNAS-KOLEA        (Windows Server 2025 · Elastic Agent installed)   │
│      └─► Fleet Server (10.10.10.1:8220) ─► Elasticsearch                  │
└────────────────────────────────────────────────────────────────────────────┘

DATA FLOW
─────────
Windows VMs (AD/WSUS) ─► Elastic Agent ─► logs-windows.*  · logs-system.*
Squid container       ─► agent-proxy   ─► logs-squid.log-default
Nginx container       ─► agent-websrv  ─► logs-nginx.access-default
Network devices       ─► Logstash :514 ─► logs-system.syslog-default
                                          logs-system.auth-default
                            ▼
                      Elastic Security
                  (prebuilt + custom rules)
```

---

## 3. Data Tiers — Production vs Lab

In a real CNAS deployment, every node is a physical or virtualised server with Elastic Agent running natively on it. The lab compresses that topology onto one development host while keeping the data shape identical:

| Node | Production form | Lab form |
|---|---|---|
| `AD-CNAS-KOLEA` | Real Windows Server | VirtualBox VM (Windows Server 2025) |
| `WSUS-CNAS-KOLEA` | Real Windows Server | VirtualBox VM (Windows Server 2025) |
| `PROXY-CNAS-KOLEA` | Real Linux server running Squid | Docker container |
| `WEBSRV-CNAS-KOLEA` | Real Linux server running Nginx | Docker container |

Because Elastic Agent emits the same ECS-mapped data streams regardless of host platform, **detection rules transfer one-to-one between lab and production**. No rule rewrites, no field renames, no index-pattern changes.

---

## 4. Component Responsibilities

### Elastic Agent

Handles every modern, integration-supported source. Each agent enrolls into a Fleet policy and ships into the canonical data stream for its dataset.

| Source | Data stream |
|---|---|
| Windows Security log (AD/WSUS) | `logs-system.security-default` |
| Windows Sysmon (AD/WSUS) | `logs-windows.sysmon_operational-default` |
| Windows PowerShell (AD/WSUS) | `logs-windows.powershell-default`, `logs-windows.powershell_operational-default` |
| Windows Defender (AD/WSUS) | `logs-windows.windows_defender-default` |
| Squid `access.log` | `logs-squid.log-default` |
| Nginx `access.log` | `logs-nginx.access-default` |

### Logstash

Reserved exclusively for **raw syslog from network devices** — sources without an Elastic Agent integration. The pipeline writes to system data streams via the dedicated `logstash_writer` role (no superuser).

| Source | Data stream |
|---|---|
| Auth-related syslog (`sshd`, `sudo`, `su`) | `logs-system.auth-default` |
| Everything else on UDP/TCP :514 | `logs-system.syslog-default` |

### Why this split

Elastic Agent integrations come with curated parsers, ingest pipelines and ECS mappings out of the box. Logstash is only used where no agent integration exists — keeping the configuration surface as small as possible.

---

## 5. ECS Normalisation

Every event lands with ECS field names so detection rules query a single, stable schema.

| Raw field | ECS field |
|---|---|
| `EventID` | `event.code` |
| `TimeCreated` | `@timestamp` |
| `SourceAddress` / `src_ip` | `source.ip` |
| `DestAddress` / `dst_ip` | `destination.ip` |
| `Username` / `user` | `user.name` |
| `Domain` | `user.domain` |
| `ComputerName` / `hostname` | `host.name` |
| `ProcessName` | `process.name` |
| `ProcessId` | `process.pid` |
| `LogonType` | `winlog.logon.type` |
| `AttackTactic` | `threat.tactic.name` |
| `AttackTechnique` | `threat.technique.name` |

A rule like `event.code: "4769" and event.outcome: "failure"` therefore matches identically against a lab VM and a production DC.

---

## 6. Prerequisites

| Requirement | Minimum |
|---|---|
| Docker Desktop (Windows, WSL2 backend) | 4.x |
| RAM for Docker | 8 GB |
| RAM available for VMs | 4 GB additional (2 GB per VM) |
| Disk | 50 GB free |
| VirtualBox | 7.x |
| Windows Server 2025 ISO | For AD and WSUS VMs |
| Git Bash / WSL shell | Required for `.env` editing (no Notepad — see §15.3) |
| Python 3 | 3.9+ |
| `curl`, `openssl` | Bundled with Git Bash / WSL |

Before booting any VM, confirm a VirtualBox **Host-Only network** exists at `10.10.10.1/24` (File → Tools → Network Manager). Without it, the VMs cannot reach Docker.

---

## 7. Repository Layout

```
pfe-siem-project/
├── elk_stack/
│   ├── docker-compose.yml                   # Core stack (ES, Kibana, Logstash, Fleet, agents)
│   ├── .env                                  # Secrets — NEVER commit
│   ├── .gitignore                            # Must include .env, *.key, *.pem
│   ├── certs/                                # TLS material
│   │   ├── elastic-ca.pem  / elastic-ca.key
│   │   ├── es01.crt        / es01.key
│   │   └── fleet-server.crt / fleet-server.key
│   ├── snapshots/                            # Snapshot repository mount
│   ├── logstash/
│   │   ├── pipeline/logstash.conf            # Syslog pipeline
│   │   └── pipelines.yml
│   └── fleet-server/elastic-agent.yml        # Reference policy (unused at runtime)
├── scripts/
│   ├── docker-compose.cnas.yml               # Squid + Nginx service containers
│   ├── nginx/                                # Custom Nginx image (combined log format)
│   │   ├── Dockerfile · entrypoint.sh · nginx.conf
│   └── squid/                                # Custom Squid image
│       └── Dockerfile · entrypoint.sh · squid.conf
└── README.md
```

---

## 8. Phase 1 — Core Stack

### 8.1 Provision secrets (one time)

```bash
cd elk_stack/

cat > .env << 'EOF'
# Service tokens (filled after first boot)
FLEET_SERVICE_TOKEN=
PROXY_ENROLLMENT_TOKEN=
WEBSRV_ENROLLMENT_TOKEN=
AD_ENROLLMENT_TOKEN=
WSUS_ENROLLMENT_TOKEN=
EOF

# Generate strong passwords and keys, then append
{
  echo "ELASTIC_PASSWORD=$(openssl rand -base64 24 | tr -d /+=)"
  echo "KIBANA_SYSTEM_PASSWORD=$(openssl rand -base64 24 | tr -d /+=)"
  echo "LOGSTASH_PASSWORD=$(openssl rand -base64 24 | tr -d /+=)"
  echo "XPACK_ENCRYPTED_SAVED_OBJECTS_KEY=$(openssl rand -hex 32)"
  echo "XPACK_REPORTING_KEY=$(openssl rand -hex 32)"
  echo "XPACK_SECURITY_KEY=$(openssl rand -hex 32)"
} >> .env

# Strip Windows line endings if you ever edit .env outside Linux/WSL
sed -i 's/\r//' .env

# Lock it out of Git immediately
echo ".env"  >> .gitignore
echo "*.key" >> .gitignore
echo "*.pem" >> .gitignore
```

> ⚠️ **Always edit `.env` in Linux/WSL.** Notepad on Windows saves CRLF line endings, which embed invisible `\r` characters into variable values and break `curl` JSON payloads downstream.

### 8.2 Generate TLS certificates

```bash
mkdir -p certs && cd certs

# 1. CA
docker run --rm -v "$(pwd):/certs" \
  docker.elastic.co/elasticsearch/elasticsearch-wolfi:9.1.3 bash -c "
    cd /usr/share/elasticsearch
    bin/elasticsearch-certutil ca --pem --out /certs/ca.zip --pass '' --silent
    cd /certs && unzip -o ca.zip
    cp ca/ca.crt elastic-ca.pem && cp ca/ca.key elastic-ca.key
  "

# 2. Node certs (es01 + fleet-server)
docker run --rm -v "$(pwd):/certs" \
  docker.elastic.co/elasticsearch/elasticsearch-wolfi:9.1.3 bash -c "
    cd /usr/share/elasticsearch
    for n in es01 fleet-server; do
      bin/elasticsearch-certutil cert \
        --ca-cert /certs/elastic-ca.pem --ca-key /certs/elastic-ca.key \
        --pem --out /certs/\$n.zip --name \$n \
        --dns \$n --dns localhost --ip 127.0.0.1 \
        --pass 'temp123' --silent
      cd /certs && unzip -o \$n.zip && cp \$n/\$n.crt \$n.crt
      cd /usr/share/elasticsearch
    done
  "

# 3. Strip key passwords
for n in es01 fleet-server; do
  docker run --rm -v "$(pwd):/certs" alpine/openssl rsa \
    -in /certs/$n/$n.key -out /certs/$n.key -passin pass:temp123
done

chmod 644 *.pem *.crt *.key
cd ..
```

The fingerprint of `elastic-ca.pem` is referenced in `docker-compose.yml` (`XPACK_FLEET_OUTPUTS … ca_trusted_fingerprint`). Regenerate it whenever the CA changes:

```bash
openssl x509 -noout -fingerprint -sha256 -in certs/elastic-ca.pem | sed 's/.*=//;s/://g'
```

### 8.3 Boot Elasticsearch and bootstrap built-in users

```bash
set -a && source .env && set +a
docker compose up -d es01
sleep 40

# Confirm ES is up
curl -sk -u elastic:${ELASTIC_PASSWORD} https://localhost:9200/_cluster/health
```

> If you get `401 Unauthorized` on a fresh volume, the password baked into `esdata` doesn't match `.env`. Reset it:
> ```bash
> docker exec -it es01 bin/elasticsearch-reset-password \
>   -u elastic --url https://localhost:9200 --batch
> ```
> Copy the printed password into `.env` and `set -a && source .env && set +a` again.

Set the `kibana_system` and `logstash_system` passwords to match `.env`:

```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  -X POST https://localhost:9200/_security/user/kibana_system/_password \
  -H 'Content-Type: application/json' \
  -d "{\"password\":\"${KIBANA_SYSTEM_PASSWORD}\"}"

curl -sk -u elastic:${ELASTIC_PASSWORD} \
  -X POST https://localhost:9200/_security/user/logstash_system/_password \
  -H 'Content-Type: application/json' \
  -d "{\"password\":\"${LOGSTASH_PASSWORD}\"}"
```

### 8.4 Bring up the rest

```bash
docker compose up -d
sleep 40
docker ps
```

Kibana: `https://localhost:5601` · login `elastic` / `${ELASTIC_PASSWORD}`.

---

## 9. Phase 2 — Fleet Server & Agent Enrollment

### 9.1 Generate the Fleet service token

```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  -X POST "https://localhost:9200/_security/service/elastic/fleet-server/credential/token/fleet-token-1" \
  -H "Content-Type: application/json" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token']['value'])"
```

Paste the token into `.env` as `FLEET_SERVICE_TOKEN=…`, then recreate Fleet Server so it picks up the new value:

```bash
docker compose up -d --force-recreate fleet-server
sleep 30
docker logs fleet-server --tail 30 | grep -E "started|error"
```

### 9.2 Common Phase 2 issues (and the fixes that work)

**Kibana can't authenticate to Elasticsearch.** Symptoms: `kibana01` log spam about authentication failures; the UI never loads. Cause: the `kibana_system` password in `.env` and Elasticsearch are out of sync.

```bash
# Reset kibana_system to match the .env value
curl -sk -u elastic:${ELASTIC_PASSWORD} -X POST \
  "https://localhost:9200/_security/user/kibana_system/_password" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"${KIBANA_SYSTEM_PASSWORD}\"}"

docker compose up -d --force-recreate kibana01
```

**Fleet Server fails to start with `invalid token`.** The token in `.env` no longer exists in Elasticsearch (e.g. volume was wiped). Delete and recreate:

```bash
# Delete existing token
curl -sk -u elastic:${ELASTIC_PASSWORD} -X DELETE \
  "https://localhost:9200/_security/service/elastic/fleet-server/credential/token/fleet-token-1"

# Recreate it
curl -sk -u elastic:${ELASTIC_PASSWORD} -X POST \
  "https://localhost:9200/_security/service/elastic/fleet-server/credential/token/fleet-token-1" \
  -H "Content-Type: application/json"
```

Copy the new `value` into `.env` → `FLEET_SERVICE_TOKEN=…` and run `docker compose up -d --force-recreate fleet-server`.

### 9.3 Create agent policies in Kibana

**Management → Fleet → Agent Policies → Create agent policy**, then add integrations:

| Policy | Integration |
|---|---|
| `AD-CNAS Policy` | System + Windows |
| `WSUS-CNAS Policy` | System + Windows |
| `PROXY-CNAS Policy` | System + Squid (custom log path `/var/log/squid/access.log`) |
| `WEBSRV-CNAS Policy` | System + Nginx (custom log path `/var/log/nginx/access.log`) |

Copy each policy's enrollment token into the matching `.env` variable.

### 9.4 Start the Linux agents

```bash
docker compose up -d agent-proxy agent-websrv
docker logs agent-proxy   --tail 30 | grep -Ei "error|warn"
docker logs agent-websrv  --tail 30 | grep -Ei "error|warn"
```

Windows VM enrollment is covered in [Phase 5](#12-phase-5--windows-vms).

---

## 10. Phase 3 — Logstash Syslog Pipeline

`logstash/pipeline/logstash.conf` listens on UDP/TCP **514** and routes events to two ECS-correct data streams:

- `logs-system.auth-default` — events from `sshd`, `sudo`, `su`
- `logs-system.syslog-default` — everything else

Logstash authenticates as `logstash_writer` (created in [§15.4](#154-rbac-logstash-and-kibana-users)) over TLS. No superuser involved.

Test ingestion from the host:

```bash
python3 -c "
import socket
msg='<34>$(date +"%b %d %H:%M:%S") test-host sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2'
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(msg.encode(), ('127.0.0.1', 514))
"
sleep 5
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  "https://localhost:9200/logs-system.auth-default/_count?pretty"
```

---

## 11. Phase 4 — CNAS Service Containers

### 11.1 Bring up Squid and Nginx

```bash
cd ../scripts
docker compose -f docker-compose.cnas.yml up -d
```

Verify real logs are being generated:

```bash
docker exec PROXY-CNAS-KOLEA  tail -f /var/log/squid/access.log
docker exec WEBSRV-CNAS-KOLEA tail -f /var/log/nginx/access.log
```

### 11.2 Volume wiring

The agents read service logs through Docker named volumes shared with the service containers:

```
WEBSRV-CNAS-KOLEA  ──► writes to elk_stack_websrv-logs → /var/log/nginx
agent-websrv       ──► reads  from elk_stack_websrv-logs → /var/log/nginx (read-only)

PROXY-CNAS-KOLEA   ──► writes to elk_stack_proxy-logs  → /var/log/squid
agent-proxy        ──► reads  from elk_stack_proxy-logs  → /var/log/squid  (read-only)
```

### 11.3 Nginx log format

The Elastic Nginx integration expects the `combined` format. `scripts/nginx/nginx.conf` already sets:

```nginx
access_log /var/log/nginx/access.log combined;
```

This file is bind-mounted into the container — no manual reload needed on a fresh build.

### 11.4 Why `logs-system.auth-default` is empty for service containers

Minimal Docker images (`nginx:latest`, `ubuntu/squid`) ship without `rsyslog` or an init system. There is no `auth.log` for the agent to read. This is expected — auth events are collected from the Windows VMs and from any external syslog source on port 514.

---

## 12. Phase 5 — Windows VMs

### 12.1 VM creation

| Setting | Value |
|---|---|
| OS | Windows Server 2025 |
| RAM | 2048 MB minimum |
| CPU | 2 cores |
| Adapter 1 | NAT (internet) |
| Adapter 2 | **Host-Only Adapter → `VirtualBox Host-Only Ethernet Adapter` (10.10.10.1)** — mandatory |

### 12.2 hosts file on each VM (PowerShell as Administrator)

```powershell
$hosts = Get-Content "C:\Windows\System32\drivers\etc\hosts"
$hosts = $hosts | Where-Object { $_ -notmatch "es01|fleet-server" }
$hosts | Set-Content "C:\Windows\System32\drivers\etc\hosts"

Add-Content "C:\Windows\System32\drivers\etc\hosts" "10.10.10.1`tes01"
Add-Content "C:\Windows\System32\drivers\etc\hosts" "10.10.10.1`tfleet-server"

Test-NetConnection -ComputerName fleet-server -Port 8220   # TcpTestSucceeded : True
```

### 12.3 Trust the CA, then enroll

Copy `elk_stack/certs/elastic-ca.pem` to the VM, then:

```powershell
# Trust the lab CA (one time)
Import-Certificate -FilePath "C:\elastic-ca.pem" -CertStoreLocation Cert:\LocalMachine\Root

# Download and install the agent (replace token)
Invoke-WebRequest `
  -Uri "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.1.3-windows-x86_64.zip" `
  -OutFile "elastic-agent.zip"
Expand-Archive elastic-agent.zip -DestinationPath C:\elastic-agent
cd C:\elastic-agent\elastic-agent-9.1.3-windows-x86_64

.\elastic-agent.exe install `
  --url=https://fleet-server:8220 `
  --enrollment-token=<AD_OR_WSUS_TOKEN_FROM_KIBANA> `
  --non-interactive
```

Trusting the CA in `LocalMachine\Root` is preferred over `--insecure`; it works across all Windows tooling and survives agent reinstalls.

### 12.4 Audit policy (run on each VM)

Without these, the Windows Security log will not contain the events the detection rules query.

```powershell
auditpol /set /subcategory:"Credential Validation"      /success:enable /failure:enable
auditpol /set /subcategory:"Logon"                      /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout"            /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation"           /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access"   /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes"  /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon"              /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management"  /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management"    /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use"    /success:enable /failure:enable
```

### 12.5 PowerShell logging

```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
        /v EnableModuleLogging /t REG_DWORD /d 1 /f
```

### 12.6 Windows Server 2025 caveat — event ID filters silently ignored

WS2025 has a known Event Log API limitation: filters configured in the Windows integration are dropped. **Workaround:** in Fleet → Windows integration, remove all event ID filters and let the agent collect everything.

⚠️ Unfiltered collection on a busy AD DC produces hundreds of events per minute (4634, 4648, 4776). After enabling, immediately apply the ILM policy in [§15.1](#151-storage-hardening) and add explicit exclusions for the noisiest benign events.

---

## 13. Phase 6 — VirtualBox Networking

### Why `10.0.2.2` (NAT) does not work

Docker Desktop runs inside WSL2 (Hyper-V). The Hyper-V WSL firewall intercepts inbound TCP from VirtualBox NAT's `10.0.2.2` even though `0.0.0.0:9200` shows as `LISTENING`.

```
VM ─► 10.0.2.2 (VBox NAT) ─► Windows ─► Hyper-V WSL firewall  ❌ blocked
                                                ─► WSL2 ─► Docker
```

### Why `10.10.10.1` (Host-Only) works

The Host-Only adapter is a native Windows interface; Docker's `0.0.0.0` binding covers it. Traffic bypasses the WSL2 firewall entirely.

```
VM ─► 10.10.10.1 (native Windows iface) ─► Docker 0.0.0.0:9200  ✅
```

### Host-side checks

```powershell
# IP must be 10.10.10.1
ipconfig | findstr "10.10.10"

# Both must show 0.0.0.0
netstat -an | findstr "9200"
netstat -an | findstr "8220"

# Open the firewall (one time, as Administrator)
New-NetFirewallRule -DisplayName "ELK ES 9200"     -Direction Inbound -Protocol TCP -LocalPort 9200 -Action Allow
New-NetFirewallRule -DisplayName "ELK Fleet 8220"  -Direction Inbound -Protocol TCP -LocalPort 8220 -Action Allow
New-NetFirewallRule -DisplayName "ELK Kibana 5601" -Direction Inbound -Protocol TCP -LocalPort 5601 -Action Allow
```

> **Do not use** `networkingMode=mirrored` in `.wslconfig` or `netsh interface portproxy` — both interfere with Docker Desktop's internal networking and were verified broken in this environment.

---

## 14. Phase 7 — Detection Rules

### 14.1 Health gate (run before enabling rules)

Rules firing against empty indices produce false confidence. Verify everything is flowing:

```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  "https://localhost:9200/_cat/indices/logs-windows.*,logs-system.*,logs-squid.*,logs-nginx.*?v&h=index,docs.count&s=index"
```

All expected data streams must show non-zero `docs.count`.

### 14.2 Load and enable rules

**Kibana → Security → Rules → Detection Rules → Add Elastic rules.**

Enable in this order:

#### 🔴 Tier 1 — Critical (enable first)

Filter: **Severity = Critical → Enable All**.

Key Windows rules:
- *Suspicious Lsass Process Access*, *LSASS Memory Dump Handle Access*
- *Potential Credential Access via Windows Utilities*
- *Windows Event Log Cleared*, *Disable Windows Event and Security Logs*
- *Scheduled Task Created*, *Persistence via WMI Event Subscription*
- *Potential Shadow Credentials added to AD Object*
- *Windows Service Installed via an Unusual Client*
- *PowerShell HackTool Script*, *Suspicious PowerShell Script*
- *Network Connection via Certutil*

Key Linux rules:
- *Web Shell Detection: Script Process Child of Common Web Process*
- *Unusual Web Server Command Execution*
- *Suspicious Child Execution via Web Server*
- *Linux Restricted Shell Breakout*
- *Systemd Service Created*
- *Potential Data Exfiltration Through Curl*

#### 🟠 Tier 2 — High

Filter: **Severity = High** → enable rules tagged `Windows`, `Linux`, or `Active Directory`.

#### 🟡 Tier 3 — Medium

Review individually. **Skip rules tagged AWS / GCP / Kubernetes / Office365** — they only generate noise here.

### 14.3 Index-pattern note

Do **not** alias `winlogbeat-*` onto data streams; this triggers `verification_exception` on rules referencing `process.name`. If a prebuilt rule needs a different index pattern, **duplicate the rule** and append the pattern to the copy.

### 14.4 Detection map per source

| Source | Examples |
|---|---|
| `AD-CNAS-KOLEA` (Win Sec) | 4625 brute force · 4740 lockout · 4769 Kerberoasting (RC4) · 4662 DCSync · 4728 Domain Admin add · 4672 special priv |
| `WSUS-CNAS-KOLEA` (Win Sec) | Same Windows rule set; WSUS-specific *IIS HTTP Logging Disabled* |
| `PROXY-CNAS-KOLEA` (Squid) | DNS tunneling · connection to commonly abused web services |
| `WEBSRV-CNAS-KOLEA` (Nginx) | Web shell child process · unusual web-server command execution |

---

## 15. Post-Deployment Hardening

The deployment as it stands is functional and TLS-secured, but a production-ready posture requires the runtime apply steps below. Items marked ✅ are already enforced by `docker-compose.yml` / `logstash.conf`; ⏳ items are one-time API calls or UI actions.

| # | Item | Status | Reference |
|---|---|---|---|
| 15.1 | ILM policy on system data streams | ⏳ | Storage |
| 15.1 | Snapshot repository + daily SLM | ⏳ | Storage |
| 15.1 | Replicas = 0 globally (single-node) | ⏳ | Storage |
| 15.1 | Disk watermarks tuned for 50 GB disk | ⏳ | Storage |
| 15.2 | `syslog-*` index template (legacy guard) | ⏳ | Schema |
| 15.3 | Secrets in `.env`, not in compose files | ✅ | Security |
| 15.3 | TLS on ES, Kibana, Logstash, Fleet | ✅ | Security |
| 15.3 | `.env` excluded from Git | ⏳ verify | Security |
| 15.4 | `logstash_writer` role (no superuser for ingest) | ✅ | Security |
| 15.4 | `siem-analyst` Kibana role | ⏳ | Security |
| 15.4 | Fleet enrollment tokens revoked after enrollment | ⏳ | Security |
| 15.5 | Container hardening (no `pid:host`, `cap_drop: ALL`) | ✅ | Runtime |
| 15.5 | `restart: unless-stopped` on ES + Kibana | ✅ | Runtime |
| 15.5 | `ulimits` on ES (memlock, nofile) | ✅ | Runtime |
| 15.5 | `vm.max_map_count=262144` on host | ⏳ | Runtime |
| 15.6 | Stack Monitoring enabled in Kibana | ⏳ | Operations |
| 15.6 | Pre-demo health check script | ⏳ | Operations |

### 15.1 Storage hardening

**ILM policy** (prevents flood-stage lockout when disks fill):

```bash
# 1. Component template that only injects an ILM name
curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_component_template/custom-syslog-ilm" \
  -H "Content-Type: application/json" \
  -d '{"template":{"settings":{"index.lifecycle.name":"syslog-policy"}}}'

# 2. Append it to the managed system.syslog template (do NOT replace composed_of —
#    fetch the existing array first and add "custom-syslog-ilm" at the end)
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  "https://localhost:9200/_index_template/logs-system.syslog?pretty" \
  | grep -A 20 "composed_of"

# 3. The policy itself
curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_ilm/policy/syslog-policy" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": { "phases": {
      "hot":    { "min_age":"0ms","actions":{"rollover":{"max_size":"5gb","max_age":"7d"}}},
      "delete": { "min_age":"30d","actions":{"delete":{}}}
    }}
  }'
```

Repeat for `logs-system.auth`, `logs-system.security`, `logs-windows.sysmon_operational`, etc.

**Snapshot repository + daily SLM** (the `path.repo` mount is already declared in `docker-compose.yml`):

```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_snapshot/local_backup" \
  -H "Content-Type: application/json" \
  -d '{"type":"fs","settings":{"location":"/usr/share/elasticsearch/snapshots","compress":true}}'

curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_slm/policy/daily-snapshots" \
  -H "Content-Type: application/json" \
  -d '{
    "schedule":"0 30 1 * * ?",
    "name":"<daily-snap-{now/d}>",
    "repository":"local_backup",
    "config":{"include_global_state":true},
    "retention":{"expire_after":"14d","min_count":3,"max_count":14}
  }'
```

**Replicas = 0** (single-node — every index starts yellow otherwise, breaking the *Cluster Status Changed* prebuilt rule):

```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_settings" \
  -H "Content-Type: application/json" \
  -d '{"index":{"number_of_replicas":"0"}}'

curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_template/default-no-replicas" \
  -H "Content-Type: application/json" \
  -d '{"index_patterns":["*"],"order":0,"settings":{"number_of_replicas":"0"}}'
```

**Disk watermarks** (default 85/90/95 % is unsafe on a 50 GB disk):

```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_cluster/settings" \
  -H "Content-Type: application/json" \
  -d '{
    "persistent":{
      "cluster.routing.allocation.disk.watermark.low":"10gb",
      "cluster.routing.allocation.disk.watermark.high":"5gb",
      "cluster.routing.allocation.disk.watermark.flood_stage":"2gb"
    }
  }'
```

### 15.2 `syslog-*` index template (legacy guard)

Logstash currently writes to `logs-system.*` data streams (managed templates apply). This template is only needed if you ever fall back to legacy `syslog-YYYY.MM.dd` indices:

```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_index_template/syslog-template" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns":["syslog-*"],
    "template":{
      "settings":{"number_of_replicas":0},
      "mappings":{"properties":{
        "@timestamp":{"type":"date"},
        "source.ip":{"type":"ip"},
        "host.name":{"type":"keyword"},
        "process.name":{"type":"keyword"},
        "facility":{"type":"integer"},
        "severity":{"type":"integer"},
        "message":{"type":"text"}
      }}
    }
  }'
```

### 15.3 Secrets handling

`.env` already holds every credential; verify it never reaches Git:

```bash
# In repo root
echo ".env"  >> .gitignore
echo "*.key" >> .gitignore
echo "*.pem" >> .gitignore
git rm --cached elk_stack/.env 2>/dev/null || true
git commit -m "sec: lock secrets out of version control"

# Sanity scan — neither command should return any non-comment match
grep -rn "changeme" elk_stack/docker-compose.yml elk_stack/logstash/
grep -rn 'password.*=.*[A-Za-z0-9]\{8,\}' elk_stack/docker-compose.yml \
  | grep -v '\${' | grep -v '#'
```

> If `changeme` was ever pushed to a public remote, treat those values as compromised and rotate every password and key in `.env`.

### 15.4 RBAC: Logstash and Kibana users

**`logstash_writer` (already used by `logstash.conf`):**

```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_security/role/logstash_writer" \
  -H 'Content-Type: application/json' \
  -d '{
    "cluster":["monitor","manage_index_templates","manage_ilm","manage_pipeline"],
    "indices":[{
      "names":["logs-*",".ds-logs-*"],
      "privileges":["create_doc","create_index","manage","auto_configure","create","index","write"]
    }]
  }'

curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_security/user/logstash_writer" \
  -H 'Content-Type: application/json' \
  -d "{\"password\":\"${LOGSTASH_PASSWORD}\",\"roles\":[\"logstash_writer\"],\"full_name\":\"Logstash Output User\"}"
```

**`siem-analyst` (read-only Kibana role for evaluators):**

Kibana → Stack Management → Security → Roles → Create role.
- Indices: `logs-*`, `syslog-*`, `.alerts-*` → read, view_index_metadata
- Kibana spaces: Read on Security, Discover, Dashboard.

Then create an `analyst` user mapped to that role for demo viewing.

**Revoke Fleet enrollment tokens** once all four agents (AD, WSUS, proxy, websrv) are healthy:
Kibana → Fleet → Enrollment tokens → Revoke. Already-enrolled agents keep working; only new enrollments are blocked.

### 15.5 Runtime hardening

**Host kernel parameter** for Elasticsearch:

```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

The container hardening listed below is **already enforced** by `docker-compose.yml` and `logstash.conf`:

- TLS on every listener (`xpack.security.http.ssl.enabled=true`, Fleet `FLEET_SERVER_CERT`, Kibana `ELASTICSEARCH_SSL_*`).
- No `pid: host` on agent containers.
- `cap_drop: ALL` plus a minimal allow-list (`NET_ADMIN`, `NET_RAW`, `DAC_READ_SEARCH`).
- `security_opt: no-new-privileges:true`.
- Specific host mounts (`/proc`, `/sys/fs/cgroup`, `/etc/hostname`, `/etc/os-release`) — never `/:/hostfs:ro`.
- `ulimits.memlock=-1` and `nofile=65536` on `es01`.
- `restart: unless-stopped` on every long-running service.
- Network segmentation: `backend-net` (ES, Kibana, Logstash) ↔ `frontend-net` (Fleet, agents); only Fleet bridges both.

### 15.6 Operational

**Enable Stack Monitoring** so heap usage, Logstash event rates and Fleet health are visible without `docker logs`:
Kibana → Stack Management → Stack Monitoring → Turn on monitoring.

**Pre-demo health check** (`scripts/setup/pre-demo-check.sh`):

```bash
#!/usr/bin/env bash
set -e
source elk_stack/.env

echo "── Containers ──"
docker ps --format "table {{.Names}}\t{{.Status}}" | grep -v "Up.*healthy" | tee /tmp/unhealthy
[ "$(wc -l < /tmp/unhealthy)" -le 1 ] || { echo "❌ unhealthy containers"; exit 1; }

echo "── Cluster ──"
curl -fsk -u "elastic:${ELASTIC_PASSWORD}" "https://localhost:9200/_cluster/health" \
  | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['status']);exit(0 if d['status']!='red' else 1)"

echo "── Data streams ──"
curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
  "https://localhost:9200/_cat/indices/logs-*?h=index,docs.count" \
  | awk '$2==0 {print "⚠ empty: "$1}'

echo "── Fleet agents ──"
curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
  "https://localhost:5601/api/fleet/agents?perPage=20" -H 'kbn-xsrf:true' \
  | python3 -c "
import sys,json
for a in json.load(sys.stdin).get('list',[]):
    n=a.get('local_metadata',{}).get('host',{}).get('name','?')
    s=a.get('status','?')
    print(f'  {n}: {s}')
    if s!='online': sys.exit(1)
"
echo "✅ ready"
```

---

## 16. Operations & Verification

### Cluster snapshot

```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} "https://localhost:9200/_cluster/health?pretty"
```

### Indices and data streams

```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  "https://localhost:9200/_cat/indices/logs-*,syslog-*?v&s=index&h=index,docs.count,store.size"
```

> Data streams live under **Stack Management → Index Management → Data Streams** in Kibana — they do **not** appear under the *Indices* tab.

### Logstash pipeline stats

```bash
curl -s http://localhost:9600/_node/stats/pipelines?pretty \
  | python3 -c "
import sys,json
for n,p in json.load(sys.stdin)['pipelines'].items():
    e=p['events']; print(f'{n}: in={e[\"in\"]} out={e[\"out\"]} failed={e.get(\"failed\",0)}')
"
```

### Fleet agent status

```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  "https://localhost:5601/api/fleet/agents?perPage=20" -H "kbn-xsrf: true" \
  | python3 -c "
import sys,json
for a in json.load(sys.stdin).get('list',[]):
    n=a.get('local_metadata',{}).get('host',{}).get('name','?')
    print(f'  {n}: {a.get(\"status\",\"?\")}')"
```

### Useful Kibana data views

| Data view | Index pattern |
|---|---|
| Windows — All | `logs-windows.*,logs-system.security-default,logs-system.application-default,logs-system.system-default` |
| Linux — All | `logs-squid.log-default,logs-nginx.access-default,logs-system.auth-default` |
| Raw Syslog | `logs-system.syslog-default` |
| Fleet Telemetry | `metrics-*,logs-elastic_agent*` |
| All Security | `logs-*` |

### Useful KQL

```kql
host.name : "AD-CNAS-KOLEA"
event.category : "authentication" and event.outcome : "failure"
event.code : "4769"               # Kerberoasting indicator
event.code : "4662"               # DCSync indicator
threat.tactic.name : *            # Anything MITRE-tagged
```

---

## 17. Troubleshooting

**VM cannot reach Docker (`Test-NetConnection` fails).** NAT (`10.0.2.2`) does not work — see [Phase 6](#13-phase-6--virtualbox-networking). Use the Host-Only adapter at `10.10.10.1`. Do not use `networkingMode=mirrored` or `netsh portproxy`.

**`401 Unauthorized` from Kibana or Logstash.** Built-in user passwords are out of sync with `.env`. Reset `kibana_system` / `logstash_system` via the API (see [§9.2](#92-common-phase-2-issues-and-the-fixes-that-work) and [§8.3](#83-boot-elasticsearch-and-bootstrap-built-in-users)) and `--force-recreate` the affected container.

**Fleet Server `invalid token`.** The token was deleted server-side or Elasticsearch was wiped. Recreate per [§9.2](#92-common-phase-2-issues-and-the-fixes-that-work).

**Indices show as YELLOW.** Single-node cluster; replicas can never be assigned. Apply `number_of_replicas: 0` (see [§15.1](#151-storage-hardening)).

**Nginx logs not appearing despite the volume mount.** The Elastic integration parses `combined`, not `main`. The fix is already in `scripts/nginx/nginx.conf`; rebuild the container if you changed the format manually:
```bash
docker compose -f scripts/docker-compose.cnas.yml up -d --build websrv-cnas
```

**`logs-system.auth-default` is empty for the Linux agents.** Expected — minimal Squid/Nginx images have no `rsyslog`. Auth events come from the Windows VMs and from external syslog on port 514.

**`_grokparsefailure` tag in Logstash.** Caused by a syslog payload that doesn't match `<PRI>TIMESTAMP HOST PROG[PID]: MSG`. Confirm the sender is RFC 3164 compliant; the lab's pipeline only rewrites `message` when the grok succeeds.

**Windows Server 2025 filter warning.** Known WS2025 Event Log API limitation — see [§12.6](#126-windows-server-2025-caveat--event-id-filters-silently-ignored).

**ES blocks wildcard index deletion (`destructive_requires_name`).** Temporarily relax the cluster setting, delete, restore:
```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_cluster/settings" \
  -H "Content-Type: application/json" \
  -d '{"transient":{"action.destructive_requires_name":false}}'
```

**Git Bash mangles paths on Windows.** Add `export MSYS_NO_PATHCONV=1` to `~/.bashrc`.

**`.env` values get extra invisible characters.** Edited in Notepad — re-strip:
```bash
sed -i 's/\r//' elk_stack/.env
cat -A elk_stack/.env | grep -E "PASSWORD|KEY"   # every line must end with $
```

---

## 18. Credentials & Quick Reference

| Service | URL | Credentials |
|---|---|---|
| Elasticsearch | `https://localhost:9200` | `elastic` / `${ELASTIC_PASSWORD}` |
| Kibana + Elastic Security | `https://localhost:5601` | `elastic` / `${ELASTIC_PASSWORD}` |
| Fleet Server | `https://localhost:8220` | service token in `.env` |
| Logstash monitoring | `http://localhost:9600` | — |
| Squid Proxy | `http://localhost:3128` | — |
| Nginx WebSrv | `http://localhost:80` | — |

### `.env` template

```env
# Service tokens
FLEET_SERVICE_TOKEN=
PROXY_ENROLLMENT_TOKEN=
WEBSRV_ENROLLMENT_TOKEN=
AD_ENROLLMENT_TOKEN=
WSUS_ENROLLMENT_TOKEN=

# Built-in user passwords
ELASTIC_PASSWORD=
KIBANA_SYSTEM_PASSWORD=
LOGSTASH_PASSWORD=

# Kibana encryption keys (openssl rand -hex 32)
XPACK_ENCRYPTED_SAVED_OBJECTS_KEY=
XPACK_REPORTING_KEY=
XPACK_SECURITY_KEY=
```

### Network reference

| Address | Purpose |
|---|---|
| `10.10.10.1` | VirtualBox Host-Only adapter — VMs reach Docker here |
| `10.0.2.2` | VirtualBox NAT gateway — **does not** reach Docker on WSL2 |
| `127.0.0.1` | Host-only — not reachable from VMs |

### Host firewall rules (Windows, as Administrator)

```powershell
New-NetFirewallRule -DisplayName "ELK ES 9200"     -Direction Inbound -Protocol TCP -LocalPort 9200 -Action Allow
New-NetFirewallRule -DisplayName "ELK Fleet 8220"  -Direction Inbound -Protocol TCP -LocalPort 8220 -Action Allow
New-NetFirewallRule -DisplayName "ELK Kibana 5601" -Direction Inbound -Protocol TCP -LocalPort 5601 -Action Allow
```

---

*Elastic Stack 9.1.3 · Elastic Agent 9.1.3 · Elastic Security · Docker Desktop (WSL2) · VirtualBox 7.x · Windows Server 2025*

*Lab environment — credentials in `.env` are unique per deployment. Rotate everything before any external exposure.*
