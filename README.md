# PFE-SIEM — ELK Stack 9.x CNAS Lab

A fully containerised SIEM lab built on **ELK Stack 9.1.3**, simulating four CNAS agency nodes (AD, WSUS, Proxy, WebSrv), ingesting real cybersecurity datasets, and running live attack detection via Elastic Security — all normalized to **Elastic Common Schema (ECS)**.

> **Read this first.** This README documents the **target architecture** (designed state), the **current deployed state** (what is actually running), and **migration steps** between the two. Follow the target architecture for any fresh deployment.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Data Tiers — Real vs Simulated vs Live](#2-data-tiers--real-vs-simulated-vs-live)
3. [Elastic Agent vs Logstash — Who Does What](#3-elastic-agent-vs-logstash--who-does-what)
4. [ECS Normalization — Core Requirement](#4-ecs-normalization--core-requirement)
5. [Dataset Mapping per CNAS Source](#5-dataset-mapping-per-cnas-source)
6. [Current Deployed State](#6-current-deployed-state)
7. [Prerequisites](#7-prerequisites)
8. [Repository Layout](#8-repository-layout)
9. [Phase 1 — Core ELK Stack](#9-phase-1--core-elk-stack)
10. [Phase 2 — Fleet Server & Agent Enrollment](#10-phase-2--fleet-server--agent-enrollment)
11. [Phase 3 — Logstash Multi-Pipeline](#11-phase-3--logstash-multi-pipeline)
12. [Phase 4 — Dataset Preparation](#12-phase-4--dataset-preparation)
13. [Phase 5 — CNAS Containers (Proxy & WebSrv)](#13-phase-5--cnas-containers-proxy--websrv)
14. [Phase 6 — Windows VMs Setup (AD & WSUS)](#14-phase-6--windows-vms-setup-ad--wsus)
15. [Phase 7 — VirtualBox Networking for VM→Docker Connectivity](#15-phase-7--virtualbox-networking-for-vmdocker-connectivity)
16. [Phase 8 — Shared Volume Wiring](#16-phase-8--shared-volume-wiring)
17. [Phase 9 — Ingest & Verify](#17-phase-9--ingest--verify)
18. [Kibana Data Views](#18-kibana-data-views)
19. [Phase 10 — Elastic Security & Detection Rules](#19-phase-10--elastic-security--detection-rules)
20. [Migration: Current State → Target Architecture](#20-migration-current-state--target-architecture)
21. [Real Production Deployment](#21-real-production-deployment)
22. [Known Issues & Fixes](#22-known-issues--fixes)
23. [Troubleshooting Reference](#23-troubleshooting-reference)
24. [Credentials & Quick Reference](#24-credentials--quick-reference)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CURRENT ARCHITECTURE                                │
│                                                                             │
│  ┌─ HOST PC ──────────────────────────────────────────────────────────┐    │
│  │                                                                     │    │
│  │  Docker (WSL2)                                                      │    │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────┐   │    │
│  │  │   es01      │  │  kibana01    │  │     logstash01          │   │    │
│  │  │  :9200      │  │   :5601      │  │  Syslog UDP/TCP :514    │   │    │
│  │  └─────────────┘  └──────────────┘  └─────────────────────────┘   │    │
│  │  ┌─────────────┐  ┌──────────────┐  ┌──────────┐  ┌───────────┐  │    │
│  │  │fleet-server │  │ proxy-cnas   │  │agent-    │  │agent-     │  │    │
│  │  │  :8220      │  │(Squid :3128) │  │proxy     │  │websrv     │  │    │
│  │  └─────────────┘  └──────────────┘  └──────────┘  └───────────┘  │    │
│  │  ┌─────────────┐                                                   │    │
│  │  │ websrv-cnas │                                                   │    │
│  │  │(Nginx :80)  │                                                   │    │
│  │  └─────────────┘                                                   │    │
│  │                                                                     │    │
│  │  VirtualBox Host-Only Adapter: 10.10.10.1  ◄── VMs connect here   │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  ┌─ VirtualBox VMs ───────────────────────────────────────────────────┐    │
│  │                                                                     │    │
│  │  AD-CNAS-KOLEA (Windows Server 2025)                               │    │
│  │    Elastic Agent → Fleet Server (10.10.10.1:8220)                  │    │
│  │    Real Windows Event Logs →                                        │    │
│  │      logs-windows.sysmon_operational-default                       │    │
│  │      logs-system.security-default                                  │    │
│  │      logs-windows.powershell-default                               │    │
│  │      logs-windows.windows_defender-default                         │    │
│  │                                                                     │    │
│  │  WSUS-CNAS-KOLEA (Windows Server 2025)                             │    │
│  │    Elastic Agent → Fleet Server (10.10.10.1:8220)                  │    │
│  │    Real Windows Event Logs → (same data streams as above)          │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  DATA SOURCES              COLLECTION          ECS DATA STREAM   PURPOSE   │
│  ─────────────────         ──────────────      ───────────────── ────────  │
│  Windows VMs (AD/WSUS) ──► Elastic Agent   ──► logs-windows.*   Live Win  │
│                                            ──► logs-system.*    Live Win  │
│  Squid proxy logs      ──► Elastic Agent   ──► logs-squid.log-default     │
│  Nginx web server logs ──► Elastic Agent   ──► logs-nginx.access-default  │
│  Syslog (net devices)  ──► Logstash :514   ──► syslog-*         Raw syslog│
│  ALL data streams ─────────────────────────►  Elastic Security            │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Tiers — Real vs Simulated vs Live

### Tier 2 — Real production VMs (AD/WSUS)

AD-CNAS-KOLEA and WSUS-CNAS-KOLEA are **real Windows Server 2025 VMs** running in VirtualBox. Elastic Agent is installed natively on each VM and enrolls to Fleet Server via the Host-Only network adapter. These generate real Windows Event Logs — real authentication events, real process creation, real security logs.

**Why this matters:** Detection rules written against the lab environment will fire on these VMs immediately — same EventIDs, same ECS fields, different timestamps.

### Tier 3 — Real Docker services (Proxy & WebSrv)

PROXY-CNAS-KOLEA runs real **Squid** and WEBSRV-CNAS-KOLEA runs real **Nginx** — both Docker containers generating actual access logs instead of telemetry scripts. Elastic Agent reads those logs and ships them to Fleet.

### Tier 4 — Syslog via Logstash

Logstash listens on UDP/TCP port 514 to receive syslog from network devices. This is the only remaining Logstash pipeline. No static file ingestion (EVTX, CICIDS, Faker) is active.

---

## 3. Elastic Agent vs Logstash — Who Does What

### What Elastic Agent does in this lab

| Source | Index Pattern |
|--------|---------------|
| Windows Security logs (AD/WSUS) | `logs-system.security-default` |
| Windows Sysmon (AD/WSUS) | `logs-windows.sysmon_operational-default` |
| Windows PowerShell (AD/WSUS) | `logs-windows.powershell-default` + `logs-windows.powershell_operational-default` |
| Windows Defender (AD/WSUS) | `logs-windows.windows_defender-default` |
| Squid proxy logs | `logs-squid.log-default` |
| Nginx web server logs | `logs-nginx.access-default` *(pending fix — see Section 22)* |

### What Logstash does in this lab

| Source | Why Logstash | Index |
|--------|-------------|-------|
| Syslog UDP/TCP :514 | Network device syslog receiver | `syslog-*` |

> **Note:** The EVTX-ATTACK-SAMPLES, CICIDS 2017, CICIDS Web Attacks, and Faker authentication pipeline has been fully removed. All Windows log collection is handled exclusively by Elastic Agent.

---

## 4. ECS Normalization — Core Requirement

Every event ingested into Elasticsearch **must** use ECS field names. This is enforced in the Logstash filter section and in how Elastic Agent integrations emit data natively.

**Why this matters:** A detection rule written as `event.code: "4769" and event.outcome: "failure"` works identically against:
- Live events from a Windows VM via Elastic Agent (production)
- Real Squid/Nginx logs from Docker containers

### ECS field mappings used in this lab

| Raw field (source) | ECS field | Example |
|--------------------|-----------|---------|
| `EventID` / `event_id` | `event.code` | `"4625"` |
| `TimeCreated` | `@timestamp` | `"2024-01-15T10:30:00Z"` |
| `SourceAddress` / `src_ip` | `source.ip` | `"192.168.1.100"` |
| `DestAddress` / `dst_ip` | `destination.ip` | `"10.0.0.1"` |
| `SourcePort` | `source.port` | `54321` |
| `DestPort` | `destination.port` | `443` |
| `Username` / `user` | `user.name` | `"jdoe"` |
| `Domain` | `user.domain` | `"KOLEA"` |
| `ComputerName` / `hostname` | `host.name` | `"AD-CNAS-KOLEA"` |
| `ProcessName` | `process.name` | `"lsass.exe"` |
| `ProcessId` | `process.pid` | `1234` |
| `AttackTactic` | `threat.tactic.name` | `"Credential Access"` |
| `AttackTechnique` | `threat.technique.name` | `"Brute Force"` |
| `LogonType` | `winlog.logon.type` | `"Network"` |

---

## 5. Dataset Mapping per CNAS Source

### 5.1 AD-CNAS-KOLEA → Live Windows VM

AD-CNAS-KOLEA is a **real Windows Server 2025 VM** running in VirtualBox. Elastic Agent ships live Windows Event Logs directly to Fleet Server.

| EventID | Attack | MITRE | Detection logic |
|---------|--------|-------|-----------------|
| 4625 | Failed login | T1110 | High volume from one source IP |
| 4740 | Account lockout | T1110.001 | Any 4740 event |
| 4769 | Kerberos TGS request | T1558.003 | TicketEncryptionType=0x17 (RC4) |
| 4662 | Directory service access | T1003.006 DCSync | Specific ObjectType GUIDs |
| 4728 | Member added to group | T1098 | Group = "Domain Admins" |
| 4672 | Special privileges on logon | T1078 | Non-admin user |
| 4648 | Explicit credential use | T1550 | Unexpected host |

### 5.2 PROXY-CNAS-KOLEA → Real Squid

Real Squid container generating actual access.log entries, shipped by `agent-proxy` to `logs-squid.log-default`.

### 5.3 WEBSRV-CNAS-KOLEA → Real Nginx

Real Nginx container generating access.log entries, shipped by `agent-websrv` to `logs-nginx.access-default`. *(Pending log format fix — see Section 22.)*

---

## 6. Current Deployed State

| Component | Status | Notes |
|-----------|--------|-------|
| Elasticsearch (es01) | ✅ Running | Security enabled, port 9200 |
| Kibana (kibana01) | ✅ Running | Port 5601 |
| Logstash (logstash01) | ✅ Running | Syslog only |
| Fleet Server | ✅ Running | Port 8220 |
| proxy-cnas (Squid) | ✅ Running | Real logs, port 3128 |
| websrv-cnas (Nginx) | ✅ Running | Real logs, port 80 |
| agent-proxy | ✅ Enrolled | Ships Squid logs to Fleet |
| agent-websrv | ✅ Enrolled | Ships Nginx logs to Fleet |
| AD-CNAS-KOLEA | ✅ Windows VM | Elastic Agent installed natively |
| WSUS-CNAS-KOLEA | ✅ Windows VM | Elastic Agent installed natively |

| Data Stream | Status | Notes |
|-------------|--------|-------|
| `logs-windows.sysmon_operational-default` | ✅ Active | 10,000+ docs, AD live |
| `logs-system.security-default` | ✅ Active | 8,044 docs, AD live |
| `logs-system.application-default` | ✅ Active | AD/WSUS |
| `logs-system.system-default` | ✅ Active | AD/WSUS |
| `logs-windows.powershell-default` | ✅ Active | AD/WSUS |
| `logs-windows.powershell_operational-default` | ✅ Active | AD/WSUS |
| `logs-windows.windows_defender-default` | ✅ Active | AD/WSUS |
| `logs-squid.log-default` | ✅ Active | Proxy live |
| `logs-nginx.access-default` | ⚠️ Pending | Volume mounted, log format fix needed |
| `logs-system.auth-default` | ❌ Not applicable | No rsyslog in minimal containers |
| `logs-system.syslog-default` | ❌ Not applicable | Same reason |
| `sysmon-*`, `network-cnas-*`, `proxy-cnas-*`, `auth-cnas-*` | ❌ Removed | ETTX pipeline deleted |

> **All data streams show YELLOW status** — expected on a single-node Elasticsearch cluster (no replicas can be assigned). This is not an error.

> **Data streams are NOT plain indices.** `logs-windows.sysmon_operational-default` will not appear under Index Management → Indices. Find it at: Stack Management → Index Management → **Data Streams** tab.

---

## 7. Prerequisites

| Requirement | Minimum |
|-------------|---------|
| Docker Desktop (Windows) | 4.x — WSL2 backend required |
| RAM for Docker | 8 GB (ELK needs ~4–5 GB alone) |
| RAM for VMs | 4 GB additional (2 GB per VM) |
| Disk | 50 GB free |
| VirtualBox | 7.x |
| Windows Server 2025 ISO | For AD and WSUS VMs |
| Git Bash (Windows) | Any |
| Python 3 | 3.9+ |
| `curl` | Included in Git Bash |

> **VirtualBox Host-Only network prerequisite:** Before starting any VMs, verify that a Host-Only network at `10.10.10.1 / 255.255.255.0` exists in VirtualBox (File → Tools → Network Manager → Host-only Networks). Create it if missing. The VMs will not be able to reach Docker without this adapter.

### Windows / Git Bash — mandatory setup

```bash
echo 'export MSYS_NO_PATHCONV=1' >> ~/.bashrc
source ~/.bashrc
```

> **Never use `/tmp` as a Docker volume target on Windows.** Use `/usr/share/logstash/ettx-input` and `/var/log/<service>` instead.

---

## 8. Repository Layout

```
ELK/
├── elk_stack/
│   ├── docker-compose.yml
│   ├── docker-compose.cnas.yml
│   ├── .env                               # ← NEVER commit
│   ├── logstash/
│   │   ├── pipeline/ettx-attacks.conf     # Syslog only
│   │   └── pipelines.yml
```

---

## 9. Phase 1 — Core ELK Stack

### `docker-compose.yml`

```yaml
version: "3.8"

services:

  es01:
    image: docker.elastic.co/elasticsearch/elasticsearch-wolfi:9.1.3
    container_name: es01
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=false
      - ELASTIC_PASSWORD=changeme
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
    ports:
      - "0.0.0.0:9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data
    networks:
      - elastic-net
    healthcheck:
      test: ["CMD-SHELL", "curl -s -u elastic:changeme http://localhost:9200/_cluster/health | grep -q 'status'"]
      interval: 15s
      timeout: 10s
      retries: 10

  kibana01:
    image: docker.elastic.co/kibana/kibana-wolfi:9.1.3
    container_name: kibana01
    ports:
      - "0.0.0.0:5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://es01:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=changeme
      - XPACK_FLEET_ENABLED=true
      - XPACK_FLEET_AGENTS_ELASTICSEARCH_HOSTS=["http://es01:9200"]
      - XPACK_FLEET_AGENTS_FLEET_SERVER_HOSTS=["http://fleet-server:8220"]
      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=a7f3c1d2e4b5a6f7c8d9e0a1b2c3d4e5
      - XPACK_REPORTING_ENCRYPTIONKEY=b8e4d1c2f3a7b6c5d4e3f2a1b0c9d8e7
      - XPACK_SECURITY_ENCRYPTIONKEY=c9f5e2d3a4b7c6d5e4f3a2b1c0d9e8f7
    depends_on:
      es01:
        condition: service_healthy
    networks:
      - elastic-net

  logstash01:
    image: docker.elastic.co/logstash/logstash-wolfi:9.1.3
    container_name: logstash01
    ports:
      - "514:514/tcp"
      - "514:514/udp"
      - "5000:5000"
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline:ro
      - ./logstash/pipelines.yml:/usr/share/logstash/config/pipelines.yml:ro
    environment:
      - "LS_JAVA_OPTS=-Xms512m -Xmx512m"
    depends_on:
      es01:
        condition: service_healthy
    networks:
      - elastic-net

  fleet-server:
    image: docker.elastic.co/elastic-agent/elastic-agent:9.1.3
    container_name: fleet-server
    hostname: fleet-server
    restart: unless-stopped
    user: root
    environment:
      - FLEET_SERVER_ENABLE=1
      - FLEET_SERVER_ELASTICSEARCH_HOST=http://es01:9200
      - FLEET_SERVER_SERVICE_TOKEN=${FLEET_SERVICE_TOKEN}
      - FLEET_SERVER_INSECURE_HTTP=1
      - FLEET_SERVER_ELASTICSEARCH_INSECURE=1
      - FLEET_SERVER_HOST=0.0.0.0
      - FLEET_SERVER_PORT=8220
      - KIBANA_HOST=http://kibana01:5601
      - KIBANA_FLEET_SETUP=1
    volumes:
      - fleet-server-state:/usr/share/elastic-agent/state
    ports:
      - "0.0.0.0:8220:8220"
    depends_on:
      es01:
        condition: service_healthy
    networks:
      - elastic-net

  # AD-CNAS and WSUS-CNAS are real Windows Server 2025 VMs
  # Elastic Agent runs natively on them — no containers here

  agent-proxy:
    image: docker.elastic.co/elastic-agent/elastic-agent:9.1.3
    container_name: agent-proxy
    hostname: PROXY-CNAS-KOLEA
    restart: unless-stopped
    user: root
    environment:
      - FLEET_ENROLL=1
      - FLEET_URL=http://fleet-server:8220
      - FLEET_ENROLLMENT_TOKEN=${PROXY_ENROLLMENT_TOKEN}
      - FLEET_INSECURE=true
    volumes:
      - proxy-logs:/var/log/squid:ro
    depends_on:
      - fleet-server
    networks:
      - elastic-net

  agent-websrv:
    image: docker.elastic.co/elastic-agent/elastic-agent:9.1.3
    container_name: agent-websrv
    hostname: WEBSRV-CNAS-KOLEA
    restart: unless-stopped
    user: root
    environment:
      - FLEET_ENROLL=1
      - FLEET_URL=http://fleet-server:8220
      - FLEET_ENROLLMENT_TOKEN=${WEBSRV_ENROLLMENT_TOKEN}
      - FLEET_INSECURE=true
    volumes:
      - websrv-logs:/var/log/nginx:ro
    depends_on:
      - fleet-server
    networks:
      - elastic-net

volumes:
  esdata:
    driver: local
  fleet-server-state:
    driver: local
  proxy-logs:
    driver: local
  websrv-logs:
    driver: local

networks:
  elastic-net:
    driver: bridge
```

### `docker-compose.cnas.yml`

```yaml
version: "3.8"

services:

  # AD-CNAS and WSUS-CNAS removed — replaced by real Windows Server 2025 VMs

  proxy-cnas:
    image: ubuntu/squid:latest
    container_name: PROXY-CNAS-KOLEA
    hostname: PROXY-CNAS-KOLEA
    restart: unless-stopped
    ports:
      - "3128:3128"
    volumes:
      - proxy-logs:/var/log/squid        # real Squid access.log
    networks:
      - cnas-net

  websrv-cnas:
    image: nginx:latest
    container_name: WEBSRV-CNAS-KOLEA
    hostname: WEBSRV-CNAS-KOLEA
    restart: unless-stopped
    ports:
      - "80:80"
    volumes:
      - websrv-logs:/var/log/nginx       # real Nginx access.log + error.log
    networks:
      - cnas-net

volumes:
  proxy-logs:
    driver: local
  websrv-logs:
    driver: local

networks:
  cnas-net:
    external: true
    name: elk_stack_elastic-net
```

### Start and validate

```bash
cd ~/ELK/elk_stack
docker compose up -d es01 kibana01 logstash01

until curl -s -u elastic:changeme http://localhost:9200/_cluster/health \
  | grep -qE '"status":"green"|"status":"yellow"'; do
  echo "Waiting for Elasticsearch..."; sleep 5
done
echo "✅ Elasticsearch ready"

until curl -s http://localhost:5601/api/status \
  | python3 -c "import sys,json; s=json.load(sys.stdin); exit(0 if s['status']['overall']['level']=='available' else 1)" 2>/dev/null; do
  echo "Waiting for Kibana..."; sleep 5
done
echo "✅ Kibana ready"
```

---

## 10. Phase 2 — Fleet Server & Agent Enrollment

### Generate Fleet Server service token

```bash
curl -s -u elastic:changeme \
  -X POST "http://localhost:9200/_security/service/elastic/fleet-server/credential/token/fleet-token-1" \
  -H "Content-Type: application/json" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['token']['value'])"
```

Paste output into `elk_stack/.env` as `FLEET_SERVICE_TOKEN=`.

### Start Fleet Server

```bash
docker compose up -d fleet-server
docker logs fleet-server 2>&1 | grep -E "started|error" | tail -5
```

### Create Agent Policies in Kibana

`http://localhost:5601` → **Management** → **Fleet** → **Agent Policies** → **Create agent policy**

| Policy name | System integration | Custom log paths |
|-------------|-------------------|------------------|
| `AD-CNAS Policy` | ✅ enabled | Windows Event Log integration |
| `WSUS-CNAS Policy` | ✅ enabled | Windows Event Log integration |
| `PROXY-CNAS Policy` | ✅ enabled | `/var/log/squid/access.log` |
| `WEBSRV-CNAS Policy` | ✅ enabled | `/var/log/nginx/access.log` |

### Start Docker agents (proxy + websrv)

```bash
docker compose up -d agent-proxy agent-websrv
```

### Enroll Windows VMs — see Phase 6

---

## 11. Phase 3 — Logstash Multi-Pipeline

### `logstash/pipelines.yml`

```yaml
- pipeline.id: main
  path.config: "/usr/share/logstash/pipeline/ettx-attacks.conf"
  pipeline.workers: 1
```

### `logstash/pipeline/ettx-attacks.conf`

The pipeline now handles **syslog only**. All EVTX, CICIDS, and Faker blocks have been removed.

```ruby
input {
  udp { port => 514; tags => ["syslog-udp"] }
  tcp { port => 514; tags => ["syslog-tcp"] }
}
output {
  elasticsearch {
    hosts => ["http://es01:9200"]
    user => "elastic"
    password => "changeme"
    index => "syslog-%{+YYYY.MM.dd}"
    manage_template => false
  }
}
```

---

## 12. Phase 4 — Dataset Preparation

> **Note:** Static dataset ingestion (EVTX-ATTACK-SAMPLES, CICIDS, Faker) has been removed from this lab. The lab is now fully live agent-based. This section is retained for reference only.

```bash
mkdir -p ~/ELK/elk_stack/logstash/datasets/cicids2017
mkdir -p ~/ELK/elk_stack/logstash/datasets/cicids-webattacks
mkdir -p ~/ELK/elk_stack/logstash/datasets/auth-cnas
mkdir -p ~/ELK/elk_stack/logstash/ettx-input
```

---

## 13. Phase 5 — CNAS Containers (Proxy & WebSrv)

AD and WSUS are now real Windows VMs. Only Proxy and WebSrv remain as Docker containers, using real service images instead of telemetry scripts.

```bash
cd ~/ELK/elk_stack
docker compose -f docker-compose.cnas.yml up -d
docker compose up -d agent-proxy agent-websrv
```

Verify real logs are being generated:
```bash
docker exec PROXY-CNAS-KOLEA tail -f /var/log/squid/access.log
docker exec WEBSRV-CNAS-KOLEA tail -f /var/log/nginx/access.log
```

### Nginx log format fix (required for Elastic integration to parse correctly)

The Elastic Nginx integration expects the `combined` log format. Change `nginx.conf`:

```nginx
# Change from:
access_log /var/log/nginx/access.log main;
# To:
access_log /var/log/nginx/access.log combined;
```

Then reload:
```bash
docker exec -it WEBSRV-CNAS-KOLEA nginx -s reload
```

### Volume architecture

```
agent-websrv  ──► mounts volume: elk_stack_websrv-logs → /var/log/nginx  (read-only)
WEBSRV-CNAS-KOLEA ──► writes to same volume → /var/log/nginx             (read-write)
```

Verify:
```bash
docker inspect agent-websrv | grep -A 20 "Mounts"
```

### Why auth.log / syslog don't exist in containers

Minimal Docker images (`nginx:latest`, `ubuntu/squid`) have no init system and no rsyslog. `systemctl` and `/etc/init.d/rsyslog` do not exist inside these containers. As a result, `logs-system.auth-default` and `logs-system.syslog-default` will never be created for containerised services. This is expected behaviour and not an error.

---

## 14. Phase 6 — Windows VMs Setup (AD & WSUS)

### 14.1 Create VMs in VirtualBox

| Setting | Value |
|---------|-------|
| OS | Windows Server 2025 |
| RAM | 2048 MB minimum |
| CPU | 2 cores |
| Network Adapter 1 | NAT (internet access) |
| Network Adapter 2 | Host-Only Adapter → `VirtualBox Host-Only Ethernet Adapter` (10.10.10.1) |

> **Adapter 2 is mandatory.** NAT mode (Adapter 1) cannot reach Docker ports due to WSL2 isolation. The Host-Only adapter bypasses this entirely.

### 14.2 Configure hosts file on each Windows VM

After booting, open PowerShell as Administrator on each VM:

```powershell
# Clean any old entries
$hosts = Get-Content "C:\Windows\System32\drivers\etc\hosts"
$hosts = $hosts | Where-Object { $_ -notmatch "es01|fleet-server" }
$hosts | Set-Content "C:\Windows\System32\drivers\etc\hosts"

# Add entries pointing to Host-Only adapter IP (never changes)
Add-Content "C:\Windows\System32\drivers\etc\hosts" "10.10.10.1`tes01"
Add-Content "C:\Windows\System32\drivers\etc\hosts" "10.10.10.1`tfleet-server"
```

Verify connectivity:
```powershell
Test-NetConnection -ComputerName es01 -Port 9200
Test-NetConnection -ComputerName fleet-server -Port 8220
# TcpTestSucceeded : True ✅
```

### 14.3 Install Elastic Agent on each Windows VM

Download the agent from Kibana → Fleet → Add Agent, or use PowerShell:

```powershell
# Run as Administrator
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.1.3-windows-x86_64.zip" -OutFile "elastic-agent.zip"
Expand-Archive -Path "elastic-agent.zip" -DestinationPath "C:\elastic-agent"
cd "C:\elastic-agent\elastic-agent-9.1.3-windows-x86_64"

# Enroll to fleet (replace token with AD or WSUS enrollment token from Kibana)
.\elastic-agent.exe install `
  --fleet-url=http://fleet-server:8220 `
  --enrollment-token=YOUR_ENROLLMENT_TOKEN `
  --insecure
```

### 14.4 Add Windows Event Log integration

In Kibana Fleet → AD-CNAS Policy → Add integration → **Windows**:
- ✅ Security Event Log
- ✅ System Event Log
- ✅ PowerShell Operational
- ✅ Sysmon (if Sysmon is installed)

**Known issue — Windows Server 2025 filter warning:**

```
skipping query filters for Windows Server 2025 due to known issue with Event Log API and forwarded events
```

This is a confirmed WS2025 API limitation — event ID filters are silently ignored. **Fix:** In Fleet → Windows Integration → Edit, **remove all event ID filters** from every channel and set each channel to collect all events. This makes the unfiltered behaviour explicit.

### 14.5 Audit policy setup (mandatory for complete Security logs)

Run on each Windows VM as Administrator:

```powershell
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable
```

### 14.6 PowerShell logging setup (required for PowerShell detection rules to fire)

```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
```

---

## 15. Phase 7 — VirtualBox Networking for VM→Docker Connectivity

### Why 10.0.2.2 (NAT) does NOT work

Docker Desktop runs inside WSL2, which is a separate Hyper-V VM. The Hyper-V WSL firewall (`vEthernet (WSL (Hyper-V firewall))`) intercepts traffic before it reaches Docker's listeners. VirtualBox NAT's `10.0.2.2` gateway goes through this layer and gets blocked — even though `netstat` shows `0.0.0.0:9200 LISTENING`.

```
VM (10.0.2.15)
  → 10.0.2.2 (VirtualBox NAT gateway)
  → Windows network stack
  → Hyper-V WSL firewall ← BLOCKS HERE ❌
  → WSL2
  → Docker
```

### Why 10.10.10.1 (Host-Only) WORKS

The VirtualBox Host-Only adapter (`10.10.10.1`) is a native Windows network interface. Docker's `0.0.0.0` binding includes it. Traffic bypasses the WSL2 Hyper-V firewall entirely.

```
VM (10.10.10.X)
  → 10.10.10.1 (Host-Only adapter — native Windows interface)
  → Docker 0.0.0.0:9200 binding ← CONNECTS ✅
```

### Setup (one time)

In VirtualBox on host PC:
```
File → Tools → Network Manager → Host-only Networks
  Verify: 10.10.10.1 / 255.255.255.0 exists
  If not: Create → set IPv4 to 10.10.10.1
```

Each VM needs **Adapter 2 → Host-only Adapter → VirtualBox Host-Only Ethernet Adapter**.
See Phase 6 for full VM setup.

### Verify on host PC

```powershell
# Confirm host-only adapter IP
ipconfig | findstr "10.10.10"
# Should show: 10.10.10.1

# Confirm Docker ports are listening
netstat -an | findstr "9200"
netstat -an | findstr "8220"
# Must show: 0.0.0.0:9200 and 0.0.0.0:8220
```

---

## 16. Phase 8 — Shared Volume Wiring

```bash
# Pre-create shared volumes
docker volume create proxy-logs
docker volume create websrv-logs

# Verify agents can read the logs
docker exec agent-proxy ls -lh /var/log/squid/
docker exec agent-websrv ls -lh /var/log/nginx/
```

---

## 17. Phase 9 — Ingest & Verify

### Check all data streams

```bash
curl -s -u elastic:changeme \
  "http://localhost:9200/_cat/indices/logs-windows.*,logs-system.*,logs-squid.*,logs-nginx.*,syslog-*?v&h=index,docs.count&s=index"
```

### Data stream health check

```json
GET /_data_stream/logs-windows.sysmon_operational-default/_stats
GET /_data_stream/logs-system.security-default/_stats
GET /_data_stream/logs-squid.log-default/_stats
GET /_data_stream/logs-nginx.access-default/_stats
GET /_cat/indices/logs-*?v&s=index&h=index,docs.count,store.size
```

### Fleet agent health check

```bash
docker logs agent-websrv --tail 30 | grep -E "error|warn|skip"
docker logs agent-proxy --tail 30 | grep -E "error|warn|skip"
```

---

## 18. Kibana Data Views

| Data View | Index Pattern |
|-----------|---------------|
| **Windows — All** | `logs-windows.*,logs-system.security-default,logs-system.application-default,logs-system.system-default` |
| **Linux — All** | `logs-squid.log-default,logs-nginx.access-default,logs-system.auth-default` |
| **Fleet Telemetry** | `metrics-*,logs-elastic_agent*` |
| **Raw Syslog** | `syslog-*` |
| **All Security** | `logs-*` |

### Key KQL queries

```kql
# Scope to one machine
host.name: "AD-CNAS-KOLEA"

# Authentication failures across all sources
event.category: "authentication" and event.outcome: "failure"

# All MITRE-labeled events
threat.tactic.name: *

# Kerberoasting indicator
event.code: "4769"

# DCSync indicator
event.code: "4662"

# Live Windows VM events only
event.module: "windows" or event.dataset: "windows.security"
```

---

## 19. Phase 10 — Elastic Security & Detection Rules

### Phase 1 — Prerequisites

Before enabling any rules, verify that data is actually flowing into the expected data streams. Rules firing against empty indices produce no alerts and give false confidence.

**Enable Elastic Security:**
Kibana → **Security** (left sidebar) → **Get started**.

**Load all prebuilt rules:**
```
Security → Rules → Detection Rules → Add Elastic rules
```

**Data stream health check — run this first:**

```json
GET /_data_stream/logs-windows.sysmon_operational-default/_stats
GET /_data_stream/logs-system.security-default/_stats
GET /_data_stream/logs-squid.log-default/_stats
GET /_data_stream/logs-nginx.access-default/_stats
GET /_cat/indices/logs-*?v&s=index&h=index,docs.count,store.size
```

**Fleet agent health check:**
```bash
docker logs agent-websrv --tail 30 | grep -E "error|warn|skip"
docker logs agent-proxy --tail 30 | grep -E "error|warn|skip"
```

Only proceed to Phase 2 once all expected data streams show non-zero doc counts and agents report healthy.

---

### Phase 2 — Production Rule Enablement

Enable rules in this exact priority order.

---

### 🔴 Tier 1 — Enable First (Critical Severity)

```
Kibana → Security → Rules → Detection Rules → Filter: Severity = Critical → Enable All
```

#### Windows (AD + WSUS)

| Rule Name | Why Critical |
|-----------|-------------|
| **Suspicious Lsass Process Access** | Core credential theft detection |
| **LSASS Memory Dump Handle Access** | Mimikatz / procdump detection |
| **Potential Credential Access via Windows Utilities** | NTDS / VSS abuse |
| **Windows Event Log Cleared** | Attacker covering tracks |
| **Disable Windows Event and Security Logs Using Built-in Tools** | Attacker killing visibility |
| **A scheduled task was created** | Most common persistence method |
| **Persistence via WMI Event Subscription** | Stealthy persistence |
| **Potential Shadow Credentials added to AD Object** | AD-specific backdoor |
| **Windows Service Installed via an Unusual Client** | Malicious service install |
| **Potential PowerShell HackTool Script by Function Names** | Mimikatz / BloodHound in PS |
| **Suspicious Powershell Script** | Obfuscated PS execution |
| **Network Connection via Certutil** | Living-off-the-land download |

#### Linux (Proxy + Web)

| Rule Name | Why Critical |
|-----------|-------------|
| **Web Shell Detection: Script Process Child of Common Web Process** | Active compromise of web server |
| **Unusual Web Server Command Execution** | RCE on web server |
| **Suspicious Child Execution via Web Server** | Web process spawning shell |
| **Linux Restricted Shell Breakout via Linux Binaries** | Container / shell escape |
| **Systemd Service Created** | Linux persistence |
| **Potential Data Exfiltration Through Curl** | Data theft in progress |

---

### 🟠 Tier 2 — Enable Second (High Severity)

```
Kibana → Security → Rules → Detection Rules → Filter: Severity = High
→ Enable All that match Windows, Linux, or Active Directory tags
```

Key rules to confirm are active:

| Rule Name | Machine |
|-----------|---------|
| **AdFind Command Activity** | AD |
| **Searching for Saved Credentials via VaultCmd** | AD + WSUS |
| **Wireless Credential Dumping using Netsh Command** | AD + WSUS |
| **Startup Folder Persistence via Unsigned Process** | AD + WSUS |
| **Uncommon Registry Persistence Change** | AD + WSUS |
| **PowerShell Suspicious Discovery Related Windows API Functions** | AD + WSUS |
| **Windows Subsystem for Linux Enabled via Dism Utility** | WSUS |
| **IIS HTTP Logging Disabled** | WSUS |
| **Cron Job Created or Modified** | Proxy + Web |
| **Python Site or User Customize File Creation** | Web |
| **APT Package Manager Configuration File Creation** | Proxy + Web |
| **Unusual Sudo Activity** | Proxy + Web |
| **File Deletion via Shred** | Proxy + Web |
| **DNS Tunneling** | Proxy |
| **Connection to Commonly Abused Web Services** | Proxy |

---

### 🟡 Tier 3 — Enable Last (Medium Severity)

```
Kibana → Security → Rules → Detection Rules → Filter: Severity = Medium
→ Review each rule individually before enabling
```

Only enable what makes sense for your environment. **Skip rules tagged AWS, GCP, Kubernetes, or Office365** — they will only generate noise and false positives in this lab.

---

### Index pattern note

Do NOT create aliases pointing `winlogbeat-*` to your data streams. This causes `verification_exception` on rules querying `process.name`. If a prebuilt rule needs a different index pattern, **duplicate the rule** and add your index pattern to the copy.

---

## 20. Migration: Current State → Target Architecture

### Step A — Enable Elastic Security detection rules

See Phase 10. No pipeline changes needed.

---

## 21. Real Production Deployment

The architecture is identical to this lab. Only the data source changes.

### On a real Windows machine

```powershell
.\elastic-agent.exe install `
  --fleet-url=https://YOUR_FLEET_SERVER:8220 `
  --enrollment-token=YOUR_TOKEN `
  --insecure
```

Add the **Windows** integration in Fleet to collect Security, System, PowerShell, and Sysmon event logs.

### On a real Linux machine

```bash
sudo ./elastic-agent install \
  --fleet-url=http://YOUR_FLEET_SERVER:8220 \
  --enrollment-token=YOUR_TOKEN \
  --insecure
```

Add **System** + **Nginx** or **Apache** integrations.

### Detection rules transfer automatically

Rules written against this lab fire on live machines immediately — same EventIDs, same ECS fields, zero reconfiguration.

---

## 22. Known Issues & Fixes

### VirtualBox NAT + Docker WSL2 — ports unreachable from VMs

**Cause:** Docker runs inside WSL2 (Hyper-V). The Hyper-V WSL firewall blocks TCP from VirtualBox NAT's `10.0.2.2` even though `0.0.0.0:9200` shows as LISTENING.

**Fix:** Add a second network adapter (Host-Only) to each VM. Use `10.10.10.1` in the hosts file. See Phase 7.

**Do NOT use:**
- `networkingMode=mirrored` in `.wslconfig` — breaks other networking
- `netsh portproxy` — unreliable with VirtualBox NAT
- Static Docker IPs (`172.20.x.x`) — internal only, not reachable from outside Docker

### `networkingMode=mirrored` in `.wslconfig` breaks networking

**Cause:** Setting `networkingMode=mirrored` in `%USERPROFILE%\.wslconfig` is sometimes suggested as a fix for WSL2 port exposure, but it interferes with Docker Desktop's internal networking and breaks container-to-container and host-to-container connectivity.

**Fix:** Remove the line, then restart WSL2 and Docker:
```powershell
# Edit %USERPROFILE%\.wslconfig — remove or comment out networkingMode=mirrored
wsl --shutdown
# Then restart Docker Desktop
```

### `netsh portproxy` is unreliable with VirtualBox NAT

**Cause:** Port proxying via `netsh interface portproxy` routes traffic through the Windows NAT layer, which still hits the WSL2 Hyper-V firewall before reaching Docker. Connections appear to be forwarded but drop silently.

**Fix:** Do not use `netsh portproxy` for this setup. Use the VirtualBox Host-Only adapter (`10.10.10.1`) as described in Phase 7.

### `0.0.0.0` binding in `docker ps` is misleading on WSL2

**Cause:** `docker ps` shows `0.0.0.0:9200->9200/tcp`, which implies all-interface binding. On WSL2 this is true within the WSL2 virtual network, but the Hyper-V WSL firewall still blocks inbound TCP from external sources (including VirtualBox NAT). The port is genuinely reachable only from `127.0.0.1` on the Windows host — not from VMs.

**The only correct fix** is the VirtualBox Host-Only adapter — a native Windows interface that Docker's `0.0.0.0` binding covers without Hyper-V firewall interference.

### Data streams are YELLOW

Single-node cluster — replicas cannot be assigned. Not an error, ignore it.

### `logs-system.auth-default` never created

Minimal Docker containers have no rsyslog or init system. Expected behaviour. Not fixable without rebuilding container images with rsyslog installed.

### Nginx logs not appearing despite volume being mounted

**Root cause:** Nginx is using the `main` log format; the Elastic integration expects `combined`.

**Fix:** Change `nginx.conf`:
```nginx
access_log /var/log/nginx/access.log combined;
```
Then reload: `docker exec -it WEBSRV-CNAS-KOLEA nginx -s reload`

### Windows Server 2025 filter warning

```
skipping query filters for Windows Server 2025 due to known issue with Event Log API and forwarded events
```

This is not data loss — logs are still collected unfiltered. **Fix:** Remove all event ID filters in Fleet → Windows integration. See Section 14.4.

### Data stream vs plain index confusion

`logs-windows.sysmon_operational-default` is a **data stream**, not a plain index. It will not appear in Index Management → Indices tab. Find it at: Stack Management → Index Management → **Data Streams** tab.

### Alias approach breaks other rules

Do NOT create aliases pointing `winlogbeat-*` to your data streams. This causes `verification_exception` on rules querying `process.name`. If a prebuilt rule needs a different index pattern → **duplicate the rule** and add your index pattern to the copy.

### ETTX pipeline caused duplicate / misrouted data

**Root cause:** Output routing by `event.module` into `logs-system.security-default` conflicted with agent-written data stream mappings.

**Fix:** Delete the ETTX pipeline entirely. Use Elastic Agent for all Windows log collection.

Cleanup commands:
```bash
systemctl stop logstash
rm /etc/logstash/conf.d/ettx-attacks.conf
rm /usr/share/logstash/data/sincedb-ettx
rm /usr/share/logstash/data/sincedb-ad
rm /usr/share/logstash/data/sincedb-wsus
rm /usr/share/logstash/data/sincedb-proxy
rm /usr/share/logstash/data/sincedb-websrv
rm /usr/share/logstash/data/sincedb-auth
systemctl start logstash
```

```json
DELETE /_data_stream/logs-windows.sysmon_operational-default
DELETE /_data_stream/logs-system.security-default
DELETE /logs-windows.sysmon_operational
```

### `_jsonparsefailure` in Logstash

**Cause:** `codec => "json"` reads one line at a time. Heredoc or pretty-printed JSON creates multi-line output.

**Fix:** Single `echo` per event. Never use heredoc in telemetry scripts.

### `grep -c || echo "0"` inserts newline into JSON

**Fix:** Use `|| true` instead of `|| echo "0"`.

### ES 9.x blocks wildcard index deletion

**Fix:** Temporarily disable `action.destructive_requires_name`, delete, re-enable.

### Git Bash path conversion on Windows

**Fix:** `export MSYS_NO_PATHCONV=1` in `~/.bashrc`.

---

## 23. Troubleshooting Reference

### All containers at a glance

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### Host PC — verify Docker port bindings (run on Windows host, not in WSL)

```powershell
# Confirm Docker is actually binding to all interfaces
netstat -ano | findstr "9200"
netstat -ano | findstr "8220"
# Both must show: 0.0.0.0:9200 and 0.0.0.0:8220

# Find VirtualBox Host-Only adapter IP
ipconfig /all
# Look for "VirtualBox Host-Only Ethernet Adapter" — IPv4 Address must be 10.10.10.1

# Confirm ports are reachable from the host itself
Test-NetConnection -ComputerName localhost -Port 9200
Test-NetConnection -ComputerName localhost -Port 8220
# TcpTestSucceeded : True ✅
```

### Host PC — Windows Firewall rules for ELK (run as Administrator)

If VMs still cannot reach Docker after confirming the Host-Only adapter, Windows Firewall may be blocking the ports. Add rules:

```powershell
New-NetFirewallRule -DisplayName "ELK ES 9200"     -Direction Inbound -Protocol TCP -LocalPort 9200 -Action Allow
New-NetFirewallRule -DisplayName "ELK Fleet 8220"  -Direction Inbound -Protocol TCP -LocalPort 8220 -Action Allow
New-NetFirewallRule -DisplayName "ELK Kibana 5601" -Direction Inbound -Protocol TCP -LocalPort 5601 -Action Allow
```

Verify the rules were created:

```powershell
Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*ELK*" }
```

### Windows VM connectivity check

```powershell
# Run on each Windows VM
Test-NetConnection -ComputerName es01 -Port 9200
Test-NetConnection -ComputerName fleet-server -Port 8220

# Check hosts file
Get-Content "C:\Windows\System32\drivers\etc\hosts" | Select-String "es01|fleet-server"

# Check Elastic Agent service
Get-Service "Elastic Agent"
```

### Logstash event counts

```bash
curl -s http://localhost:9600/_node/stats/pipelines?pretty \
  | python3 -c "
import sys, json
for name, p in json.load(sys.stdin)['pipelines'].items():
    e = p['events']
    print(f'{name}: in={e[\"in\"]} out={e[\"out\"]} failed={e.get(\"failed\",0)}')
"
```

### Fleet agent status

```bash
curl -s -u elastic:changeme "http://localhost:5601/api/fleet/agents?perPage=20" \
  -H "kbn-xsrf: true" \
  | python3 -c "
import sys, json
for a in json.load(sys.stdin).get('list', []):
    name = a.get('local_metadata',{}).get('host',{}).get('name','?')
    print(f'  {name}: {a.get(\"status\",\"?\")}')
"
```

### Full health check

```bash
echo "=== Elasticsearch ===" && \
curl -s -u elastic:changeme "http://localhost:9200/_cluster/health" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('Status:', d['status'])" && \
echo "=== Data Streams ===" && \
curl -s -u elastic:changeme \
  "http://localhost:9200/_cat/indices/logs-windows.*,logs-system.*,logs-squid.*,logs-nginx.*,syslog-*?h=index,docs.count&s=index" && \
echo "=== Fleet Agents ===" && \
curl -s -u elastic:changeme "http://localhost:5601/api/fleet/agents?perPage=20" \
  -H "kbn-xsrf: true" \
  | python3 -c "
import sys, json
for a in json.load(sys.stdin).get('list', []):
    name = a.get('local_metadata',{}).get('host',{}).get('name','?')
    print(f'  {name}: {a.get(\"status\",\"?\")}')
"
```

---

## 24. Credentials & Quick Reference

| Service | URL | Credentials |
|---------|-----|-------------|
| Elasticsearch | `http://localhost:9200` | `elastic` / `changeme` |
| Kibana + Elastic Security | `http://localhost:5601` | `elastic` / `changeme` |
| Fleet Server | `http://localhost:8220` | — |
| Logstash monitoring | `http://localhost:9600` | — |
| Squid Proxy | `http://localhost:3128` | — |
| Nginx WebSrv | `http://localhost:80` | — |

### `.env` file template

```
FLEET_SERVICE_TOKEN=
PROXY_ENROLLMENT_TOKEN=
WEBSRV_ENROLLMENT_TOKEN=
```

> AD and WSUS agents enroll via the installer command — tokens are not needed in `.env`.

### Network reference

| Address | What it is | Used by |
|---------|-----------|---------|
| `10.10.10.1` | VirtualBox Host-Only adapter (permanent) | VMs → Docker |
| `10.0.2.2` | VirtualBox NAT gateway (❌ does not reach Docker) | — |
| `127.0.0.1` | Localhost | Host PC only |

---

*ELK Stack 9.1.3 · Elastic Agent 9.1.3 · Elastic Security · Docker Desktop Windows (WSL2) · VirtualBox 7.x · Windows Server 2025 VMs*

*⚠️ Lab environment. Default credentials are intentional. Do not expose ports externally. Rotate credentials and enable TLS before any production deployment.*
