# PFE-SIEM — ELK Stack 9.x CNAS Lab

A fully containerised SIEM lab built on **ELK Stack 9.1.3**, simulating four CNAS agency nodes (AD, WSUS, Proxy, WebSrv), ingesting real cybersecurity datasets and live logs, and running attack detection via Elastic Security — all normalized to **Elastic Common Schema (ECS)**.

> **Read this first.** This README documents:
> - the **target architecture**,
> - the **verified deployed state**,
> - and the **current gaps / issues**.
>
> For anything operational, trust the verified state first.

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

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CURRENT ARCHITECTURE                                │
│                                                                             │
│  ┌─ HOST PC ──────────────────────────────────────────────────────────┐    │
│  │                                                                     │    │
│  │  Docker (WSL2)                                                      │    │
│  │  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────┐   │    │
│  │  │   es01      │  │  kibana01    │  │     logstash01          │   │    │
│  │  │  :9200      │  │   :5601      │  │  :514/udp :514/tcp      │   │    │
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
│  │    Live Windows logs → ECS data streams                           │    │
│  │                                                                     │    │
│  │  WSUS-CNAS-KOLEA (Windows Server 2025)                             │    │
│  │    Elastic Agent → Fleet Server (10.10.10.1:8220)                  │    │
│  │    Live Windows logs → ECS data streams                           │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  DATA SOURCES              COLLECTION          ECS INDEX / STREAM   PURPOSE │
│  ─────────────────         ──────────────      ────────────────    ───────  │
│  Real Windows logs      ─►  Elastic Agent    ─► logs-windows.*     Live AD  │
│  Sysmon live stream     ─►  Elastic Agent    ─► logs-windows.sysmon_operational-default │
│  Squid / Nginx logs     ─►  Elastic Agent    ─► logs-squid.* / logs-nginx.* │
│  Historical attack data  ─►  Logstash        ─► sysmon-*           Detection │
│  Syslog UDP/TCP :514    ─►  Logstash        ─► syslog-*            Network   │
│  ALL indices/streams ───────────────────────────────────────────► Elastic Security │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Tiers — Real vs Simulated vs Live

### Tier 1 — Real historical attack data

The historical datasets in this lab are captures from real attacks on real systems. They are used to validate detection logic and threat hunting patterns.

### Tier 2 — Real production VMs

AD-CNAS-KOLEA and WSUS-CNAS-KOLEA are real Windows Server 2025 VMs. Elastic Agent is installed natively on each VM and enrolled to Fleet Server over the Host-Only network.

### Tier 3 — Real Docker services

PROXY-CNAS-KOLEA runs real Squid and WEBSRV-CNAS-KOLEA runs real Nginx. These are actual service logs, not simulated telemetry.

### Tier 4 — Static file ingestion via Logstash

Logstash is still used for syslog and any file-based ingestion paths that remain part of the lab.

---

## 3. Elastic Agent vs Logstash — Who Does What

### Elastic Agent handles

| Source | Method | Output |
|---|---|---|
| Windows Event Logs | Native integration | `logs-windows.*` |
| Sysmon live logs | Windows integration | `logs-windows.sysmon_operational-default` |
| Squid logs | Custom log integration | `logs-squid.*` |
| Nginx logs | Custom log integration | `logs-nginx.*` |
| Fleet telemetry | Built-in | `logs-elastic_agent.*`, `metrics-*` |

### Logstash handles

| Source | Why Logstash | Output |
|---|---|---|
| Syslog UDP/TCP :514 | Receiver and parser | `syslog-*` |
| Historical attack logs | Static file ingestion | `sysmon-*` |
| Other replayed files | ECS transform | custom ECS indices |

---

## 4. ECS Normalization — Core Requirement

Every event ingested into Elasticsearch must use ECS field names. This keeps detection rules consistent across historical and live data.

Examples:
- `EventID` → `event.code`
- `TimeCreated` → `@timestamp`
- `SourceAddress` → `source.ip`
- `DestAddress` → `destination.ip`
- `Username` → `user.name`
- `ComputerName` → `host.name`

---

## 5. Dataset Mapping per CNAS Source

### 5.1 AD-CNAS-KOLEA

The AD VM is a real Windows Server 2025 machine. It produces live Windows events and Sysmon data through Elastic Agent.

### 5.2 WSUS-CNAS-KOLEA

The WSUS VM is also a real Windows Server 2025 machine with native Elastic Agent enrollment.

### 5.3 PROXY-CNAS-KOLEA

Squid generates access logs that are read by the `agent-proxy` container.

### 5.4 WEBSRV-CNAS-KOLEA

Nginx generates access logs that are read by the `agent-websrv` container.

---

## 6. Current Deployed State

| Component | Status | Notes |
|---|---|---|
| Elasticsearch (es01) | ✅ Running | Security enabled |
| Kibana (kibana01) | ✅ Running | Port 5601 |
| Logstash (logstash01) | ✅ Running | Multi-pipeline |
| Fleet Server | ✅ Running | Port 8220 |
| proxy-cnas (Squid) | ✅ Running | Real logs |
| websrv-cnas (Nginx) | ✅ Running | Real logs |
| agent-proxy | ✅ Enrolled | Reads Squid logs |
| agent-websrv | ✅ Enrolled | Reads Nginx logs |
| AD-CNAS-KOLEA | ✅ Windows VM | Native Elastic Agent |
| WSUS-CNAS-KOLEA | ✅ Windows VM | Native Elastic Agent |

### Confirmed live streams / indices

| Source | State |
|---|---|
| `logs-system.security-default` | ✅ Confirmed |
| `logs-system.application-default` | ✅ Confirmed |
| `logs-system.system-default` | ✅ Confirmed |
| `logs-windows.powershell-default` | ✅ Confirmed |
| `logs-windows.powershell_operational-default` | ✅ Confirmed |
| `logs-windows.sysmon_operational-default` | ✅ Confirmed |
| `logs-windows.windows_defender-default` | ✅ Confirmed |
| `logs-squid.log-default` | ✅ Confirmed |
| `syslog-*` | ✅ Confirmed |
| `sysmon-*` | ✅ Confirmed |

### Still to verify or under diagnosis

| Source | State |
|---|---|
| `logs-nginx.access-default` | ⚠️ Verify |
| `logs-nginx.error-default` | ⚠️ Verify |
| `logs-system.auth-default` | ⚠️ Verify |
| `logs-system.syslog-default` | ⚠️ Verify |

### Important note

`logs-windows.sysmon_operational-default` is a **data stream**, not a classic index.  
It will appear in **Kibana → Stack Management → Index Management → Data Streams**.

A single-node Elasticsearch cluster may stay **YELLOW** because replica shards cannot be assigned. That is expected in this lab.

---

## 7. Prerequisites

| Requirement | Minimum |
|---|---|
| Docker Desktop (Windows) | 4.x with WSL2 |
| RAM for Docker | 8 GB |
| RAM for VMs | 4 GB additional |
| Disk | 50 GB free |
| VirtualBox | 7.x |
| Windows Server 2025 ISO | For AD and WSUS |
| Git Bash | Any |
| Python 3 | 3.9+ |
| curl | Included in Git Bash |

### Windows / Git Bash setup

```bash
echo 'export MSYS_NO_PATHCONV=1' >> ~/.bashrc
source ~/.bashrc
```

> Never use `/tmp` as a Docker volume target on Windows.

---

## 8. Repository Layout

```text
ELK/
├── elk_stack/
│   ├── docker-compose.yml
│   ├── docker-compose.cnas.yml
│   ├── .env
│   ├── logstash/
│   │   ├── pipeline/
│   │   ├── pipelines.yml
│   │   ├── ettx-input/
│   │   └── datasets/
```

---

## 9. Phase 1 — Core ELK Stack

Use your existing Docker Compose setup for Elasticsearch, Kibana, Logstash, and Fleet Server.

### Start and validate

```bash
cd ~/ELK/elk_stack
docker compose up -d es01 kibana01 logstash01

until curl -s -u elastic:changeme http://localhost:9200/_cluster/health | grep -qE '"status":"green"|"status":"yellow"'; do
  echo "Waiting for Elasticsearch..."
  sleep 5
done

until curl -s http://localhost:5601/api/status | python3 -c "import sys,json; s=json.load(sys.stdin); exit(0 if s['status']['overall']['level']=='available' else 1)" 2>/dev/null; do
  echo "Waiting for Kibana..."
  sleep 5
done
```

---

## 10. Phase 2 — Fleet Server & Agent Enrollment

Keep your existing Fleet Server service token and enrollment setup.

### Create agent policies in Kibana

| Policy name | Purpose |
|---|---|
| AD-CNAS Policy | Windows Security, System, Sysmon |
| WSUS-CNAS Policy | Windows Security, System, Sysmon |
| PROXY-CNAS Policy | Squid logs |
| WEBSRV-CNAS Policy | Nginx logs |

---

## 11. Phase 3 — Logstash Multi-Pipeline

Keep your Logstash pipeline for syslog and any remaining file-based ingestion.

The important part now is that the README should clearly say:
- live Windows logs are handled by Elastic Agent,
- data streams are used for Windows sources,
- Logstash is mainly for syslog and any file-based replay.

---

## 12. Phase 4 — Dataset Preparation

If you are now using real data, keep this section only for sources you still need.  
If EVTX and CICIDS are no longer part of your current workflow, mark them as legacy or optional.

---

## 13. Phase 5 — CNAS Containers (Proxy & WebSrv)

AD and WSUS are real Windows VMs. Proxy and WebSrv remain Docker containers.

```bash
cd ~/ELK/elk_stack
docker compose -f docker-compose.cnas.yml up -d
docker compose up -d agent-proxy agent-websrv
```

### Verify logs exist in the service containers

```bash
docker exec PROXY-CNAS-KOLEA tail -f /var/log/squid/access.log
docker exec WEBSRV-CNAS-KOLEA tail -f /var/log/nginx/access.log
```

### Verify the agent containers can read the mounted logs

```bash
docker inspect agent-proxy | grep -A 20 "Mounts"
docker inspect agent-websrv | grep -A 20 "Mounts"

docker exec -it agent-proxy ls -lh /var/log/squid/
docker exec -it agent-websrv ls -lh /var/log/nginx/

docker exec -it agent-proxy tail -5 /var/log/squid/access.log
docker exec -it agent-websrv tail -5 /var/log/nginx/access.log
```

### Important limitation

Minimal Linux containers may not include:
- `systemctl`
- `service`
- `rsyslog`
- `/var/log/auth.log`
- `/var/log/syslog`

So missing auth/syslog logs in those containers may be normal.

---

## 14. Phase 6 — Windows VMs Setup (AD & WSUS)

Keep your VirtualBox setup and Host-Only networking.

### Mandatory adapter setup

| Setting | Value |
|---|---|
| Adapter 1 | NAT |
| Adapter 2 | Host-Only Adapter → `10.10.10.1` |

### Hosts file entries

```powershell
Add-Content "C:\Windows\System32\drivers\etc\hosts" "10.10.10.1`t es01"
Add-Content "C:\Windows\System32\drivers\etc\hosts" "10.10.10.1`t fleet-server"
```

### Connectivity check

```powershell
Test-NetConnection -ComputerName es01 -Port 9200
Test-NetConnection -ComputerName fleet-server -Port 8220
```

### Elastic Agent install

Keep your existing Windows install steps.

---

## 15. Phase 7 — VirtualBox Networking for VM→Docker Connectivity

Keep the Host-Only explanation because it is useful and correct.

The important point:
- `10.0.2.2` from NAT is not reliable for Docker Desktop + WSL2
- `10.10.10.1` Host-Only works

---

## 16. Phase 8 — Shared Volume Wiring

Keep the shared volume setup and add a direct validation step:

```bash
docker inspect agent-proxy | grep -A 20 "Mounts"
docker inspect agent-websrv | grep -A 20 "Mounts"
```

---

## 17. Phase 9 — Ingest & Verify

This section should emphasize **data streams first**.

### Check data streams

```bash
curl -s -u elastic:changeme "http://localhost:9200/_data_stream?pretty"
```

### Check the streams that matter

```bash
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-windows.sysmon_operational-default/_stats?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-system.security-default/_stats?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-squid.log-default/_stats?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-nginx.access-default/_stats?pretty"
```

### Check recent documents

```bash
curl -s -u elastic:changeme "http://localhost:9200/logs-windows.sysmon_operational-default/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 1,
    "sort": [{"@timestamp":"desc"}]
  }'
```

### Classic indices still matter for Logstash outputs

```bash
curl -s -u elastic:changeme \
  "http://localhost:9200/_cat/indices/sysmon-*,syslog-*,*-cnas-*?v&h=index,docs.count&s=index"
```

### Verification rule

A source is only working when:
1. the stream or index exists,
2. documents are present,
3. recent events can be queried.

Fleet health alone is not enough.

---

## 18. Kibana Data Views

Create these data views in Kibana:

| Data View name | Index pattern | Time field | Purpose |
|---|---|---|---|
| CNAS — All Sources | `*-cnas-*,sysmon-*,auth-cnas-*,logs-system.*,logs-windows.*,logs-squid.*,logs-nginx.*` | `@timestamp` | Main investigation view |
| Windows Live | `logs-system.*,logs-windows.*` | `@timestamp` | AD / WSUS live events |
| Proxy + Web | `logs-squid.*,logs-nginx.*` | `@timestamp` | Container service logs |
| Fleet Telemetry | `logs-elastic_agent.*,metrics-*` | `@timestamp` | Agent and stack health |
| Raw Syslog | `syslog-*` | `@timestamp` | Logstash syslog receiver |

### Important note

Some live Windows and service outputs are data streams, so they may not show up where classic indices appear.

---

## 19. Phase 10 — Elastic Security & Detection Rules

This was missing before, so keep it explicit.

### Enable Elastic Security

Kibana → **Security** → **Get started**

### Load built-in detection rules

Kibana → **Security** → **Rules** → **Detection Rules** → **Add Elastic rules**

### Rules that should be enabled first

| Rule / focus | Typical condition | Purpose |
|---|---|---|
| Account Lockout | `event.code: "4740"` | Brute-force / lockout detection |
| High Failed Logon Attempts | `event.code: "4625"` | Credential stuffing / password spray |
| Kerberoasting via Service Tickets | `event.code: "4769"` | Kerberos abuse |
| DCSync / Directory Replication Access | `event.code: "4662"` | Domain replication abuse |
| Sensitive Privilege Use | `event.code: "4672"` | Privilege escalation |
| Member Added to Security Group | `event.code: "4728"` | Persistence / privilege changes |

### Recommended rule coverage

| Tag filter | Fires on |
|---|---|
| Windows | `sysmon-*`, `logs-windows.*` |
| Credential Access | `sysmon-*`, `logs-windows.*` |
| Lateral Movement | `sysmon-*` |
| Network | `network-cnas-*` |
| Web Application Attack | `proxy-cnas-*` |

### Custom rule example

```text
Index patterns: *-cnas-*, sysmon-*, logs-windows.*
KQL: event.code: "4625" and event.category: "authentication"
Group by: source.ip
Threshold: >= 5 events in 5 minutes
Severity: High
MITRE: Credential Access / T1110
```

---

## 20. Migration: Current State → Target Architecture

If you are now using real data, keep this section only for what still needs to be migrated.  
You can remove the EVTX and CICIDS replay steps if they are no longer part of your workflow.

---

## 21. Real Production Deployment

Keep this section. It is still useful.

The same architecture can be used for a real Windows or Linux machine by changing only the Fleet URL and enrollment token.

---

## 22. Known Issues & Fixes

### Sysmon not in index list
`logs-windows.sysmon_operational-default` is a data stream, not a classic index. Check **Data Streams**.

### Elasticsearch health is YELLOW
Expected on a single-node lab because replica shards cannot be allocated.

### Agent is healthy but no logs appear
Check:
- mount paths,
- actual log file contents,
- data stream creation,
- recent documents.

### Nginx logs missing
Check:
- `agent-websrv` mounts,
- `/var/log/nginx/` content,
- stream existence in Elasticsearch.

### Linux auth/syslog missing
This may be normal in minimal service containers that do not run rsyslog or create those logs.

### Windows Server 2025 filtering warning
Do not rely only on Fleet policy filtering. Confirm actual arriving events in the data stream.

### Logstash sincedb prevents replay
Delete `sincedb-*` and restart Logstash.

---

## 23. Troubleshooting Reference

### Check all containers

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### Check mounts for the agents

```bash
docker inspect agent-proxy | grep -A 20 "Mounts"
docker inspect agent-websrv | grep -A 20 "Mounts"
```

### Check file visibility inside agents

```bash
docker exec -it agent-proxy tail -5 /var/log/squid/access.log
docker exec -it agent-websrv tail -5 /var/log/nginx/access.log
```

### Check agent logs

```bash
docker logs agent-proxy --tail 50
docker logs agent-websrv --tail 50
```

### Check Windows connectivity

```powershell
Test-NetConnection -ComputerName es01 -Port 9200
Test-NetConnection -ComputerName fleet-server -Port 8220
Get-Service "Elastic Agent"
```

### Check data stream existence

```bash
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-system.security-default?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-windows.sysmon_operational-default?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-squid.log-default?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-nginx.access-default?pretty"
```

### If a stream returns 404
That source is not ingesting yet, even if Fleet says the agent is healthy.

---

## 24. Credentials & Quick Reference

Keep your existing credentials and quick command references here.
