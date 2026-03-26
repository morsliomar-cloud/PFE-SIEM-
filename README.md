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
│  │    Real Windows Event Logs → sysmon-* / logs-winlog-*              │    │
│  │                                                                     │    │
│  │  WSUS-CNAS-KOLEA (Windows Server 2025)                             │    │
│  │    Elastic Agent → Fleet Server (10.10.10.1:8220)                  │    │
│  │    Real Windows Event Logs → sysmon-* / logs-winlog-*              │    │
│  │                                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│  DATA SOURCES              COLLECTION          ECS INDEX      PURPOSE       │
│  ─────────────────         ──────────────      ──────────     ──────────   │
│  EVTX-ATTACK-SAMPLES  ──►  Logstash file   ──► sysmon-*       Detection    │
│  CICIDS 2017 CSVs     ──►  Logstash CSV    ──► network-cnas-* Network      │
│  CICIDS Web Attacks   ──►  Logstash CSV    ──► proxy-cnas-*   Web attack   │
│  Faker auth events    ──►  Logstash file   ──► auth-cnas-*    Auth baseline│
│  Windows VMs          ──►  Elastic Agent   ──► logs-winlog-*  Live Windows │
│  Squid / Nginx logs   ──►  Elastic Agent   ──► logs-*         Live proxy   │
│  ALL indices ─────────────────────────────►  Elastic Security             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Tiers — Real vs Simulated vs Live

### Tier 1 — Real historical attack data (datasets)

The EVTX-ATTACK-SAMPLES and CICIDS datasets are **captures from real attacks on real systems**. Someone ran DCSync, Kerberoasting, SQL injection, and XSS attacks — real tools, real machines — and recorded every event. These files are ground truth.

**Purpose:** Write and validate detection rules. A detection rule that correctly identifies Kerberoasting in the EVTX dataset will correctly identify Kerberoasting in live data, because the EventID pattern is identical regardless of which machine generated it.

### Tier 2 — Real production VMs (current state for AD/WSUS)

AD-CNAS-KOLEA and WSUS-CNAS-KOLEA are now **real Windows Server 2025 VMs** running in VirtualBox. Elastic Agent is installed natively on each VM and enrolls to Fleet Server via the Host-Only network adapter. These generate real Windows Event Logs — real authentication events, real process creation, real security logs.

**Why this matters:** The detection rules you write against EVTX historical data will fire on these VMs immediately — same EventIDs, same ECS fields, different timestamps.

### Tier 3 — Real Docker services (Proxy & WebSrv)

PROXY-CNAS-KOLEA runs real **Squid** and WEBSRV-CNAS-KOLEA runs real **Nginx** — both Docker containers generating actual access logs instead of telemetry scripts. Elastic Agent reads those logs and ships them to Fleet.

### Tier 4 — Static file ingestion via Logstash

CICIDS CSVs and EVTX NDJSON files sit in directories. Logstash file inputs read them, apply ECS normalization, and write to Elasticsearch. This is the historical attack data layer.

---

## 3. Elastic Agent vs Logstash — Who Does What

### What Elastic Agent does in this lab

| Source | Collection method | Index pattern |
|--------|-------------------|---------------|
| Windows Event Logs (AD/WSUS VMs) | Elastic Agent native | `logs-winlog.*` |
| System metrics (CPU, memory, disk) | Elastic Agent system integration | `metrics-system.*` |
| Squid proxy logs | Elastic Agent custom log | `logs-*` |
| Nginx web server logs | Elastic Agent custom log | `logs-*` |

### What Logstash does in this lab

| Source | Why Logstash | Index |
|--------|-------------|-------|
| EVTX-ATTACK-SAMPLES NDJSON | Static files, needs ECS transform | `sysmon-*` |
| CICIDS 2017 CSV | CSV parsing + ECS field mapping | `network-cnas-*` |
| CICIDS Web Attacks CSV | CSV parsing + attack classification | `proxy-cnas-*` |
| Faker auth NDJSON | Static file ingestion | `auth-cnas-*` |
| Syslog UDP/TCP :514 | Network device syslog receiver | `syslog-*` |

---

## 4. ECS Normalization — Core Requirement

Every event ingested into Elasticsearch **must** use ECS field names. This is enforced in the Logstash filter section and in how Elastic Agent integrations emit data natively.

**Why this matters:** A detection rule written as `event.code: "4769" and event.outcome: "failure"` works identically against:
- An EVTX file from 2020 (historical)
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

### 5.1 AD-CNAS-KOLEA → EVTX-ATTACK-SAMPLES + Live Windows VM

**Dataset:** [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) — real Windows EVTX captures from actual attacks (DCSync, Pass-the-Hash, Kerberoasting).

| EventID | Attack | MITRE | Detection logic |
|---------|--------|-------|-----------------|
| 4625 | Failed login | T1110 | High volume from one source IP |
| 4740 | Account lockout | T1110.001 | Any 4740 event |
| 4769 | Kerberos TGS request | T1558.003 | TicketEncryptionType=0x17 (RC4) |
| 4662 | Directory service access | T1003.006 DCSync | Specific ObjectType GUIDs |
| 4728 | Member added to group | T1098 | Group = "Domain Admins" |
| 4672 | Special privileges on logon | T1078 | Non-admin user |
| 4648 | Explicit credential use | T1550 | Unexpected host |

### 5.2 Network Traffic → CICIDS 2017

**Dataset:** [CICIDS 2017](https://www.unb.ca/cic/datasets/ids-2017.html) — real network captures labeled by attack type: DoS, DDoS, brute force, botnet, infiltration.

### 5.3 PROXY-CNAS-KOLEA → CICIDS Web Attacks + Real Squid

**Dataset:** CICIDS 2017 Thursday file — SQLi, XSS, and brute force HTTP attacks.
**Live:** Real Squid container generating actual access.log entries.

### 5.4 Authentication → Faker + Logstash

Faker generates statistically plausible authentication events (EventIDs 4624, 4625, 4634, 4740, 4767) to provide the normal baseline that anomaly detection needs.

---

## 6. Current Deployed State

| Component | Status | Notes |
|-----------|--------|-------|
| Elasticsearch (es01) | ✅ Running | Security enabled, port 9200 |
| Kibana (kibana01) | ✅ Running | Port 5601 |
| Logstash (logstash01) | ✅ Running | Multi-pipeline |
| Fleet Server | ✅ Running | Port 8220 |
| proxy-cnas (Squid) | ✅ Running | Real logs, port 3128 |
| websrv-cnas (Nginx) | ✅ Running | Real logs, port 80 |
| agent-proxy | ✅ Enrolled | Ships Squid logs to Fleet |
| agent-websrv | ✅ Enrolled | Ships Nginx logs to Fleet |
| AD-CNAS-KOLEA | ✅ Windows VM | Elastic Agent installed natively |
| WSUS-CNAS-KOLEA | ✅ Windows VM | Elastic Agent installed natively |

| Index | Source type | State |
|-------|-------------|-------|
| `sysmon-*` | Real: EVTX-ATTACK-SAMPLES | ✅ Working |
| `syslog-*` | Raw syslog | ✅ Working |
| `logs-winlog-*` | Live: Windows VMs via Elastic Agent | ✅ Working |
| `logs-*` / `metrics-*` | Live: Elastic Agent Fleet | ✅ Working |
| `network-cnas-*` | Real: CICIDS 2017 | ⏳ Dataset not yet dropped |
| `auth-cnas-*` | Synthetic: Faker | ⏳ Not yet generated |

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
│   │   ├── pipeline/ettx-attacks.conf
│   │   ├── pipelines.yml
│   │   ├── ettx-input/                    # Drop EVTX NDJSON here
│   │   └── datasets/
│   │       ├── cicids2017/
│   │       ├── cicids-webattacks/
│   │       └── auth-cnas/
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
      - ./logstash/ettx-input:/usr/share/logstash/ettx-input
      - ./logstash/datasets:/usr/share/logstash/datasets:ro
      - proxy-logs:/var/log/proxy:ro
      - websrv-logs:/var/log/websrv:ro
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

```ruby
input {
  # EVTX-ATTACK-SAMPLES / Sysmon NDJSON
  file {
    path => "/usr/share/logstash/ettx-input/*.json"
    start_position => "beginning"
    sincedb_path => "/usr/share/logstash/data/sincedb-ettx"
    codec => "json"
    tags => ["sysmon"]
  }

  # CICIDS 2017 network flows
  file { path => "/usr/share/logstash/datasets/cicids2017/*.csv";        start_position => "beginning"; sincedb_path => "/usr/share/logstash/data/sincedb-cicids";     tags => ["cicids2017"] }
  file { path => "/usr/share/logstash/datasets/cicids-webattacks/*.csv"; start_position => "beginning"; sincedb_path => "/usr/share/logstash/data/sincedb-cicids-web"; tags => ["cicids-webattacks"] }

  # Faker auth events
  file { path => "/usr/share/logstash/datasets/auth-cnas/*.ndjson"; start_position => "beginning"; sincedb_path => "/usr/share/logstash/data/sincedb-auth"; codec => "json"; tags => ["auth-cnas"] }

  # Syslog from containers/devices
  udp { port => 514; tags => ["syslog-udp"] }
  tcp { port => 514; tags => ["syslog-tcp"] }
}

filter {
  # ECS: Sysmon / EVTX
  if "sysmon" in [tags] {
    if [EventID] or [event_id] {
      mutate {
        rename => {
          "EventID"         => "[event][code]"
          "SourceAddress"   => "[source][ip]"
          "DestAddress"     => "[destination][ip]"
          "SourcePort"      => "[source][port]"
          "DestPort"        => "[destination][port]"
          "Username"        => "[user][name]"
          "Domain"          => "[user][domain]"
          "ProcessName"     => "[process][name]"
          "ProcessId"       => "[process][pid]"
          "ComputerName"    => "[host][name]"
          "LogonType"       => "[winlog][logon][type]"
          "AttackTactic"    => "[threat][tactic][name]"
          "AttackTechnique" => "[threat][technique][name]"
        }
      }
    }
    if [TimeCreated] {
      date { match => ["TimeCreated", "ISO8601"]; target => "@timestamp"; remove_field => ["TimeCreated"] }
    }
    if      [event][code] == "4625" { mutate { add_field => { "[event][category]" => "authentication" "[event][outcome]" => "failure"  } } }
    else if [event][code] == "4624" { mutate { add_field => { "[event][category]" => "authentication" "[event][outcome]" => "success"  } } }
    else if [event][code] == "4740" { mutate { add_field => { "[event][category]" => "iam"            "[event][outcome]" => "failure"  } } }
    else if [event][code] == "4662" { mutate { add_field => { "[event][category]" => "file"                                           } } }
    else if [event][code] == "4769" { mutate { add_field => { "[event][category]" => "authentication" "[event][dataset]" => "kerberos" } } }
    else if [event][code] == "4672" { mutate { add_field => { "[event][category]" => "authentication" "[event][type]"    => "admin"    } } }
    mutate { add_field => { "[event][module]" => "sysmon" "[labels][dataset]" => "sysmon" } }
  }

  # ECS: CICIDS 2017 network flows
  if "cicids2017" in [tags] {
    csv {
      separator => ","
      skip_header => true
      columns => ["destination_port","flow_duration","total_fwd_packets","total_bwd_packets",
                  "total_length_fwd","total_length_bwd","flow_bytes_per_s","flow_packets_per_s","label"]
    }
    mutate {
      rename => { "destination_port" => "[destination][port]" "flow_bytes_per_s" => "[network][bytes]" "label" => "_raw_label" }
      add_field => { "[event][category]" => "network" "[event][module]" => "cicids2017" "[labels][dataset]" => "network-cnas" "[host][name]" => "NETWORK-CNAS-KOLEA" }
    }
    if [_raw_label] == "BENIGN" { mutate { add_field => { "[event][outcome]" => "success" } } }
    else { mutate { add_field => { "[event][outcome]" => "failure" "[threat][tactic][name]" => "%{_raw_label}" } } }
    mutate { remove_field => ["_raw_label", "message", "host", "path"] }
  }

  # ECS: CICIDS Web Attacks
  if "cicids-webattacks" in [tags] {
    csv { separator => "," skip_header => true columns => ["destination_port","flow_duration","flow_bytes_per_s","label"] }
    mutate {
      rename => { "destination_port" => "[destination][port]" "flow_bytes_per_s" => "[network][bytes]" "label" => "_raw_label" }
      add_field => { "[event][category]" => "network" "[event][module]" => "cicids_webattacks" "[labels][dataset]" => "proxy-cnas" "[host][name]" => "PROXY-CNAS-KOLEA" }
    }
    if      [_raw_label] =~ /SQL/   { mutate { add_field => { "[event][code]" => "5002" "[event][outcome]" => "failure" "[threat][technique][name]" => "SQL Injection"       "[threat][tactic][name]" => "Initial Access" } } }
    else if [_raw_label] =~ /XSS/   { mutate { add_field => { "[event][code]" => "5003" "[event][outcome]" => "failure" "[threat][technique][name]" => "Cross-Site Scripting" "[threat][tactic][name]" => "Execution"     } } }
    else if [_raw_label] =~ /Brute/ { mutate { add_field => { "[event][code]" => "5001" "[event][outcome]" => "failure" "[threat][technique][name]" => "Brute Force"          "[threat][tactic][name]" => "Credential Access" } } }
    else if [_raw_label] == "BENIGN"{ mutate { add_field => { "[event][outcome]" => "success" } } }
    mutate { remove_field => ["_raw_label", "message", "host", "path"] }
  }
}

output {
  if      "sysmon"           in [tags] { elasticsearch { hosts => ["http://es01:9200"]; user => "elastic"; password => "changeme"; index => "sysmon-%{+YYYY.MM.dd}";       manage_template => false } }
  else if "cicids2017"       in [tags] { elasticsearch { hosts => ["http://es01:9200"]; user => "elastic"; password => "changeme"; index => "network-cnas-%{+YYYY.MM.dd}"; manage_template => false } }
  else if "cicids-webattacks" in [tags]{ elasticsearch { hosts => ["http://es01:9200"]; user => "elastic"; password => "changeme"; index => "proxy-cnas-%{+YYYY.MM.dd}";   manage_template => false } }
  else if "auth-cnas"        in [tags] { elasticsearch { hosts => ["http://es01:9200"]; user => "elastic"; password => "changeme"; index => "auth-cnas-%{+YYYY.MM.dd}";    manage_template => false } }
  else                                 { elasticsearch { hosts => ["http://es01:9200"]; user => "elastic"; password => "changeme"; index => "syslog-%{+YYYY.MM.dd}";        manage_template => false } }
}
```

---

## 12. Phase 4 — Dataset Preparation

```bash
mkdir -p ~/ELK/elk_stack/logstash/datasets/cicids2017
mkdir -p ~/ELK/elk_stack/logstash/datasets/cicids-webattacks
mkdir -p ~/ELK/elk_stack/logstash/datasets/auth-cnas
mkdir -p ~/ELK/elk_stack/logstash/ettx-input

# EVTX-ATTACK-SAMPLES
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git ~/datasets/evtx-attack-samples
cp ~/datasets/evtx-attack-samples/*.json ~/ELK/elk_stack/logstash/ettx-input/ 2>/dev/null || true

# CICIDS 2017 — download from https://www.unb.ca/cic/datasets/ids-2017.html
cp ~/Downloads/MachineLearningCSV/*.csv ~/ELK/elk_stack/logstash/datasets/cicids2017/
cp ~/Downloads/MachineLearningCSV/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv \
   ~/ELK/elk_stack/logstash/datasets/cicids-webattacks/

# Faker auth events
pip install faker --break-system-packages
python3 generate_auth.py > ~/ELK/elk_stack/logstash/datasets/auth-cnas/auth-events.ndjson
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

# Verify Logstash can read the logs
docker exec logstash01 ls -lh /var/log/proxy/ /var/log/websrv/

# Clear sincedb to force re-read
MSYS_NO_PATHCONV=1 docker exec logstash01 sh -c "rm -f /usr/share/logstash/data/sincedb-*"
docker restart logstash01
```

---

## 17. Phase 9 — Ingest & Verify

### Check all indices

```bash
curl -s -u elastic:changeme \
  "http://localhost:9200/_cat/indices/sysmon-*,syslog-*,*-cnas-*,logs-winlog-*?v&h=index,docs.count&s=index"
```

### ECS parse failure check (must be 0)

```bash
for idx in sysmon network-cnas proxy-cnas auth-cnas; do
  COUNT=$(curl -s -u elastic:changeme "http://localhost:9200/${idx}-*/_count" \
    -H "Content-Type: application/json" \
    -d '{"query":{"term":{"tags":"_jsonparsefailure"}}}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))")
  echo "$idx _jsonparsefailure: $COUNT"
done
```

### Full delete and re-ingest cycle

```bash
curl -s -u elastic:changeme -X PUT "http://localhost:9200/_cluster/settings" \
  -H "Content-Type: application/json" \
  -d '{"persistent":{"action.destructive_requires_name":false}}'

curl -s -u elastic:changeme -X DELETE \
  "http://localhost:9200/*-cnas-*,sysmon-*,auth-cnas-*"

MSYS_NO_PATHCONV=1 docker exec logstash01 sh -c "rm -f /usr/share/logstash/data/sincedb-*"
docker restart logstash01
```

---

## 18. Kibana Data Views

| Data View name | Index pattern | Time field | What it covers |
|----------------|---------------|------------|----------------|
| **CNAS — All Sources** | `*-cnas-*,sysmon-*,auth-cnas-*,logs-winlog-*` | `@timestamp` | Everything security-relevant |
| **Fleet Telemetry** | `metrics-*,logs-*` | `@timestamp` | System health, agent logs |
| **Raw Syslog** | `syslog-*` | `@timestamp` | Unprocessed syslog |

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

# Web attacks
threat.technique.name: "SQL Injection" or threat.technique.name: "Cross-Site Scripting"

# Live Windows VM events only
event.module: "windows" or event.dataset: "windows.security"
```

> **EVTX historical data note:** Timestamps are from 2020. Set Kibana time picker to cover 2020 or use **All time** when investigating `sysmon-*` indices.

---

## 19. Phase 10 — Elastic Security & Detection Rules

### Enable Elastic Security

Kibana → **Security** (left sidebar) → **Get started**.

### Load prebuilt detection rules

```
Security → Rules → Detection Rules → Add Elastic rules
```

| Tag filter | Rules | Fires on |
|------------|-------|---------|
| `Windows` | Windows EventID rules | `sysmon-*`, `logs-winlog-*` |
| `Credential Access` | Brute force, Kerberoasting, DCSync | `sysmon-*`, `auth-cnas-*` |
| `Lateral Movement` | Pass-the-Hash, explicit creds | `sysmon-*` |
| `Network` | Anomalous connections | `network-cnas-*` |
| `Web Application Attack` | SQLi, XSS | `proxy-cnas-*` |

### Critical rules to enable first

```
Windows: Account Lockout                    event.code: "4740"
High Failed Logon Attempts                  event.code: "4625"
Kerberoasting via Service Tickets           event.code: "4769"
DCSync via Replication Services             event.code: "4662"
Sensitive Privilege Use                     event.code: "4672"
Member Added to Security Group              event.code: "4728"
```

### Custom rule example — brute force

```
Index patterns: *-cnas-*, sysmon-*, logs-winlog-*
KQL: event.code: "4625" and event.category: "authentication"
Group by: source.ip
Threshold: ≥ 5 events in 5 minutes
Severity: High
MITRE: Credential Access / T1110
```

---

## 20. Migration: Current State → Target Architecture

### Step A — Add CICIDS 2017 network data

```bash
cp ~/Downloads/MachineLearningCSV/*.csv ~/ELK/elk_stack/logstash/datasets/cicids2017/
docker restart logstash01
```

### Step B — Add CICIDS Web Attacks

```bash
cp ~/Downloads/MachineLearningCSV/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv \
   ~/ELK/elk_stack/logstash/datasets/cicids-webattacks/
MSYS_NO_PATHCONV=1 docker exec logstash01 rm -f /usr/share/logstash/data/sincedb-cicids-web
docker restart logstash01
```

### Step C — Generate Faker auth events

```bash
python3 generate_auth.py > ~/ELK/elk_stack/logstash/datasets/auth-cnas/auth-events.ndjson
MSYS_NO_PATHCONV=1 docker exec logstash01 rm -f /usr/share/logstash/data/sincedb-auth
docker restart logstash01
```

### Step D — Enable Elastic Security detection rules

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

Rules written against EVTX historical data fire on live Windows machines immediately — same EventIDs, same ECS fields, zero reconfiguration.

---

## 22. Known Issues & Fixes

### VirtualBox NAT + Docker WSL2 — ports unreachable from VMs

**Cause:** Docker runs inside WSL2 (Hyper-V). The Hyper-V WSL firewall blocks TCP from VirtualBox NAT's `10.0.2.2` even though `0.0.0.0:9200` shows as LISTENING.

**Fix:** Add a second network adapter (Host-Only) to each VM. Use `10.10.10.1` in the hosts file. See Phase 7.

**Do NOT use:**
- `networkingMode=mirrored` in `.wslconfig` — breaks other networking
- `netsh portproxy` — unreliable with VirtualBox NAT
- Static Docker IPs (`172.20.x.x`) — internal only, not reachable from outside Docker

### `_jsonparsefailure` in Logstash

**Cause:** `codec => "json"` reads one line at a time. Heredoc or pretty-printed JSON creates multi-line output.

**Fix:** Single `echo` per event. Never use heredoc in telemetry scripts.

### `grep -c || echo "0"` inserts newline into JSON

**Fix:** Use `|| true` instead of `|| echo "0"`.

### ES 9.x blocks wildcard index deletion

**Fix:** Temporarily disable `action.destructive_requires_name`, delete, re-enable.

### EVTX data not visible in Kibana

**Cause:** Default time range is "Last 15 minutes". EVTX timestamps are from 2020.

**Fix:** Set Kibana time picker to cover 2020 or use **All time**.

### Logstash sincedb prevents re-reading truncated files

**Fix:** Delete `/usr/share/logstash/data/sincedb-*` and restart Logstash.

### Git Bash path conversion on Windows

**Fix:** `export MSYS_NO_PATHCONV=1` in `~/.bashrc`.

---

## 23. Troubleshooting Reference

### All containers at a glance

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
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
echo "=== Indices ===" && \
curl -s -u elastic:changeme \
  "http://localhost:9200/_cat/indices/sysmon-*,syslog-*,*-cnas-*?h=index,docs.count&s=index" && \
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

### Dataset download links

| Dataset | URL | Target index |
|---------|-----|-------------|
| EVTX-ATTACK-SAMPLES | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES | `sysmon-*` |
| CICIDS 2017 | https://www.unb.ca/cic/datasets/ids-2017.html | `network-cnas-*` |
| CICIDS Web Attacks | Same download → Thursday morning file | `proxy-cnas-*` |
| Faker | `pip install faker` | `auth-cnas-*` |

---

*ELK Stack 9.1.3 · Elastic Agent 9.1.3 · Elastic Security · Docker Desktop Windows (WSL2) · VirtualBox 7.x · Windows Server 2025 VMs*

*⚠️ Lab environment. Default credentials are intentional. Do not expose ports externally. Rotate credentials and enable TLS before any production deployment.*
