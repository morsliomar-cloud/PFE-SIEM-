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
13. [Phase 5 — CNAS Containers & Telemetry Scripts](#13-phase-5--cnas-containers--telemetry-scripts)
14. [Phase 6 — Shared Volume Wiring](#14-phase-6--shared-volume-wiring)
15. [Phase 7 — Ingest & Verify](#15-phase-7--ingest--verify)
16. [Kibana Data Views](#16-kibana-data-views)
17. [Phase 8 — Elastic Security & Detection Rules](#17-phase-8--elastic-security--detection-rules)
18. [Migration: Current State → Target Architecture](#18-migration-current-state--target-architecture)
19. [Real Production Deployment](#19-real-production-deployment)
20. [Known Issues & Fixes](#20-known-issues--fixes)
21. [Troubleshooting Reference](#21-troubleshooting-reference)
22. [Credentials & Quick Reference](#22-credentials--quick-reference)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TARGET ARCHITECTURE                                 │
│                                                                             │
│  DATA SOURCES              COLLECTION          ECS INDEX      PURPOSE       │
│  ─────────────────         ──────────────      ──────────     ──────────    │
│  EVTX-ATTACK-SAMPLES  ──►  Logstash file   ──► sysmon-*       Detection     │
│  (real attack captures)    input + ECS map                    rule dev      │
│                                                                             │
│  CICIDS 2017 CSVs     ──►  Logstash CSV    ──► network-cnas-* Network       │
│  (real network flows)      filter + ECS map                   detection     │
│                                                                             │
│  CICIDS Web Attacks   ──►  Logstash CSV    ──► proxy-cnas-*   Web attack    │
│  (SQLi, XSS captures)      filter + ECS map                   detection     │
│                                                                             │
│  Faker-generated auth ──►  Logstash file   ──► auth-cnas-*    Auth          │
│  events (synthetic)        input + ECS map                    baseline      │
│                                                                             │
│  CNAS containers      ──►  Elastic Agent   ──► logs-*/         Live         │
│  (Ubuntu, simulating        (Fleet-managed)     metrics-*       system      │
│   AD/WSUS/Proxy/Web)                                           telemetry    │
│                                                                             │
│  Syslog UDP/TCP       ──►  Logstash input  ──► syslog-*        Raw log      │
│                                                                 fallback    │
│                                                                             │
│  ALL indices ──────────────────────────────► Elastic Security              │
│                                               Detection Rules               │
│                                               (600+ prebuilt + custom)      │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key design rule:** Every event written to Elasticsearch must use ECS field names. This is what makes a detection rule written against EVTX historical data automatically work against live events from real machines.

---

## 2. Data Tiers — Real vs Simulated vs Live

Understanding the distinction between these three is critical.

### Tier 1 — Real historical attack data (datasets)

The EVTX-ATTACK-SAMPLES and CICIDS datasets are **captures from real attacks on real systems**. Someone ran DCSync, Kerberoasting, SQL injection, and XSS attacks — real tools, real machines — and recorded every event. These files are ground truth.

**Purpose:** Write and validate detection rules. A detection rule that correctly identifies Kerberoasting in the EVTX dataset will correctly identify Kerberoasting in live data, because the EventID pattern is identical regardless of which machine generated it.

**What they cannot do:** They are static files. They will not generate new events. They are your training and validation dataset, not your live monitoring target.

### Tier 2 — Simulated telemetry (current state, temporary)

The `ad_telemetry.sh`, `wsus_telemetry.sh`, etc. scripts generate JSON events with real Windows EventID codes but fabricated field values. They exist because the CNAS containers are **Ubuntu Linux, not Windows** — a Linux container cannot natively generate Windows Event Logs.

**Purpose:** Keep the live indices (`ad-cnas-*`, `wsus-cnas-*`) populated with current-timestamp data for dashboard development and pipeline testing.

**Limitation:** The events are synthetic. They are not real attack indicators. Do not write production detection rules against simulated telemetry data.

**When to remove them:** When either (a) you deploy Elastic Agent on real Windows machines, or (b) you move to Windows containers with actual Windows Event Log generation.

### Tier 3 — Real production deployment

On actual infrastructure — a real Windows Domain Controller, a real proxy server — you install **Elastic Agent** directly on the machine. The agent reads the native Windows Event Log, syslog, application logs, and streams them in ECS format directly to Elasticsearch via Fleet. No scripts. No Logstash file inputs for live data. The detection rules you built against the historical datasets fire immediately on real events.

This lab builds the exact pipeline that production deployment uses. The architecture is identical — only the data source changes from static files to live machines.

---

## 3. Elastic Agent vs Logstash — Who Does What

A common point of confusion: Elastic Agent is the **unified replacement** for all individual Beats agents (Filebeat, Metricbeat, Auditbeat, Winlogbeat, Packetbeat). You do **not** add Beats separately. One Elastic Agent per machine handles everything.

### What Elastic Agent does in this lab

When an agent is enrolled with Fleet, it automatically collects:

| What it collects | Data stream | Index pattern |
|-----------------|-------------|---------------|
| System logs (syslog, auth.log, etc.) | `logs-system.syslog` | `logs-*` |
| System metrics (CPU, memory, disk, network) | `metrics-system.cpu` | `metrics-*` |
| Any integration you enable in Fleet UI | integration-specific stream | varies |

These write to **data streams** — not traditional indices. A data stream like `logs-system.syslog-default` is automatically backed by time-series indices but you query the stream name directly. `logs-*` and `metrics-*` cover all of them.

**Every metric and log from a running machine goes through Elastic Agent. You never need to configure Filebeat or Metricbeat separately.**

### What Logstash does in this lab

Logstash handles the two tasks that Elastic Agent cannot do:

**1. Static dataset file ingestion.** CICIDS CSVs and EVTX NDJSON files sitting in a directory are not streaming events from a running machine. Logstash's `file` input watches a directory, reads new content, applies the ECS normalization filter, and writes to Elasticsearch. Elastic Agent has no equivalent for this.

**2. Syslog UDP/TCP receiver.** Some network devices and containers send syslog without an agent. Logstash listens on port 514 and receives these. Elastic Agent can be configured to do this too, but Logstash is simpler for this use case.

### Architecture in plain terms

```
Machine-based events (live)
  → Elastic Agent (installed on machine)
  → Fleet Server (manages agent config)
  → Elasticsearch (logs-* / metrics-* data streams)

File-based datasets and syslog (ingestion pipeline)
  → Logstash (file inputs + ECS filter + output)
  → Elasticsearch (sysmon-* / network-cnas-* / auth-cnas-* etc.)

Both paths land in Elasticsearch.
Both are visible in Kibana.
Both are queried by Elastic Security detection rules.
```

---

## 4. ECS Normalization — Core Requirement

Every event ingested into Elasticsearch **must** use ECS field names before it is written to any index. This is enforced in the Logstash filter section and in how the telemetry scripts emit JSON.

**Why this matters:** A detection rule written as `event.code: "4769" and event.outcome: "failure"` works identically against:
- An EVTX file from 2020 (historical)
- Live events from a Windows machine via Elastic Agent (production)
- A simulated event from a telemetry script (development)

Without ECS, you would write a separate rule for each source. With ECS, one rule covers all of them.

### ECS field mappings used in this lab

| Raw field (source) | ECS field | Type | Example |
|--------------------|-----------|------|---------|
| `EventID` / `event_id` | `event.code` | keyword | `"4625"` |
| `TimeCreated` | `@timestamp` | date | `"2024-01-15T10:30:00Z"` |
| `SourceAddress` / `src_ip` | `source.ip` | ip | `"192.168.1.100"` |
| `DestAddress` / `dst_ip` | `destination.ip` | ip | `"10.0.0.1"` |
| `SourcePort` | `source.port` | long | `54321` |
| `DestPort` | `destination.port` | long | `443` |
| `Username` / `user` | `user.name` | keyword | `"jdoe"` |
| `Domain` | `user.domain` | keyword | `"CORP"` |
| `ComputerName` / `hostname` | `host.name` | keyword | `"AD-CNAS-KOLEA"` |
| `ProcessName` | `process.name` | keyword | `"lsass.exe"` |
| `ProcessId` | `process.pid` | long | `1234` |
| `AttackTactic` | `threat.tactic.name` | keyword | `"Credential Access"` |
| `AttackTechnique` | `threat.technique.name` | keyword | `"Brute Force"` |
| `LogonType` | `winlog.logon.type` | keyword | `"Network"` |
| — | `event.category` | keyword | `"authentication"` |
| — | `event.outcome` | keyword | `"failure"` |
| — | `event.module` | keyword | `"sysmon"` |
| — | `labels.dataset` | keyword | `"ad-cnas"` |

### ECS event.category values used

| Value | Used for |
|-------|----------|
| `authentication` | Login success/failure, Kerberos, SSH |
| `iam` | Account lockout, group changes, privilege use |
| `network` | Connections, proxy traffic, DNS |
| `file` | File creation, webshell detection, DCSync |
| `process` | Process spawning |
| `host` | Load average, disk, uptime |
| `configuration` | WSUS patch state |

### Validate ECS compliance of any index

```bash
curl -s -u elastic:changeme \
  "http://localhost:9200/ad-cnas-*/_search?size=1&pretty" \
  | python3 -c "
import sys, json
doc = json.load(sys.stdin)['hits']['hits'][0]['_source']
required = ['@timestamp', 'event', 'host', 'labels']
for f in required:
    print(('✅' if f in doc else '❌ MISSING'), f)
for subf in ['code', 'category', 'outcome', 'module']:
    print(('  ✅' if subf in doc.get('event',{}) else '  ❌ MISSING'), 'event.' + subf)
"
```

---

## 5. Dataset Mapping per CNAS Source

### 5.1 AD-CNAS-KOLEA → EVTX-ATTACK-SAMPLES

**Simulates:** A Windows Active Directory domain controller under attack.

**Dataset:** [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) — real Windows EVTX captures from actual attacks (DCSync, Pass-the-Hash, Kerberoasting, etc.), converted to NDJSON.

**Why these events let you detect real attacks:**

| EventID | Attack | MITRE Technique | Detection rule logic |
|---------|--------|----------------|---------------------|
| 4625 | Failed login / brute force | T1110 | High volume of 4625 from one source IP in short window |
| 4740 | Account lockout | T1110.001 | Any 4740 event — always suspicious |
| 4769 | Kerberos TGS request | T1558.003 Kerberoasting | `event.code:4769` + TicketEncryptionType=0x17 (RC4) |
| 4662 | Directory service access | T1003.006 DCSync | `event.code:4662` + specific ObjectType GUIDs |
| 4728 | Member added to group | T1098 | `event.code:4728` where group = "Domain Admins" |
| 4672 | Special privileges on logon | T1078 Valid Accounts | `event.code:4672` for non-admin user |
| 4648 | Explicit credential use | T1550 Pass-the-Hash | `event.code:4648` from unexpected host |

When these rules fire on EVTX historical data → rule is validated.
When the same EventIDs appear in live Elastic Agent data from a real Windows DC → same rules fire automatically.

**Download:**
```bash
git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git ~/datasets/evtx-attack-samples
cp ~/datasets/evtx-attack-samples/*.json ~/ELK/elk_stack/logstash/ettx-input/ 2>/dev/null || true
```

---

### 5.2 Network Traffic → CICIDS 2017

**Simulates:** Network traffic between CNAS agencies including attack traffic.

**Dataset:** [CICIDS 2017](https://www.unb.ca/cic/datasets/ids-2017.html) — University of New Brunswick. Real network captures labeled by attack type: DoS, DDoS, brute force, botnet, infiltration.

**Why these flows let you detect real attacks:**

The CICIDS dataset contains labeled NetFlow records. An ML anomaly detection job or threshold rule trained on "BENIGN" flows will flag flows that match the attack patterns — same IP behavior, same port patterns, same flow duration distributions. These statistical signatures transfer to real network data.

**Download:**
```bash
# From https://www.unb.ca/cic/datasets/ids-2017.html → MachineLearningCSV.zip
cp ~/Downloads/MachineLearningCSV/*.csv ~/ELK/elk_stack/logstash/datasets/cicids2017/
```

---

### 5.3 PROXY-CNAS-KOLEA → CICIDS Web Attacks

**Simulates:** A corporate proxy receiving web attack traffic.

**Dataset:** CICIDS 2017 Thursday file — `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`. Contains SQLi, XSS, and brute force HTTP attacks with full flow features.

**Detection mapping:**
- Label `Web Attack – Sql Injection` → `event.code: "5002"`, `threat.technique.name: "SQL Injection"`
- Label `Web Attack – XSS` → `event.code: "5003"`, `threat.technique.name: "Cross-Site Scripting"`
- Label `Web Attack – Brute Force` → `event.code: "5001"`, `threat.tactic.name: "Credential Access"`

```bash
cp ~/Downloads/MachineLearningCSV/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv \
   ~/ELK/elk_stack/logstash/datasets/cicids-webattacks/
```

---

### 5.4 Authentication → Faker + Logstash

**Simulates:** User account activity across all CNAS systems — normal logins, failed attempts, lockouts.

**Why synthetic here:** There is no public dataset of real multi-source authentication logs (privacy reasons). Faker generates statistically plausible data: realistic usernames, private IP ranges, realistic event distribution (mostly 4624/success, occasional 4625/failure, rare 4740/lockout).

**Purpose in detection:** Provides the normal baseline. Anomaly detection needs to know what "normal" authentication looks like before it can flag deviations.

**Generate:**
```bash
pip install faker --break-system-packages

python3 - << 'PYEOF' > ~/ELK/elk_stack/logstash/datasets/auth-cnas/auth-events.ndjson
import json, random
from faker import Faker
from datetime import datetime, timedelta, timezone

fake = Faker()
event_types = [
    ("4624", "authentication", "success", "Successful logon"),
    ("4625", "authentication", "failure", "Failed logon"),
    ("4634", "authentication", "success", "Logoff"),
    ("4648", "authentication", "unknown", "Logon using explicit credentials"),
    ("4740", "iam",            "failure", "Account lockout"),
    ("4767", "iam",            "success", "Account unlocked"),
]
tactics = {
    "4625": ("Credential Access",  "Brute Force"),
    "4740": ("Credential Access",  "Brute Force"),
    "4648": ("Lateral Movement",   "Use Alternate Authentication Material"),
}
base_time = datetime.now(timezone.utc) - timedelta(days=7)
hosts = ["AD-CNAS-KOLEA","WSUS-CNAS-KOLEA","PROXY-CNAS-KOLEA","WEBSRV-CNAS-KOLEA"]

for _ in range(5000):
    code, category, outcome, msg = random.choice(event_types)
    ts = base_time + timedelta(seconds=random.randint(0, 604800))
    event = {
        "@timestamp": ts.strftime('%Y-%m-%dT%H:%M:%S.000Z'),
        "event": {"code": code, "category": category, "outcome": outcome, "module": "faker_auth"},
        "host": {"name": random.choice(hosts)},
        "user": {"name": fake.user_name(), "domain": "KOLEA"},
        "source": {"ip": fake.ipv4_private()},
        "message": msg,
        "labels": {"dataset": "auth-cnas", "source": "faker"}
    }
    if code in tactics:
        tactic, technique = tactics[code]
        event["threat"] = {"tactic": {"name": tactic}, "technique": {"name": technique}}
    print(json.dumps(event))
PYEOF

echo "Generated $(wc -l < ~/ELK/elk_stack/logstash/datasets/auth-cnas/auth-events.ndjson) auth events"
```

---

## 6. Current Deployed State

| Component | Status | Notes |
|-----------|--------|-------|
| Elasticsearch (es01) | ✅ Running | Security enabled, port 9200 |
| Kibana (kibana01) | ✅ Running | Port 5601 |
| Logstash (logstash01) | ✅ Running | Multi-pipeline |
| Fleet Server | ✅ Running | Port 8220 |
| agent-ad / wsus / proxy / websrv | ✅ Online | All 4 enrolled, collecting to `logs-*` / `metrics-*` |
| All 4 CNAS containers | ✅ Running | Simulated telemetry every 5 min |

| Index | Source type | State |
|-------|-------------|-------|
| `sysmon-*` | Real: EVTX-ATTACK-SAMPLES | ✅ Working |
| `syslog-*` | Raw syslog from containers | ✅ Working |
| `ad-cnas-*` | Simulated (telemetry script) | ✅ Working — temporary |
| `wsus-cnas-*` | Simulated (telemetry script) | ✅ Working — temporary |
| `proxy-cnas-*` | Simulated (telemetry script) | ✅ Working — temporary |
| `websrv-cnas-*` | Simulated (telemetry script) | ✅ Working — temporary |
| `network-cnas-*` | Real: CICIDS 2017 | ⏳ Dataset not yet dropped |
| `auth-cnas-*` | Synthetic: Faker | ⏳ Not yet generated |
| `logs-*` / `metrics-*` | Live: Elastic Agent Fleet | ✅ Working |

---

## 7. Prerequisites

| Requirement | Minimum |
|-------------|---------|
| Docker Desktop (Windows) | 4.x — WSL2 backend required |
| RAM for Docker | 8 GB (ELK needs ~4–5 GB alone) |
| Disk | 30 GB free |
| Git Bash (Windows) | Any |
| Python 3 | 3.9+ |
| `curl` | Included in Git Bash |

### Windows / Git Bash — mandatory setup

```bash
echo 'export MSYS_NO_PATHCONV=1' >> ~/.bashrc
source ~/.bashrc
```

> **Never use `/tmp` as a Docker volume target on Windows.** Docker Desktop maps container `/tmp` to `%TEMP%`. Use `/usr/share/logstash/ettx-input` and `/var/log/<service>` instead.

---

## 8. Repository Layout

```
ELK/
├── elk_stack/
│   ├── docker-compose.yml
│   ├── .env                               # ← NEVER commit
│   ├── logstash/
│   │   ├── pipeline/ettx-attacks.conf     # All inputs, ECS filters, outputs
│   │   ├── pipelines.yml
│   │   ├── ettx-input/                    # Drop EVTX NDJSON here
│   │   └── datasets/
│   │       ├── cicids2017/                # CICIDS 2017 CSVs
│   │       ├── cicids-webattacks/         # Thursday web attacks CSV
│   │       └── auth-cnas/                 # Faker NDJSON
│
└── scripts/
    ├── docker-compose.cnas.yml
    └── scripts/
        ├── ad_telemetry.sh                # Temporary — simulated data
        ├── wsus_telemetry.sh
        ├── proxy_telemetry.sh
        └── webserver_telemetry.sh
```

---

## 9. Phase 1 — Core ELK Stack

### `docker-compose.yml`

```yaml
version: "3.8"

services:

  es01:
    image: docker.elastic.co/elasticsearch/elasticsearch:9.1.3
    container_name: es01
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=changeme
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
    ports:
      - "9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data
    networks:
      - elastic-net
    healthcheck:
      test: ["CMD-SHELL", "curl -s -u elastic:changeme http://localhost:9200/_cluster/health | grep -qE 'green|yellow'"]
      interval: 15s
      timeout: 10s
      retries: 10

  kibana01:
    image: docker.elastic.co/kibana/kibana:9.1.3
    container_name: kibana01
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://es01:9200
      - ELASTICSEARCH_USERNAME=elastic
      - ELASTICSEARCH_PASSWORD=changeme
      - XPACK_FLEET_ENABLED=true
      - XPACK_FLEET_AGENTS_ELASTICSEARCH_HOSTS=["http://es01:9200"]
      - XPACK_FLEET_AGENTS_FLEET_SERVER_HOSTS=["http://fleet-server:8220"]
    depends_on:
      es01:
        condition: service_healthy
    networks:
      - elastic-net

  logstash01:
    image: docker.elastic.co/logstash/logstash:9.1.3
    container_name: logstash01
    ports:
      - "514:514/udp"
      - "514:514/tcp"
      - "5000:5000/tcp"
      - "9600:9600"
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline:ro
      - ./logstash/pipelines.yml:/usr/share/logstash/config/pipelines.yml:ro
      - ./logstash/ettx-input:/usr/share/logstash/ettx-input
      - ./logstash/datasets:/usr/share/logstash/datasets:ro
      - scripts_ad-json-logs:/var/log/ad:ro
      - scripts_wsus-json-logs:/var/log/wsus:ro
      - scripts_proxy-json-logs:/var/log/proxy:ro
      - scripts_websrv-json-logs:/var/log/websrv:ro
    environment:
      - "LS_JAVA_OPTS=-Xms512m -Xmx512m"
    depends_on:
      es01:
        condition: service_healthy
    networks:
      - elastic-net

  fleet-server:
    image: docker.elastic.co/beats/elastic-agent:9.1.3
    container_name: fleet-server
    hostname: fleet-server
    restart: unless-stopped
    user: root
    environment:
      - FLEET_SERVER_ENABLE=true
      - FLEET_SERVER_ELASTICSEARCH_HOST=http://es01:9200
      - FLEET_SERVER_ELASTICSEARCH_USERNAME=elastic
      - FLEET_SERVER_ELASTICSEARCH_PASSWORD=changeme
      - FLEET_SERVER_SERVICE_TOKEN=${FLEET_SERVICE_TOKEN}
      - FLEET_SERVER_POLICY_ID=fleet-server-policy
      - FLEET_URL=http://fleet-server:8220
      - KIBANA_HOST=http://kibana01:5601
      - KIBANA_FLEET_SETUP=true
      - FLEET_SERVER_INSECURE_HTTP=true
    ports:
      - "8220:8220"
    depends_on:
      es01:
        condition: service_healthy
    networks:
      - elastic-net

  # One Elastic Agent per CNAS node — replaces all individual Beats
  agent-ad:
    image: docker.elastic.co/beats/elastic-agent:9.1.3
    container_name: agent-ad
    hostname: AD-CNAS-KOLEA
    restart: unless-stopped
    user: root
    environment:
      - FLEET_ENROLL=true
      - FLEET_URL=http://fleet-server:8220
      - FLEET_ENROLLMENT_TOKEN=${AD_ENROLLMENT_TOKEN}
      - FLEET_INSECURE=true
    volumes:
      - scripts_ad-json-logs:/var/log/ad:ro   # Agent can read CNAS container logs
    depends_on:
      - fleet-server
    networks:
      - elastic-net

  agent-wsus:
    image: docker.elastic.co/beats/elastic-agent:9.1.3
    container_name: agent-wsus
    hostname: WSUS-CNAS-KOLEA
    restart: unless-stopped
    user: root
    environment:
      - FLEET_ENROLL=true
      - FLEET_URL=http://fleet-server:8220
      - FLEET_ENROLLMENT_TOKEN=${WSUS_ENROLLMENT_TOKEN}
      - FLEET_INSECURE=true
    volumes:
      - scripts_wsus-json-logs:/var/log/wsus:ro
    depends_on:
      - fleet-server
    networks:
      - elastic-net

  agent-proxy:
    image: docker.elastic.co/beats/elastic-agent:9.1.3
    container_name: agent-proxy
    hostname: PROXY-CNAS-KOLEA
    restart: unless-stopped
    user: root
    environment:
      - FLEET_ENROLL=true
      - FLEET_URL=http://fleet-server:8220
      - FLEET_ENROLLMENT_TOKEN=${PROXY_ENROLLMENT_TOKEN}
      - FLEET_INSECURE=true
    volumes:
      - scripts_proxy-json-logs:/var/log/proxy:ro
    depends_on:
      - fleet-server
    networks:
      - elastic-net

  agent-websrv:
    image: docker.elastic.co/beats/elastic-agent:9.1.3
    container_name: agent-websrv
    hostname: WEBSRV-CNAS-KOLEA
    restart: unless-stopped
    user: root
    environment:
      - FLEET_ENROLL=true
      - FLEET_URL=http://fleet-server:8220
      - FLEET_ENROLLMENT_TOKEN=${WEBSRV_ENROLLMENT_TOKEN}
      - FLEET_INSECURE=true
    volumes:
      - scripts_websrv-json-logs:/var/log/websrv:ro
    depends_on:
      - fleet-server
    networks:
      - elastic-net

volumes:
  esdata:
    driver: local
  scripts_ad-json-logs:
    external: true
    name: scripts_ad-json-logs
  scripts_wsus-json-logs:
    external: true
    name: scripts_wsus-json-logs
  scripts_proxy-json-logs:
    external: true
    name: scripts_proxy-json-logs
  scripts_websrv-json-logs:
    external: true
    name: scripts_websrv-json-logs

networks:
  elastic-net:
    driver: bridge
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

### Create four Agent Policies in Kibana

`http://localhost:5601` → **Management** → **Fleet** → **Agent Policies** → **Create agent policy**

| Policy name | System integration | Custom log paths to add |
|-------------|-------------------|------------------------|
| `AD-CNAS Policy` | ✅ enabled | `/var/log/ad/*.json` |
| `WSUS-CNAS Policy` | ✅ enabled | `/var/log/wsus/*.json` |
| `PROXY-CNAS Policy` | ✅ enabled | `/var/log/proxy/*.json` |
| `WEBSRV-CNAS Policy` | ✅ enabled | `/var/log/websrv/*.json` |

Adding the custom log paths means Elastic Agent will ship the CNAS JSON logs directly to `logs-*`, in addition to system metrics. This removes the dependency on Logstash for live CNAS data.

### Start agents

```bash
# After copying enrollment tokens into .env:
docker compose up -d agent-ad agent-wsus agent-proxy agent-websrv

# Verify all four online
curl -s -u elastic:changeme "http://localhost:5601/api/fleet/agents?perPage=20" \
  -H "kbn-xsrf: true" \
  | python3 -c "
import sys, json
for a in json.load(sys.stdin).get('list', []):
    name = a.get('local_metadata', {}).get('host', {}).get('name', '?')
    print(f'  {name}: {a.get(\"status\",\"?\")}')
"
```

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
  # ── EVTX-ATTACK-SAMPLES / Sysmon NDJSON ──────────────────────────────────
  file {
    path => "/usr/share/logstash/ettx-input/*.json"
    start_position => "beginning"
    sincedb_path => "/usr/share/logstash/data/sincedb-ettx"
    codec => "json"
    tags => ["sysmon"]
  }

  # ── CNAS container telemetry (shared Docker volumes) ─────────────────────
  file { path => "/var/log/ad/ad-telemetry.json";     start_position => "beginning"; sincedb_path => "/usr/share/logstash/data/sincedb-ad";      codec => "json"; tags => ["ad-cnas",   "live"] }
  file { path => "/var/log/wsus/wsus-telemetry.json"; start_position => "beginning"; sincedb_path => "/usr/share/logstash/data/sincedb-wsus";    codec => "json"; tags => ["wsus-cnas", "live"] }
  file { path => "/var/log/proxy/proxy-telemetry.json"; start_position => "beginning"; sincedb_path => "/usr/share/logstash/data/sincedb-proxy"; codec => "json"; tags => ["proxy-cnas","live"] }
  file { path => "/var/log/websrv/websrv-telemetry.json"; start_position => "beginning"; sincedb_path => "/usr/share/logstash/data/sincedb-websrv"; codec => "json"; tags => ["websrv-cnas","live"] }

  # ── CICIDS 2017 network flows ─────────────────────────────────────────────
  file { path => "/usr/share/logstash/datasets/cicids2017/*.csv";         start_position => "beginning"; sincedb_path => "/usr/share/logstash/data/sincedb-cicids";     tags => ["cicids2017"] }
  file { path => "/usr/share/logstash/datasets/cicids-webattacks/*.csv";  start_position => "beginning"; sincedb_path => "/usr/share/logstash/data/sincedb-cicids-web"; tags => ["cicids-webattacks"] }

  # ── Faker auth events ─────────────────────────────────────────────────────
  file { path => "/usr/share/logstash/datasets/auth-cnas/*.ndjson"; start_position => "beginning"; sincedb_path => "/usr/share/logstash/data/sincedb-auth"; codec => "json"; tags => ["auth-cnas"] }

  # ── Syslog from CNAS containers ───────────────────────────────────────────
  udp { port => 514; tags => ["syslog-udp"] }
  tcp { port => 514; tags => ["syslog-tcp"] }
  tcp { port => 5000; codec => json_lines; tags => ["sysmon"] }
}

filter {
  # ── ECS: Sysmon / EVTX ───────────────────────────────────────────────────
  if "sysmon" in [tags] {
    if [EventID] or [event_id] {
      mutate {
        rename => {
          "EventID"         => "[event][code]"
          "event_id"        => "[event][code]"
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
      date { match => ["TimeCreated", "ISO8601", "yyyy-MM-dd HH:mm:ss"]; target => "@timestamp"; remove_field => ["TimeCreated"] }
    }
    # ECS classification by EventID
    if      [event][code] == "4625" { mutate { add_field => { "[event][category]" => "authentication" "[event][outcome]" => "failure"  } } }
    else if [event][code] == "4624" { mutate { add_field => { "[event][category]" => "authentication" "[event][outcome]" => "success"  } } }
    else if [event][code] == "4740" { mutate { add_field => { "[event][category]" => "iam"            "[event][outcome]" => "failure"  } } }
    else if [event][code] == "4662" { mutate { add_field => { "[event][category]" => "file"                                           } } }
    else if [event][code] == "4728" or [event][code] == "4732" { mutate { add_field => { "[event][category]" => "iam" "[event][type]" => "group" } } }
    else if [event][code] == "4769" { mutate { add_field => { "[event][category]" => "authentication"  "[event][dataset]" => "kerberos"} } }
    else if [event][code] == "4672" { mutate { add_field => { "[event][category]" => "authentication"  "[event][type]" => "admin"     } } }
    mutate { add_field => { "[event][module]" => "sysmon" "[labels][dataset]" => "sysmon" } }
  }

  # ── ECS: CICIDS 2017 network flows ───────────────────────────────────────
  if "cicids2017" in [tags] {
    csv {
      separator => ","
      skip_header => true
      columns => ["destination_port","flow_duration","total_fwd_packets","total_bwd_packets",
                  "total_length_fwd","total_length_bwd","flow_bytes_per_s","flow_packets_per_s","label"]
    }
    mutate {
      rename => {
        "destination_port"   => "[destination][port]"
        "flow_bytes_per_s"   => "[network][bytes]"
        "flow_packets_per_s" => "[network][packets]"
        "label"              => "_raw_label"
      }
      add_field => { "[event][category]" => "network" "[event][module]" => "cicids2017" "[labels][dataset]" => "network-cnas" "[host][name]" => "NETWORK-CNAS-KOLEA" }
    }
    if [_raw_label] == "BENIGN" { mutate { add_field => { "[event][outcome]" => "success" } } }
    else {
      mutate { add_field => { "[event][outcome]" => "failure" "[threat][tactic][name]" => "%{_raw_label}" } }
    }
    mutate { remove_field => ["_raw_label", "message", "host", "path"] }
  }

  # ── ECS: CICIDS Web Attacks ───────────────────────────────────────────────
  if "cicids-webattacks" in [tags] {
    csv {
      separator => ","
      skip_header => true
      columns => ["destination_port","flow_duration","flow_bytes_per_s","label"]
    }
    mutate {
      rename => {
        "destination_port" => "[destination][port]"
        "flow_bytes_per_s" => "[network][bytes]"
        "label"            => "_raw_label"
      }
      add_field => { "[event][category]" => "network" "[event][module]" => "cicids_webattacks" "[labels][dataset]" => "proxy-cnas" "[host][name]" => "PROXY-CNAS-KOLEA" }
    }
    if      [_raw_label] =~ /SQL/   { mutate { add_field => { "[event][code]" => "5002" "[event][outcome]" => "failure" "[threat][technique][name]" => "SQL Injection"       "[threat][tactic][name]" => "Initial Access" } } }
    else if [_raw_label] =~ /XSS/   { mutate { add_field => { "[event][code]" => "5003" "[event][outcome]" => "failure" "[threat][technique][name]" => "Cross-Site Scripting" "[threat][tactic][name]" => "Execution"     } } }
    else if [_raw_label] =~ /Brute/ { mutate { add_field => { "[event][code]" => "5001" "[event][outcome]" => "failure" "[threat][technique][name]" => "Brute Force"          "[threat][tactic][name]" => "Credential Access" } } }
    else if [_raw_label] == "BENIGN"{ mutate { add_field => { "[event][outcome]" => "success" } } }
    else                             { mutate { add_field => { "[event][outcome]" => "failure" "[threat][tactic][name]" => "%{_raw_label}" } } }
    mutate { remove_field => ["_raw_label", "message", "host", "path"] }
  }
}

output {
  if      "sysmon"            in [tags] { elasticsearch { hosts => ["http://es01:9200"]; user => "elastic"; password => "changeme"; index => "sysmon-%{+YYYY.MM.dd}";       manage_template => false } }
  else if "ad-cnas"           in [tags] { elasticsearch { hosts => ["http://es01:9200"]; user => "elastic"; password => "changeme"; index => "ad-cnas-%{+YYYY.MM.dd}";      manage_template => false } }
  else if "wsus-cnas"         in [tags] { elasticsearch { hosts => ["http://es01:9200"]; user => "elastic"; password => "changeme"; index => "wsus-cnas-%{+YYYY.MM.dd}";    manage_template => false } }
  else if "proxy-cnas"        in [tags] { elasticsearch { hosts => ["http://es01:9200"]; user => "elastic"; password => "changeme"; index => "proxy-cnas-%{+YYYY.MM.dd}";   manage_template => false } }
  else if "cicids-webattacks"  in [tags]{ elasticsearch { hosts => ["http://es01:9200"]; user => "elastic"; password => "changeme"; index => "proxy-cnas-%{+YYYY.MM.dd}";   manage_template => false } }
  else if "websrv-cnas"       in [tags] { elasticsearch { hosts => ["http://es01:9200"]; user => "elastic"; password => "changeme"; index => "websrv-cnas-%{+YYYY.MM.dd}";  manage_template => false } }
  else if "cicids2017"        in [tags] { elasticsearch { hosts => ["http://es01:9200"]; user => "elastic"; password => "changeme"; index => "network-cnas-%{+YYYY.MM.dd}"; manage_template => false } }
  else if "auth-cnas"         in [tags] { elasticsearch { hosts => ["http://es01:9200"]; user => "elastic"; password => "changeme"; index => "auth-cnas-%{+YYYY.MM.dd}";    manage_template => false } }
  else                                  { elasticsearch { hosts => ["http://es01:9200"]; user => "elastic"; password => "changeme"; index => "syslog-%{+YYYY.MM.dd}";        manage_template => false } }
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

# CICIDS 2017 — download MachineLearningCSV.zip from https://www.unb.ca/cic/datasets/ids-2017.html
cp ~/Downloads/MachineLearningCSV/*.csv ~/ELK/elk_stack/logstash/datasets/cicids2017/
cp ~/Downloads/MachineLearningCSV/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv \
   ~/ELK/elk_stack/logstash/datasets/cicids-webattacks/

# Faker auth events (script from Section 5.4)
python3 generate_auth.py > ~/ELK/elk_stack/logstash/datasets/auth-cnas/auth-events.ndjson
```

---

## 13. Phase 5 — CNAS Containers & Telemetry Scripts

### `docker-compose.cnas.yml`

```yaml
version: "3.8"

services:
  ad-cnas:
    image: ubuntu:22.04
    container_name: AD-CNAS-KOLEA
    hostname: AD-CNAS-KOLEA
    restart: unless-stopped
    volumes:
      - ./scripts/ad_telemetry.sh:/usr/local/bin/ad_telemetry.sh
      - ad-json-logs:/var/log
    command: >
      bash -c "
        apt-get update -qq && apt-get install -y -qq netcat-openbsd cron &&
        chmod +x /usr/local/bin/ad_telemetry.sh &&
        echo '*/5 * * * * /usr/local/bin/ad_telemetry.sh logstash01 514 >> /var/log/telemetry.log 2>&1' | crontab - &&
        cron && sleep 30 &&
        /usr/local/bin/ad_telemetry.sh logstash01 514 &&
        tail -f /var/log/telemetry.log"
    networks: [default, elk_stack_elastic-net]

  wsus-cnas:
    image: ubuntu:22.04
    container_name: WSUS-CNAS-KOLEA
    hostname: WSUS-CNAS-KOLEA
    restart: unless-stopped
    volumes:
      - ./scripts/wsus_telemetry.sh:/usr/local/bin/wsus_telemetry.sh
      - wsus-json-logs:/var/log     # ← must be wsus-json-logs
    command: >
      bash -c "
        apt-get update -qq && apt-get install -y -qq netcat-openbsd cron &&
        chmod +x /usr/local/bin/wsus_telemetry.sh &&
        echo '*/5 * * * * /usr/local/bin/wsus_telemetry.sh logstash01 514 >> /var/log/telemetry.log 2>&1' | crontab - &&
        cron && sleep 30 &&
        /usr/local/bin/wsus_telemetry.sh logstash01 514 &&
        tail -f /var/log/telemetry.log"
    networks: [default, elk_stack_elastic-net]

  proxy-cnas:
    image: ubuntu:22.04
    container_name: PROXY-CNAS-KOLEA
    hostname: PROXY-CNAS-KOLEA
    restart: unless-stopped
    volumes:
      - ./scripts/proxy_telemetry.sh:/usr/local/bin/proxy_telemetry.sh
      - proxy-json-logs:/var/log
    command: >
      bash -c "
        apt-get update -qq && apt-get install -y -qq netcat-openbsd cron &&
        chmod +x /usr/local/bin/proxy_telemetry.sh &&
        echo '*/5 * * * * /usr/local/bin/proxy_telemetry.sh logstash01 514 >> /var/log/telemetry.log 2>&1' | crontab - &&
        cron && sleep 30 &&
        /usr/local/bin/proxy_telemetry.sh logstash01 514 &&
        tail -f /var/log/telemetry.log"
    networks: [default, elk_stack_elastic-net]

  websrv-cnas:
    image: ubuntu:22.04
    container_name: WEBSRV-CNAS-KOLEA
    hostname: WEBSRV-CNAS-KOLEA
    restart: unless-stopped
    volumes:
      - ./scripts/webserver_telemetry.sh:/usr/local/bin/webserver_telemetry.sh
      - websrv-json-logs:/var/log
    command: >
      bash -c "
        apt-get update -qq && apt-get install -y -qq netcat-openbsd cron nginx &&
        chmod +x /usr/local/bin/webserver_telemetry.sh &&
        echo '*/5 * * * * /usr/local/bin/webserver_telemetry.sh logstash01 514 >> /var/log/telemetry.log 2>&1' | crontab - &&
        cron && sleep 30 &&
        /usr/local/bin/webserver_telemetry.sh logstash01 514 &&
        tail -f /var/log/telemetry.log"
    networks: [default, elk_stack_elastic-net]

volumes:
  ad-json-logs:    { name: scripts_ad-json-logs }
  wsus-json-logs:  { name: scripts_wsus-json-logs }
  proxy-json-logs: { name: scripts_proxy-json-logs }
  websrv-json-logs:{ name: scripts_websrv-json-logs }

networks:
  elk_stack_elastic-net:
    external: true
    name: elk_stack_elastic-net
```

### Telemetry script rules — two non-negotiable constraints

**Rule 1 — Single-line JSON only**

`codec => "json"` reads one line at a time. Any multi-line output (heredoc, pretty-printed JSON) causes `_jsonparsefailure` on every event.

```bash
# CORRECT
function emit_json() {
    local ts; ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
    echo "{\"@timestamp\":\"$ts\",\"event\":{\"code\":\"$1\",\"category\":\"$2\",\"outcome\":\"$3\",\"module\":\"ad_telemetry\"},\"host\":{\"name\":\"$HOSTNAME\"},\"message\":\"$4\",\"labels\":{\"dataset\":\"ad-cnas\",\"source\":\"telemetry-script\"}}" >> "$JSON_LOG"
}

# WRONG — heredoc is multi-line
function emit_json() {
    cat >> "$JSON_LOG" <<EOF
{
  "@timestamp": "$ts",
  ...
}
EOF
}
```

**Rule 2 — Never `grep -c "..." || echo "0"`**

`grep -c` exits 1 on zero matches. `|| echo "0"` prints a second line, inserting a newline inside the JSON string being built.

```bash
# CORRECT
count=$(grep -c "pattern" /var/log/auth.log || true)

# WRONG
count=$(grep -c "pattern" /var/log/auth.log || echo "0")
```

---

## 14. Phase 6 — Shared Volume Wiring

```bash
# Pre-create shared volumes before starting any containers
docker volume create scripts_ad-json-logs
docker volume create scripts_wsus-json-logs
docker volume create scripts_proxy-json-logs
docker volume create scripts_websrv-json-logs

# Verify Logstash can read the files
docker exec logstash01 ls -lh /var/log/ad/ /var/log/wsus/ /var/log/proxy/ /var/log/websrv/

# Clear sincedb to force Logstash to re-read all files from the beginning
# Run this any time you truncate a log file, fix a script, or want a clean re-ingest
MSYS_NO_PATHCONV=1 docker exec logstash01 sh -c "rm -f /usr/share/logstash/data/sincedb-*"
docker restart logstash01
```

---

## 15. Phase 7 — Ingest & Verify

### Run telemetry manually to populate indices

```bash
docker exec AD-CNAS-KOLEA bash /usr/local/bin/ad_telemetry.sh
docker exec WSUS-CNAS-KOLEA bash /usr/local/bin/wsus_telemetry.sh
docker exec PROXY-CNAS-KOLEA bash /usr/local/bin/proxy_telemetry.sh
docker exec WEBSRV-CNAS-KOLEA bash /usr/local/bin/webserver_telemetry.sh
sleep 30
```

### Check all indices

```bash
curl -s -u elastic:changeme \
  "http://localhost:9200/_cat/indices/sysmon-*,syslog-*,ad-cnas-*,wsus-cnas-*,proxy-cnas-*,websrv-cnas-*,network-cnas-*,auth-cnas-*?v&h=index,docs.count&s=index"
```

### ECS parse failure check (must be 0 for all)

```bash
for idx in ad-cnas wsus-cnas proxy-cnas websrv-cnas sysmon network-cnas auth-cnas; do
  COUNT=$(curl -s -u elastic:changeme "http://localhost:9200/${idx}-*/_count" \
    -H "Content-Type: application/json" \
    -d '{"query":{"term":{"tags":"_jsonparsefailure"}}}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))")
  echo "$idx _jsonparsefailure: $COUNT"
done
```

### Full delete and re-ingest cycle

```bash
# Disable wildcard delete protection (ES 9.x default)
curl -s -u elastic:changeme -X PUT "http://localhost:9200/_cluster/settings" \
  -H "Content-Type: application/json" \
  -d '{"persistent":{"action.destructive_requires_name":false}}'

curl -s -u elastic:changeme -X DELETE \
  "http://localhost:9200/ad-cnas-*,wsus-cnas-*,proxy-cnas-*,websrv-cnas-*,network-cnas-*,auth-cnas-*"

curl -s -u elastic:changeme -X PUT "http://localhost:9200/_cluster/settings" \
  -H "Content-Type: application/json" \
  -d '{"persistent":{"action.destructive_requires_name":true}}'

docker exec AD-CNAS-KOLEA truncate -s 0 /var/log/ad-telemetry.json
docker exec WSUS-CNAS-KOLEA truncate -s 0 /var/log/wsus-telemetry.json
docker exec PROXY-CNAS-KOLEA truncate -s 0 /var/log/proxy-telemetry.json
docker exec WEBSRV-CNAS-KOLEA truncate -s 0 /var/log/websrv-telemetry.json

MSYS_NO_PATHCONV=1 docker exec logstash01 sh -c "rm -f /usr/share/logstash/data/sincedb-*"
docker restart logstash01
```

---

## 16. Kibana Data Views

### Three data views — not one per server

The point of ECS normalization is that you can query across all sources at once. One unified view with KQL filters replaces ten separate per-server views.

**Create these three views in Stack Management → Data Views:**

| Data View name | Index pattern | Time field | What it covers |
|----------------|---------------|------------|----------------|
| **CNAS — All Sources** | `*-cnas-*,sysmon-*,auth-cnas-*` | `@timestamp` | Everything security-relevant. Your main investigation view. |
| **Fleet Telemetry** | `metrics-*,logs-*` | `@timestamp` | System health, resource usage, raw container logs from Elastic Agent. |
| **Raw Syslog** | `syslog-*` | `@timestamp` | Unprocessed syslog, used for debugging the pipeline. |

### Using the unified view effectively

Once you are in **CNAS — All Sources**, use KQL to scope by host, source, or event type instead of switching views:

```kql
# Scope to one machine (replaces a per-server data view)
host.name: "AD-CNAS-KOLEA"

# Scope to one data source
labels.dataset: "sysmon"
labels.dataset: "network-cnas"

# Authentication failures across all sources simultaneously
event.category: "authentication" and event.outcome: "failure"

# All MITRE-labeled events from any source
threat.tactic.name: *

# Specific tactic across all sources
threat.tactic.name: "Credential Access"

# Account lockouts
event.code: "4740"

# DCSync indicator
event.code: "4662"

# Kerberoasting
event.code: "4769"

# Web attacks (from CICIDS dataset)
threat.technique.name: "SQL Injection" or threat.technique.name: "Cross-Site Scripting"

# Cross-source correlation: what happened on the AD server in the last hour
host.name: "AD-CNAS-KOLEA" and event.category: "authentication"

# Events from the real datasets only (not simulated telemetry)
labels.dataset: "sysmon" or labels.dataset: "network-cnas" or labels.dataset: "proxy-cnas"

# ECS parse failures — should always be 0
tags: "_jsonparsefailure"
```

> **Note for EVTX historical data:** The EVTX-ATTACK-SAMPLES events have timestamps from 2020. When viewing `sysmon-*` data, set the Kibana time picker to a custom range that covers 2020, otherwise the events will not appear.

---

## 17. Phase 8 — Elastic Security & Detection Rules

This is the purpose of everything built so far. Elastic Security uses your ECS-normalized data to run detection rules and generate alerts.

### Enable Elastic Security

In Kibana → **Security** (left sidebar). If not visible:

```bash
# Enable Security solution in Kibana
curl -s -u elastic:changeme -X POST "http://localhost:5601/api/fleet/setup" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json"
```

Then navigate to **Security → Alerts**.

### Load Elastic's prebuilt detection rules

Elastic ships 600+ detection rules covering all MITRE ATT&CK tactics. All are written against ECS fields, so they work against your indexed data immediately.

```
Kibana → Security → Rules → Detection Rules → Add Elastic rules
```

Filter by relevant tags to load only what applies:

| Tag to filter | Rules it loads | Fires on your indices |
|--------------|----------------|----------------------|
| `Windows` | Windows EventID-based rules | `sysmon-*` (EVTX data) |
| `Credential Access` | Brute force, Kerberoasting, DCSync | `sysmon-*`, `auth-cnas-*` |
| `Lateral Movement` | Pass-the-Hash, explicit creds | `sysmon-*`, `auth-cnas-*` |
| `Network` | Anomalous connections, scanning | `network-cnas-*` |
| `Web Application Attack` | SQLi, XSS patterns | `proxy-cnas-*` |

Enable the rules and click **Run all rule previews** to see which ones fire against your existing indexed data.

### Critical rules to enable first

These will fire against the EVTX-ATTACK-SAMPLES data you already have indexed:

```
Windows: Account Lockout                          event.code: "4740"
Windows: High Number of Failed Logon Attempts     event.code: "4625"
Kerberoasting via Service Tickets                 event.code: "4769"
DCSync via Replication Services                   event.code: "4662"
Sensitive Privilege Use                           event.code: "4672"
Member Added to Security Group                    event.code: "4728"
```

### Write a custom detection rule

If a prebuilt rule does not exist for your scenario, create one:

```
Security → Rules → Create new rule → Custom query
```

Example — detect brute force (5+ failures from same IP in 5 minutes):

```
Index patterns: *-cnas-*, sysmon-*

KQL query:
event.code: "4625" and event.category: "authentication"

Group by: source.ip
Threshold: ≥ 5 events in 5 minutes

Severity: High
MITRE tactic: Credential Access
MITRE technique: T1110 Brute Force
```

Example — detect Kerberoasting (RC4 ticket with suspicious options):

```
KQL query:
event.code: "4769" and winlog.event_data.TicketEncryptionType: "0x17"

Threshold: ≥ 1
Severity: Critical
```

### How historical data validates live detection

```
1. EVTX file (real Kerberoasting from 2020) ingested → sysmon-* index
          ↓
2. Detection rule: event.code="4769" and TicketEncryptionType="0x17"
          ↓
3. Rule fires against historical data → alert generated → RULE IS VALIDATED
          ↓
4. Same rule runs every 5 minutes against ALL *-cnas-* indices
          ↓
5. Real Kerberoasting on a live Windows machine (same EventID pattern)
   → Elastic Agent ships the event → same index → same rule fires → alert
```

The historical data is the test bench. The same rule automatically covers live data because ECS is the shared language.

### Review alerts

```
Security → Alerts
```

Each alert shows: rule name, severity, host, timestamp, all ECS fields, MITRE tactic/technique, and a link to the full event in Discover.

---

## 18. Migration: Current State → Target Architecture

Steps are independent. Do them in any order.

### Step A — Add CICIDS 2017 network data

```bash
cp ~/Downloads/MachineLearningCSV/*.csv ~/ELK/elk_stack/logstash/datasets/cicids2017/
docker restart logstash01
sleep 30
curl -s -u elastic:changeme "http://localhost:9200/_cat/indices/network-cnas-*?v&h=index,docs.count"
```

### Step B — Add CICIDS Web Attacks

```bash
cp ~/Downloads/MachineLearningCSV/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv \
   ~/ELK/elk_stack/logstash/datasets/cicids-webattacks/
MSYS_NO_PATHCONV=1 docker exec logstash01 rm -f /usr/share/logstash/data/sincedb-cicids-web
docker restart logstash01
sleep 30
curl -s -u elastic:changeme "http://localhost:9200/_cat/indices/proxy-cnas-*?v&h=index,docs.count"
```

### Step C — Generate Faker auth events

```bash
pip install faker --break-system-packages
python3 generate_auth.py > ~/ELK/elk_stack/logstash/datasets/auth-cnas/auth-events.ndjson
MSYS_NO_PATHCONV=1 docker exec logstash01 rm -f /usr/share/logstash/data/sincedb-auth
docker restart logstash01
sleep 30
curl -s -u elastic:changeme "http://localhost:9200/_cat/indices/auth-cnas-*?v&h=index,docs.count"
```

### Step D — Enable Elastic Security detection rules

See [Phase 8](#17-phase-8--elastic-security--detection-rules). No pipeline changes required — rules run against existing indexed data.

---

## 19. Real Production Deployment

When you deploy on actual infrastructure instead of containers, the only thing that changes is the data source. The entire pipeline stays identical.

### On a real Windows machine (AD server, workstation)

```powershell
# Download Elastic Agent from https://www.elastic.co/downloads/elastic-agent
# Run as Administrator:
.\elastic-agent.exe install `
  --fleet-url=https://YOUR_FLEET_SERVER:8220 `
  --enrollment-token=YOUR_AD_TOKEN `
  --insecure
```

Elastic Agent on Windows automatically collects Windows Event Logs via the Windows integration — no scripts, no Logstash file inputs for this data source. Events flow in real time as `logs-winlog.*` data streams.

In Kibana Fleet UI → **Integrations** → **Windows** → add to the AD-CNAS Policy. This adds:
- Security Event Log (EventIDs 4624, 4625, 4740, 4769, 4662, etc.)
- System Event Log
- Application Event Log
- PowerShell operational log

### On a real Linux machine (proxy, web server)

```bash
curl -L -O https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-9.1.3-linux-x86_64.tar.gz
tar xzvf elastic-agent-9.1.3-linux-x86_64.tar.gz
cd elastic-agent-9.1.3-linux-x86_64
sudo ./elastic-agent install \
  --fleet-url=http://YOUR_FLEET_SERVER:8220 \
  --enrollment-token=YOUR_PROXY_TOKEN \
  --insecure
```

Add the **System** integration to collect `/var/log/auth.log`, `/var/log/syslog`, and system metrics.

For web servers, add the **Nginx** or **Apache** integration to collect access and error logs directly into the appropriate data streams.

### Detection rules carry over automatically

The same detection rules built against historical EVTX and CICIDS data will fire on real machine events immediately, because Elastic Agent on Windows produces the exact same ECS fields as the historical datasets.

---

## 20. Known Issues & Fixes

### `_jsonparsefailure` — heredoc multi-line JSON

Cause: `codec => "json"` reads line by line. Fix: single `echo` per event. See [Section 13](#13-phase-5--cnas-containers--telemetry-scripts).

### `grep -c || echo "0"` inserts newline into JSON

Cause: grep exits 1 on zero matches, `|| echo "0"` fires and adds a line. Fix: `|| true`.

### ES 9.x blocks wildcard index deletion

Cause: `action.destructive_requires_name: true` is default. Fix: temporarily disable, delete, re-enable. See [Section 15](#15-phase-7--ingest--verify).

### Git Bash path conversion on Windows

Fix: `export MSYS_NO_PATHCONV=1` in `~/.bashrc`.

### `/tmp` volume mounts fail on Docker Desktop Windows

Fix: use `/usr/share/logstash/ettx-input` and `/var/log/<service>` as mount targets.

### WSUS container mounting wrong volume

Earlier version mapped `websrv-json-logs` to WSUS. Must use `wsus-json-logs`. Fixed in current `docker-compose.cnas.yml`.

### Logstash sincedb prevents re-reading truncated files

Fix: delete `/usr/share/logstash/data/sincedb-*` and restart Logstash after any file truncation.

### EVTX historical data not visible in Kibana

Cause: Kibana default time range is "Last 15 minutes". EVTX data timestamps are from 2020. Fix: set time picker to custom range covering the event dates, or use **Absolute** with 2020-01-01 to 2021-01-01.

---

## 21. Troubleshooting Reference

### All containers at a glance

```bash
docker ps --format "table {{.Names}}\t{{.Status}}" \
  | grep -E "es01|kibana|logstash|fleet|agent|CNAS"
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

### Logstash errors

```bash
docker logs logstash01 2>&1 | grep -i "error\|exception\|parse" | tail -20
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

## 22. Credentials & Quick Reference

| Service | URL | Credentials |
|---------|-----|-------------|
| Elasticsearch | `http://localhost:9200` | `elastic` / `changeme` |
| Kibana + Elastic Security | `http://localhost:5601` | `elastic` / `changeme` |
| Fleet Server | `http://localhost:8220` | — |
| Logstash monitoring | `http://localhost:9600` | — |

### `.env` file template

```
FLEET_SERVICE_TOKEN=
AD_ENROLLMENT_TOKEN=
WSUS_ENROLLMENT_TOKEN=
PROXY_ENROLLMENT_TOKEN=
WEBSRV_ENROLLMENT_TOKEN=
```

> Add `.env` to `.gitignore`. Never commit tokens.

### Dataset download links

| Dataset | URL | Target index |
|---------|-----|-------------|
| EVTX-ATTACK-SAMPLES | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES | `sysmon-*` |
| CICIDS 2017 | https://www.unb.ca/cic/datasets/ids-2017.html | `network-cnas-*` |
| CICIDS Web Attacks | Same download → Thursday morning file | `proxy-cnas-*` |
| Faker | `pip install faker` | `auth-cnas-*` |

---

*ELK Stack 9.1.3 · Elastic Agent 9.1.3 · Elastic Security · Docker Desktop Windows · Ubuntu 22.04 CNAS containers*

*⚠️ Lab environment. Default credentials are intentional. Do not expose ports externally. Rotate credentials and enable TLS before any production or shared-network deployment.*
