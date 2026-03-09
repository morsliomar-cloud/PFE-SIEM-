# PFE-SIEM — ELK Stack 9.x CNAS Lab

A fully containerised SIEM lab built on **ELK Stack 9.1.3** with Elastic Agent Fleet, four CNAS simulation containers (AD, WSUS, Proxy, WebSrv), Logstash multi-pipeline ingestion, Sysmon EVTX replay, and the ETTX-ATTACKS dataset. Everything runs on Docker Desktop (Windows) or Docker Engine (Linux/macOS).

---

## Table of Contents

1. [Architecture](#1-architecture)
2. [Prerequisites](#2-prerequisites)
3. [Repository Layout](#3-repository-layout)
4. [Environment Setup](#4-environment-setup)
5. [Phase 1 — Start the ELK Core Stack](#5-phase-1--start-the-elk-core-stack)
6. [Phase 2 — Fleet Server & Agent Enrollment](#6-phase-2--fleet-server--agent-enrollment)
7. [Phase 3 — Logstash Multi-Pipeline & Sysmon Ingestion](#7-phase-3--logstash-multi-pipeline--sysmon-ingestion)
8. [Phase 4 — CNAS Containers & Telemetry Scripts](#8-phase-4--cnas-containers--telemetry-scripts)
9. [Phase 5 — Shared Volume Wiring (Logstash ↔ CNAS)](#9-phase-5--shared-volume-wiring-logstash--cnas)
10. [Phase 6 — Ingest & Verify All Data Streams](#10-phase-6--ingest--verify-all-data-streams)
11. [Kibana Data Views](#11-kibana-data-views)
12. [Known Issues & Fixes Applied](#12-known-issues--fixes-applied)
13. [Troubleshooting Reference](#13-troubleshooting-reference)
14. [Credentials & Key Config Reference](#14-credentials--key-config-reference)

---

## 1. Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Docker network: elk_stack_elastic-net                                  │
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐  │
│  │   es01       │◄───│  kibana01    │    │      fleet-server        │  │
│  │  :9200       │    │  :5601       │◄───│        :8220             │  │
│  └──────┬───────┘    └──────────────┘    └────────────┬─────────────┘  │
│         │                                             │                 │
│         │           ┌──────────────┐       ┌─────────┴──────────────┐  │
│         │◄──────────│  logstash01  │       │  agent-ad  agent-wsus  │  │
│         │           │  :514 UDP/TCP│       │  agent-proxy           │  │
│         │           │  :5000 TCP   │       │  agent-websrv          │  │
│         │           └──────┬───────┘       └────────────────────────┘  │
│         │                  │                                            │
│         │      ┌───────────┴────────────────────────────┐              │
│         │      │  Shared Docker Volumes                 │              │
│         │      │  scripts_ad-json-logs    → /var/log/ad  │              │
│         │      │  scripts_wsus-json-logs  → /var/log/wsus│              │
│         │      │  scripts_proxy-json-logs → /var/log/proxy│             │
│         │      │  scripts_websrv-json-logs→ /var/log/websrv│            │
│         │      └───────────┬────────────────────────────┘              │
│         │                  │ file input (codec json)                   │
└─────────┼──────────────────┼────────────────────────────────────────── ┘
          │                  │
┌─────────┼──────────────────┼───────────────────────────────────────────┐
│  Docker network: scripts_default (CNAS containers)                     │
│                  │                  │                                   │
│  ┌───────────────▼──┐  ┌───────────▼────────────────────────────────┐  │
│  │  AD-CNAS-KOLEA   │  │  WSUS-CNAS-KOLEA  PROXY-CNAS-KOLEA        │  │
│  │  WSUS/PROXY/WEB  │  │  WEBSRV-CNAS-KOLEA                        │  │
│  │  Telemetry cron  │  │  → write JSON to shared volume every 5min  │  │
│  │  → syslog UDP 514│  │  → syslog UDP 514                         │  │
│  └──────────────────┘  └───────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘

Data flows:
  CNAS containers → syslog UDP 514       → Logstash → syslog-* indices
  CNAS containers → JSON file (volume)   → Logstash → ad/wsus/proxy/websrv-cnas-* indices
  Sysmon NDJSON files → ettx-input/      → Logstash → sysmon-* indices
  Elastic Agents  → Fleet Server         → metrics-*/logs-* indices
```

### Elasticsearch Indices

| Index Pattern | Source | Description |
|--------------|--------|-------------|
| `syslog-*` | CNAS syslog UDP | Raw syslog from all 4 containers |
| `sysmon-*` | Sysmon EVTX NDJSON | Windows Sysmon events (ETTX dataset) |
| `ad-cnas-*` | AD JSON volume | Active Directory telemetry JSON |
| `wsus-cnas-*` | WSUS JSON volume | WSUS update telemetry JSON |
| `proxy-cnas-*` | Proxy JSON volume | Proxy/Squid telemetry JSON |
| `websrv-cnas-*` | WebSrv JSON volume | Nginx/Apache telemetry JSON |
| `logs-*` / `metrics-*` | Elastic Agents | Fleet-managed system metrics & logs |

---

## 2. Prerequisites

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| Docker Desktop (Windows) | 4.x | Enable WSL2 backend. Linux/macOS: Docker Engine 24+ |
| RAM allocated to Docker | 8 GB | ELK alone needs ~4–5 GB |
| Disk | 20 GB free | Elasticsearch data + images |
| Git Bash (Windows) | Any | Required — see Windows notes below |
| `curl` | Any | Included in Git Bash |

### Windows / Git Bash critical note

Docker Desktop on Windows with Git Bash auto-converts Linux paths (e.g. `/var/log` → `C:/Program Files/Git/var/log`). Add this permanently to prevent broken `docker exec` commands:

```bash
echo 'export MSYS_NO_PATHCONV=1' >> ~/.bashrc
source ~/.bashrc
```

**Do not use `/tmp` as a Docker volume target on Windows.** Docker Desktop maps container `/tmp` to Windows `%TEMP%`, which causes volume mount failures. This project uses `/usr/share/logstash/ettx-input` and `/var/log/<service>` instead.

---

## 3. Repository Layout

```
ELK/
├── elk_stack/                        # Main ELK docker-compose project
│   ├── docker-compose.yml            # es01, kibana01, logstash01, fleet-server, 4x agents
│   ├── .env                          # Tokens (never commit this)
│   ├── logstash/
│   │   ├── pipeline/
│   │   │   └── ettx-attacks.conf     # Multi-purpose Logstash pipeline
│   │   ├── pipelines.yml             # Multi-pipeline config
│   │   └── ettx-input/               # Drop Sysmon NDJSON files here
│   └── ...
│
└── scripts/                          # CNAS container docker-compose project
    ├── docker-compose.cnas.yml       # 4x CNAS containers + volume declarations
    └── scripts/                      # Telemetry scripts (copied into containers)
        ├── ad_telemetry.sh
        ├── wsus_telemetry.sh
        ├── proxy_telemetry.sh
        └── webserver_telemetry.sh
```

---

## 4. Environment Setup

### 4.1 Clone / set up project directories

```bash
# Your project root (adjust if different)
cd ~/ELK

# Confirm structure
ls elk_stack/
ls scripts/
```

### 4.2 Create the `.env` file

```bash
cat > ~/ELK/elk_stack/.env << 'EOF'
# ELK Stack environment variables
# Fill in tokens after completing Phase 2 Fleet setup

FLEET_SERVICE_TOKEN=
AD_ENROLLMENT_TOKEN=
WSUS_ENROLLMENT_TOKEN=
PROXY_ENROLLMENT_TOKEN=
WEBSRV_ENROLLMENT_TOKEN=
EOF
```

> ⚠️ **Never commit `.env` to git.** Add it to `.gitignore`:
> ```bash
> echo ".env" >> ~/ELK/elk_stack/.gitignore
> ```

### 4.3 Create required directories

```bash
mkdir -p ~/ELK/elk_stack/logstash/ettx-input
mkdir -p ~/ELK/elk_stack/logstash/pipeline
```

---

## 5. Phase 1 — Start the ELK Core Stack

### 5.1 `docker-compose.yml` — full reference

This is the complete working file. The key additions over a vanilla ELK compose are: Fleet Server, 4 Elastic Agents, external CNAS volumes, and the Sysmon input directory mount.

```yaml
# elk_stack/docker-compose.yml
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
    depends_on:
      - fleet-server
    networks:
      - elastic-net

volumes:
  esdata:
    driver: local
  fleet-server-state:
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

### 5.2 Start core services (ES + Kibana + Logstash)

```bash
cd ~/ELK/elk_stack

# Start only the core trio first — Fleet needs ES healthy before it starts
docker compose up -d es01 kibana01 logstash01

# Wait for Elasticsearch to be ready (takes ~30-60s)
until curl -s -u elastic:changeme http://localhost:9200/_cluster/health \
  | grep -qE '"status":"green"|"status":"yellow"'; do
  echo "Waiting for Elasticsearch..."; sleep 5
done
echo "✅ Elasticsearch ready"

# Wait for Kibana to be ready (takes ~60-90s)
until curl -s http://localhost:5601/api/status \
  | python3 -c "import sys,json; s=json.load(sys.stdin); exit(0 if s['status']['overall']['level']=='available' else 1)" 2>/dev/null; do
  echo "Waiting for Kibana..."; sleep 5
done
echo "✅ Kibana ready"
```

### 5.3 Verify core stack

```bash
# Elasticsearch cluster health
curl -s -u elastic:changeme "http://localhost:9200/_cluster/health?pretty" | grep '"status"'
# Expected: "status" : "green" or "yellow"

# Logstash pipelines active
docker exec logstash01 curl -s "http://localhost:9600/_node/pipelines?pretty" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('Pipelines:', list(d['pipelines'].keys()))"
# Expected: Pipelines: ['syslog', 'ettx-attacks']  (or similar)

# Logstash listening on syslog port
docker exec logstash01 ss -ulnp | grep 514
```

---

## 6. Phase 2 — Fleet Server & Agent Enrollment

### 6.1 Generate the Fleet Server service token

The service token lets Fleet Server authenticate to Elasticsearch. Generate it once before starting Fleet Server:

```bash
curl -s -u elastic:changeme \
  -X POST "http://localhost:9200/_security/service/elastic/fleet-server/credential/token/fleet-token-1" \
  -H "Content-Type: application/json" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['token']['value'])"
```

Copy the printed token value into `.env`:

```bash
# Edit elk_stack/.env — paste the token after FLEET_SERVICE_TOKEN=
nano ~/ELK/elk_stack/.env
```

### 6.2 Start Fleet Server

```bash
cd ~/ELK/elk_stack
docker compose up -d fleet-server

# Tail logs until you see "Fleet Server started"
docker logs -f fleet-server 2>&1 | grep -E "started|enrolled|error|WARN"
```

**Expected healthy output:**
```
{"log.level":"info","message":"Fleet Server started"}
{"log.level":"info","message":"Agent enrolled"}
```

**If Fleet Server keeps restarting**, check:
```bash
docker logs fleet-server 2>&1 | tail -30
# Common cause: FLEET_SERVICE_TOKEN missing or wrong in .env
# Fix: regenerate token, update .env, docker compose up -d fleet-server
```

### 6.3 Create Agent Policies in Kibana Fleet UI

Open `http://localhost:5601` → **Management** → **Fleet** → **Agent Policies** → **Create agent policy**

Create **four** policies with these exact names (the names are used to identify which token goes where):

| Policy Name | Description |
|-------------|-------------|
| `AD-CNAS Policy` | Active Directory container |
| `WSUS-CNAS Policy` | WSUS update server container |
| `PROXY-CNAS Policy` | Proxy/Squid container |
| `WEBSRV-CNAS Policy` | Web server container |

For each policy, leave **"Collect system logs and metrics"** enabled. This automatically adds the System integration (CPU, memory, process, auth logs).

### 6.4 Get enrollment tokens

In Fleet UI → **Enrollment tokens**, copy the token for each policy.

Then update `.env`:

```bash
# elk_stack/.env — fill in all four:
FLEET_SERVICE_TOKEN=<from step 6.1>
AD_ENROLLMENT_TOKEN=<token for AD-CNAS Policy>
WSUS_ENROLLMENT_TOKEN=<token for WSUS-CNAS Policy>
PROXY_ENROLLMENT_TOKEN=<token for PROXY-CNAS Policy>
WEBSRV_ENROLLMENT_TOKEN=<token for WEBSRV-CNAS Policy>
```

### 6.5 Start all four Elastic Agents

```bash
cd ~/ELK/elk_stack
docker compose up -d agent-ad agent-wsus agent-proxy agent-websrv

# Check enrollment status
docker logs agent-ad 2>&1 | grep -E "enrolled|error" | tail -5
docker logs agent-wsus 2>&1 | grep -E "enrolled|error" | tail -5
docker logs agent-proxy 2>&1 | grep -E "enrolled|error" | tail -5
docker logs agent-websrv 2>&1 | grep -E "enrolled|error" | tail -5
```

### 6.6 Verify agents are online

In Fleet UI → **Agents**, all four agents should show **Healthy** / **Online** status.

From the command line:
```bash
curl -s -u elastic:changeme \
  "http://localhost:5601/api/fleet/agents?perPage=20" \
  -H "kbn-xsrf: true" \
  | python3 -c "
import sys, json
agents = json.load(sys.stdin).get('list', [])
for a in agents:
    name = a.get('local_metadata', {}).get('host', {}).get('name', 'unknown')
    status = a.get('status', 'unknown')
    print(f'  {name}: {status}')
"
```

Expected:
```
  AD-CNAS-KOLEA: online
  WSUS-CNAS-KOLEA: online
  PROXY-CNAS-KOLEA: online
  WEBSRV-CNAS-KOLEA: online
```

---

## 7. Phase 3 — Logstash Multi-Pipeline & Sysmon Ingestion

### 7.1 `logstash/pipelines.yml`

This file tells Logstash to run both pipelines simultaneously:

```yaml
# elk_stack/logstash/pipelines.yml
- pipeline.id: syslog
  path.config: "/usr/share/logstash/pipeline/ettx-attacks.conf"
  pipeline.workers: 1
```

> **Note:** In this lab both syslog and Sysmon/CNAS ingestion are handled by a single pipeline file `ettx-attacks.conf` with multiple inputs. The pipeline ID name `syslog` is legacy — do not rename it as it affects sincedb state.

### 7.2 `logstash/pipeline/ettx-attacks.conf` — full reference

This single pipeline handles all five data sources:

```ruby
# elk_stack/logstash/pipeline/ettx-attacks.conf

input {
  # ── Sysmon EVTX NDJSON files (ETTX dataset) ──────────────────
  file {
    path => "/usr/share/logstash/ettx-input/*.json"
    start_position => "beginning"
    sincedb_path => "/usr/share/logstash/data/sincedb-ettx"
    codec => "json"
    tags => ["sysmon"]
  }

  # ── CNAS JSON telemetry from shared Docker volumes ────────────
  file {
    path => "/var/log/ad/ad-telemetry.json"
    start_position => "beginning"
    sincedb_path => "/usr/share/logstash/data/sincedb-ad"
    codec => "json"
    tags => ["ad-cnas", "live"]
  }
  file {
    path => "/var/log/wsus/wsus-telemetry.json"
    start_position => "beginning"
    sincedb_path => "/usr/share/logstash/data/sincedb-wsus"
    codec => "json"
    tags => ["wsus-cnas", "live"]
  }
  file {
    path => "/var/log/proxy/proxy-telemetry.json"
    start_position => "beginning"
    sincedb_path => "/usr/share/logstash/data/sincedb-proxy"
    codec => "json"
    tags => ["proxy-cnas", "live"]
  }
  file {
    path => "/var/log/websrv/websrv-telemetry.json"
    start_position => "beginning"
    sincedb_path => "/usr/share/logstash/data/sincedb-websrv"
    codec => "json"
    tags => ["websrv-cnas", "live"]
  }

  # ── Sysmon live TCP (replay / attack simulation) ──────────────
  tcp {
    port => 5000
    codec => json_lines
    tags => ["sysmon"]
  }

  # ── Syslog from CNAS containers (UDP 514) ─────────────────────
  udp {
    port => 514
    tags => ["syslog-udp"]
  }
  tcp {
    port => 514
    tags => ["syslog-tcp"]
  }
}

filter {
  # Sysmon ECS field mapping
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
          "ComputerName"    => "[host][name]"
          "AttackTactic"    => "[threat][tactic][name]"
          "AttackTechnique" => "[threat][technique][name]"
        }
      }
    }
    if [TimeCreated] {
      date {
        match => ["TimeCreated", "ISO8601", "yyyy-MM-dd HH:mm:ss"]
        target => "@timestamp"
        remove_field => ["TimeCreated"]
      }
    }
    mutate {
      add_field => { "[event][module]" => "sysmon" "[labels][dataset]" => "sysmon" }
    }
  }
}

output {
  if "sysmon" in [tags] {
    elasticsearch {
      hosts    => ["http://es01:9200"]
      user     => "elastic"
      password => "changeme"
      index    => "sysmon-%{+YYYY.MM.dd}"
      manage_template => false
    }
  } else if "ad-cnas" in [tags] {
    elasticsearch {
      hosts    => ["http://es01:9200"]
      user     => "elastic"
      password => "changeme"
      index    => "ad-cnas-%{+YYYY.MM.dd}"
      manage_template => false
    }
  } else if "wsus-cnas" in [tags] {
    elasticsearch {
      hosts    => ["http://es01:9200"]
      user     => "elastic"
      password => "changeme"
      index    => "wsus-cnas-%{+YYYY.MM.dd}"
      manage_template => false
    }
  } else if "proxy-cnas" in [tags] {
    elasticsearch {
      hosts    => ["http://es01:9200"]
      user     => "elastic"
      password => "changeme"
      index    => "proxy-cnas-%{+YYYY.MM.dd}"
      manage_template => false
    }
  } else if "websrv-cnas" in [tags] {
    elasticsearch {
      hosts    => ["http://es01:9200"]
      user     => "elastic"
      password => "changeme"
      index    => "websrv-cnas-%{+YYYY.MM.dd}"
      manage_template => false
    }
  } else {
    elasticsearch {
      hosts    => ["http://es01:9200"]
      user     => "elastic"
      password => "changeme"
      index    => "syslog-%{+YYYY.MM.dd}"
      manage_template => false
    }
  }
}
```

### 7.3 Ingest Sysmon EVTX files

Convert your `.evtx` files to NDJSON (one JSON object per line) and drop them into the input directory:

```bash
# Copy converted NDJSON files into the mount
cp /path/to/your/sysmon-events.json ~/ELK/elk_stack/logstash/ettx-input/

# Restart Logstash to pick them up
docker restart logstash01
sleep 30

# Verify Sysmon index was created
curl -s -u elastic:changeme \
  "http://localhost:9200/_cat/indices/sysmon-*?v&h=index,docs.count"
```

### 7.4 Test live TCP Sysmon injection

```bash
# Send a synthetic Sysmon event via TCP port 5000
echo '{"EventID":"4625","Username":"testuser","ComputerName":"TEST-PC","AttackTactic":"Credential Access"}' \
  | nc -w 1 localhost 5000

sleep 5
curl -s -u elastic:changeme "http://localhost:9200/sysmon-*/_count?pretty"
```

---

## 8. Phase 4 — CNAS Containers & Telemetry Scripts

### 8.1 `docker-compose.cnas.yml` — full reference

**Critical:** The WSUS container must mount `wsus-json-logs`, not `websrv-json-logs`. This was a bug in earlier versions.

```yaml
# scripts/docker-compose.cnas.yml
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
        apt-get update -qq &&
        apt-get install -y -qq netcat-openbsd cron &&
        chmod +x /usr/local/bin/ad_telemetry.sh &&
        echo '*/5 * * * * /usr/local/bin/ad_telemetry.sh logstash01 514 >> /var/log/telemetry.log 2>&1' | crontab - &&
        cron &&
        sleep 30 &&
        /usr/local/bin/ad_telemetry.sh logstash01 514 >> /var/log/telemetry.log 2>&1 &&
        tail -f /var/log/telemetry.log
      "
    networks:
      - default
      - elk_stack_elastic-net

  wsus-cnas:
    image: ubuntu:22.04
    container_name: WSUS-CNAS-KOLEA
    hostname: WSUS-CNAS-KOLEA
    restart: unless-stopped
    volumes:
      - ./scripts/wsus_telemetry.sh:/usr/local/bin/wsus_telemetry.sh
      - wsus-json-logs:/var/log        # ← must be wsus-json-logs, NOT websrv
    command: >
      bash -c "
        apt-get update -qq &&
        apt-get install -y -qq netcat-openbsd cron &&
        chmod +x /usr/local/bin/wsus_telemetry.sh &&
        echo '*/5 * * * * /usr/local/bin/wsus_telemetry.sh logstash01 514 >> /var/log/telemetry.log 2>&1' | crontab - &&
        cron &&
        sleep 30 &&
        /usr/local/bin/wsus_telemetry.sh logstash01 514 >> /var/log/telemetry.log 2>&1 &&
        tail -f /var/log/telemetry.log
      "
    networks:
      - default
      - elk_stack_elastic-net

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
        apt-get update -qq &&
        apt-get install -y -qq netcat-openbsd cron &&
        chmod +x /usr/local/bin/proxy_telemetry.sh &&
        echo '*/5 * * * * /usr/local/bin/proxy_telemetry.sh logstash01 514 >> /var/log/telemetry.log 2>&1' | crontab - &&
        cron &&
        sleep 30 &&
        /usr/local/bin/proxy_telemetry.sh logstash01 514 >> /var/log/telemetry.log 2>&1 &&
        tail -f /var/log/telemetry.log
      "
    networks:
      - default
      - elk_stack_elastic-net

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
        apt-get update -qq &&
        apt-get install -y -qq netcat-openbsd cron nginx &&
        chmod +x /usr/local/bin/webserver_telemetry.sh &&
        echo '*/5 * * * * /usr/local/bin/webserver_telemetry.sh logstash01 514 >> /var/log/telemetry.log 2>&1' | crontab - &&
        cron &&
        sleep 30 &&
        /usr/local/bin/webserver_telemetry.sh logstash01 514 >> /var/log/telemetry.log 2>&1 &&
        tail -f /var/log/telemetry.log
      "
    networks:
      - default
      - elk_stack_elastic-net

volumes:
  ad-json-logs:
    name: scripts_ad-json-logs
  wsus-json-logs:
    name: scripts_wsus-json-logs
  proxy-json-logs:
    name: scripts_proxy-json-logs
  websrv-json-logs:
    name: scripts_websrv-json-logs

networks:
  elk_stack_elastic-net:
    external: true
    name: elk_stack_elastic-net
```

### 8.2 Telemetry script requirements

Each script must:
1. Write **single-line JSON** (one complete JSON object per line, no newlines inside)
2. Use `grep -c "..." || true` (never `grep -c "..." || echo "0"` — see [Known Issues](#12-known-issues--fixes-applied))
3. Write to the correct JSON log path for its container

The four scripts are in `scripts/scripts/`. Their key properties:

| Script | Container | JSON log path | ES index |
|--------|-----------|---------------|----------|
| `ad_telemetry.sh` | AD-CNAS-KOLEA | `/var/log/ad-telemetry.json` | `ad-cnas-*` |
| `wsus_telemetry.sh` | WSUS-CNAS-KOLEA | `/var/log/wsus-telemetry.json` | `wsus-cnas-*` |
| `proxy_telemetry.sh` | PROXY-CNAS-KOLEA | `/var/log/proxy-telemetry.json` | `proxy-cnas-*` |
| `webserver_telemetry.sh` | WEBSRV-CNAS-KOLEA | `/var/log/websrv-telemetry.json` | `websrv-cnas-*` |

### 8.3 Start CNAS containers

```bash
cd ~/ELK/scripts

# The external volumes must exist before starting
# They are created automatically when CNAS containers start, OR you can pre-create them:
docker volume create scripts_ad-json-logs
docker volume create scripts_wsus-json-logs
docker volume create scripts_proxy-json-logs
docker volume create scripts_websrv-json-logs

docker compose -f docker-compose.cnas.yml up -d

# Verify all four are running
docker ps --filter "name=CNAS" --format "table {{.Names}}\t{{.Status}}"
```

### 8.4 Verify telemetry scripts are producing valid JSON

```bash
# Wait ~35 seconds for startup sleep + first run, then check each log
sleep 35

docker exec AD-CNAS-KOLEA tail -3 /var/log/ad-telemetry.json
docker exec WSUS-CNAS-KOLEA tail -3 /var/log/wsus-telemetry.json
docker exec PROXY-CNAS-KOLEA tail -3 /var/log/proxy-telemetry.json
docker exec WEBSRV-CNAS-KOLEA tail -3 /var/log/websrv-telemetry.json
```

Each line must look like one single unbroken JSON object:
```json
{"@timestamp":"2026-03-09T21:15:17.000Z","event":{"code":"4625","category":"authentication","outcome":"failure","module":"ad_telemetry"},"host":{"name":"AD-CNAS-KOLEA"},"message":"Failed login attempts: 0","labels":{"dataset":"ad-cnas","source":"telemetry-script"}}
```

If you see multi-line output like `}` on its own line, the script is still using the old heredoc format. See [Known Issues #1](#issue-1-jsonparsefailure--multi-line-json).

---

## 9. Phase 5 — Shared Volume Wiring (Logstash ↔ CNAS)

The CNAS containers write JSON to shared Docker volumes. Logstash reads from those same volumes. Both projects must reference the volumes by the same name.

### 9.1 Verify volumes exist and are named correctly

```bash
docker volume ls | grep scripts_
```

Expected:
```
local     scripts_ad-json-logs
local     scripts_proxy-json-logs
local     scripts_websrv-json-logs
local     scripts_wsus-json-logs
```

### 9.2 Verify Logstash can see the files

```bash
docker exec logstash01 ls -lh /var/log/ad/
docker exec logstash01 ls -lh /var/log/wsus/
docker exec logstash01 ls -lh /var/log/proxy/
docker exec logstash01 ls -lh /var/log/websrv/
```

Each directory should contain a `*-telemetry.json` file with a recent modification time.

### 9.3 Clear sincedb to force re-read (after script fixes or log truncation)

Logstash tracks file read positions in sincedb files. If you truncate a log file or fix a broken script, you must clear sincedb and restart Logstash or it won't re-read:

```bash
MSYS_NO_PATHCONV=1 docker exec logstash01 sh -c \
  "rm -f /usr/share/logstash/data/sincedb-ad \
         /usr/share/logstash/data/sincedb-wsus \
         /usr/share/logstash/data/sincedb-proxy \
         /usr/share/logstash/data/sincedb-websrv \
         /usr/share/logstash/data/sincedb-ettx"

docker restart logstash01
```

---

## 10. Phase 6 — Ingest & Verify All Data Streams

### 10.1 Run telemetry scripts manually (force first events)

```bash
docker exec AD-CNAS-KOLEA bash /usr/local/bin/ad_telemetry.sh
docker exec WSUS-CNAS-KOLEA bash /usr/local/bin/wsus_telemetry.sh
docker exec PROXY-CNAS-KOLEA bash /usr/local/bin/proxy_telemetry.sh
docker exec WEBSRV-CNAS-KOLEA bash /usr/local/bin/webserver_telemetry.sh
```

### 10.2 Wait for Logstash to ingest, then check indices

```bash
sleep 30

curl -s -u elastic:changeme \
  "http://localhost:9200/_cat/indices/ad-cnas-*,wsus-cnas-*,proxy-cnas-*,websrv-cnas-*,sysmon-*,syslog-*?v&h=index,docs.count,store.size&s=index"
```

Expected output (dates will vary):
```
index                  docs.count store.size
ad-cnas-2026.03.09             13       45kb
proxy-cnas-2026.03.09          14       52kb
syslog-2026.03.09            1688      1.2mb
sysmon-2026.03.09             696      2.1mb
websrv-cnas-2026.03.09        15       55kb
wsus-cnas-2026.03.09          14       50kb
```

### 10.3 Verify no `_jsonparsefailure` events

```bash
# Check each CNAS index for parse failures
for idx in ad-cnas wsus-cnas proxy-cnas websrv-cnas; do
  COUNT=$(curl -s -u elastic:changeme \
    "http://localhost:9200/${idx}-*/_count" \
    -H "Content-Type: application/json" \
    -d '{"query":{"term":{"tags":"_jsonparsefailure"}}}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))")
  echo "$idx: $COUNT parse failures"
done
```

All counts should be `0`. If any are non-zero, see [Known Issues #1](#issue-1-jsonparsefailure--multi-line-json).

### 10.4 Delete corrupted indices and re-ingest (if needed)

ES 9.x blocks wildcard deletes by default. Use this sequence:

```bash
# Step 1: Temporarily allow wildcard deletes
curl -s -u elastic:changeme \
  -X PUT "http://localhost:9200/_cluster/settings" \
  -H "Content-Type: application/json" \
  -d '{"persistent": {"action.destructive_requires_name": false}}'

# Step 2: Delete all CNAS indices
curl -s -u elastic:changeme \
  -X DELETE "http://localhost:9200/ad-cnas-*,wsus-cnas-*,proxy-cnas-*,websrv-cnas-*"

# Step 3: Re-enable protection
curl -s -u elastic:changeme \
  -X PUT "http://localhost:9200/_cluster/settings" \
  -H "Content-Type: application/json" \
  -d '{"persistent": {"action.destructive_requires_name": true}}'

# Step 4: Truncate log files so new clean data starts fresh
docker exec AD-CNAS-KOLEA truncate -s 0 /var/log/ad-telemetry.json
docker exec WSUS-CNAS-KOLEA truncate -s 0 /var/log/wsus-telemetry.json
docker exec PROXY-CNAS-KOLEA truncate -s 0 /var/log/proxy-telemetry.json
docker exec WEBSRV-CNAS-KOLEA truncate -s 0 /var/log/websrv-telemetry.json

# Step 5: Clear sincedb (Logstash won't re-read without this)
MSYS_NO_PATHCONV=1 docker exec logstash01 sh -c \
  "rm -f /usr/share/logstash/data/sincedb-ad \
         /usr/share/logstash/data/sincedb-wsus \
         /usr/share/logstash/data/sincedb-proxy \
         /usr/share/logstash/data/sincedb-websrv"

# Step 6: Run scripts to generate fresh clean JSON
docker exec AD-CNAS-KOLEA bash /usr/local/bin/ad_telemetry.sh
docker exec WSUS-CNAS-KOLEA bash /usr/local/bin/wsus_telemetry.sh
docker exec PROXY-CNAS-KOLEA bash /usr/local/bin/proxy_telemetry.sh
docker exec WEBSRV-CNAS-KOLEA bash /usr/local/bin/webserver_telemetry.sh

# Step 7: Restart Logstash and verify
docker restart logstash01
sleep 30
curl -s -u elastic:changeme \
  "http://localhost:9200/_cat/indices/ad-cnas-*,wsus-cnas-*,proxy-cnas-*,websrv-cnas-*?v&h=index,docs.count"
```

---

## 11. Kibana Data Views

Create one data view per index pattern in Kibana → **Stack Management** → **Data Views** → **Create data view**.

| Data View Name | Index Pattern | Time Field |
|----------------|---------------|------------|
| Sysmon Events | `sysmon-*` | `@timestamp` |
| Syslog | `syslog-*` | `@timestamp` |
| AD Telemetry | `ad-cnas-*` | `@timestamp` |
| WSUS Telemetry | `wsus-cnas-*` | `@timestamp` |
| Proxy Telemetry | `proxy-cnas-*` | `@timestamp` |
| WebSrv Telemetry | `websrv-cnas-*` | `@timestamp` |
| Fleet Metrics | `metrics-*` | `@timestamp` |
| Fleet Logs | `logs-*` | `@timestamp` |

> **Time filter note:** Sysmon EVTX files from the ETTX dataset contain events from 2020. When exploring these in Discover, set the time filter to **2020** or use **"All time"** — the default "Last 15 minutes" will show nothing.

### Useful KQL queries

```kql
# All failed authentication events
event.code: "4625"

# Account lockouts (brute force indicator)
event.code: "4740"

# Privilege escalation via group changes
event.code: "4728" or event.code: "4732"

# DCSync / credential dumping indicator
event.code: "4662"

# Kerberos ticket requests
event.code: "4769"

# All events from AD container
host.name: "AD-CNAS-KOLEA"

# Events with MITRE ATT&CK labels
threat.tactic.name: *

# Sysmon events only
labels.dataset: "sysmon"

# Events with parse failures (should be 0 after fixes)
tags: "_jsonparsefailure"
```

---

## 12. Known Issues & Fixes Applied

This section documents every real bug encountered and how it was resolved, so you can understand why things are configured the way they are.

---

### Issue 1: `_jsonparsefailure` — Multi-line JSON

**Root cause:** Logstash `codec => "json"` reads files **line by line**. The original `emit_json()` function in all scripts used a bash heredoc (`cat >> $FILE << EOF ... EOF`) which wrote JSON spread across multiple lines. Logstash saw each line as a separate event, producing `_jsonparsefailure` for partial JSON fragments like a lone `}`.

**Symptom in Kibana:** Events with `tags: "_jsonparsefailure"` and `message: "}"` appearing in CNAS indices.

**Fix:** Rewrote `emit_json()` in all four scripts to use a single `echo` statement that outputs the entire JSON object on one line:

```bash
# WRONG — heredoc writes multi-line JSON
function emit_json() {
    cat >> "$JSON_LOG" <<EOF
{
  "@timestamp": "$ts",
  "event": { ... }
}
EOF
}

# CORRECT — single echo writes one-line JSON
function emit_json() {
    local event_code=$1 category=$2 outcome=$3 message=$4
    local ts; ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
    echo "{\"@timestamp\":\"$ts\",\"event\":{\"code\":\"$event_code\",...}}" >> "$JSON_LOG"
}
```

---

### Issue 2: `grep -c "..." || echo "0"` splits JSON across lines

**Root cause:** `grep -c` always outputs a number and exits with code `1` when the count is zero (no matches). The pattern `grep -c "pattern" || echo "0"` was intended as a safe fallback, but when grep finds 0 matches it exits 1, triggering `|| echo "0"`. This means the variable gets assigned `0\n0` — **two lines** — which, when embedded in a JSON string mid-construction, inserts a literal newline and breaks the JSON.

**Symptom in Logstash logs:**
```
JSON parse error: Unexpected end-of-input: was expecting closing quote for a string value
data: "...\"message\":\"Outbound connections to Microsoft Update: 0"
data: "0\",\"labels\":..."
```

**Fix:** Replace `grep -c "..." || echo "0"` with `grep -c "..." || true` everywhere. The `|| true` resets the exit code to 0 without printing anything, so no extra output is produced.

```bash
# WRONG
ms_connections=$(ss -tun 2>/dev/null | grep -c ":443\|:80" || echo "0")

# CORRECT
ms_connections=$(ss -tun 2>/dev/null | grep -c ":443\|:80" || true)
```

This affected over 30 lines across all four scripts. See current script files for the corrected versions.

---

### Issue 3: ES 9.x blocks wildcard index deletion

**Root cause:** Elasticsearch 9.x ships with `action.destructive_requires_name: true` by default, blocking wildcard patterns in DELETE requests.

**Symptom:**
```json
{"error":{"type":"illegal_argument_exception","reason":"Wildcard expressions or all indices are not allowed"}}
```

**Fix:** Temporarily disable the protection, delete, then re-enable:

```bash
# Disable
curl -s -u elastic:changeme -X PUT "http://localhost:9200/_cluster/settings" \
  -H "Content-Type: application/json" \
  -d '{"persistent": {"action.destructive_requires_name": false}}'

# Wildcard delete
curl -s -u elastic:changeme -X DELETE \
  "http://localhost:9200/ad-cnas-*,wsus-cnas-*,proxy-cnas-*,websrv-cnas-*"

# Re-enable
curl -s -u elastic:changeme -X PUT "http://localhost:9200/_cluster/settings" \
  -H "Content-Type: application/json" \
  -d '{"persistent": {"action.destructive_requires_name": true}}'
```

---

### Issue 4: Docker Desktop Windows path conversion in Git Bash

**Root cause:** Git Bash on Windows automatically converts Unix-style paths in shell arguments to Windows paths. A command like `docker exec container ls /var/log` becomes `docker exec container ls C:/Program Files/Git/var/log` internally, causing "No such file or directory" errors.

**Fix:** Set `MSYS_NO_PATHCONV=1` before any docker exec command with Unix paths, or permanently in `~/.bashrc`:

```bash
echo 'export MSYS_NO_PATHCONV=1' >> ~/.bashrc
source ~/.bashrc
```

---

### Issue 5: `/tmp` volume mounts fail on Docker Desktop Windows

**Root cause:** Docker Desktop on Windows maps the container `/tmp` directory to the Windows `%TEMP%` folder via a special mount. When you specify `/tmp` as a volume mount target in `docker-compose.yml`, Docker Desktop intercepts and redirects it, preventing the volume from working correctly.

**Fix:** All volume mounts and Logstash input paths use non-`/tmp` paths:
- Sysmon input: `/usr/share/logstash/ettx-input` instead of `/tmp/ettx-input`
- sincedb files: `/usr/share/logstash/data/sincedb-*` instead of `/tmp/sincedb-*`

---

### Issue 6: WSUS container was mounted to wrong volume

**Root cause:** An earlier version of `docker-compose.cnas.yml` had the WSUS container mounting `websrv-json-logs` (the WebSrv volume) instead of `wsus-json-logs`. Both the WSUS JSON log and WebSrv JSON log ended up in the same volume, causing cross-contamination in Logstash's `/var/log/websrv/` directory.

**Symptom:** `docker exec logstash01 ls /var/log/websrv/` showed `wsus-telemetry.json` in the WebSrv directory.

**Fix:** Corrected the volume mapping in `docker-compose.cnas.yml` to use the right named volume for each container.

---

### Issue 7: Script corruption from in-place heredoc patching

**Root cause:** An attempt to patch `emit_json()` using `sed -i '/^function emit_json/,/^}/c\...'` left a stray `EOF` marker and orphaned `)` inside the script, because the script had two definitions of `emit_json` and the regex matched the wrong boundary.

**Symptom:**
```
/usr/local/bin/ad_telemetry.sh: line 19: EOF: command not found
/usr/local/bin/ad_telemetry.sh: line 20: syntax error near unexpected token ')'
```

**Fix:** Scripts were fully rewritten from scratch rather than patched in-place and redeployed via `docker cp`.

---

### Issue 8: Logstash sincedb prevents re-reading fixed files

**Root cause:** Logstash records the byte offset of every file it has read in sincedb. When you fix a script and truncate the log file, Logstash's sincedb still shows the old file offset (e.g., 12,000 bytes). Since the file is now 0 bytes, Logstash sees nothing new to read.

**Fix:** Delete sincedb files and restart Logstash whenever you truncate a monitored file:

```bash
MSYS_NO_PATHCONV=1 docker exec logstash01 sh -c \
  "rm -f /usr/share/logstash/data/sincedb-ad \
         /usr/share/logstash/data/sincedb-wsus \
         /usr/share/logstash/data/sincedb-proxy \
         /usr/share/logstash/data/sincedb-websrv"
docker restart logstash01
```

---

## 13. Troubleshooting Reference

### Check all container states at once

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" \
  --filter "name=es01|kibana01|logstash01|fleet-server|agent-|AD-CNAS|WSUS-CNAS|PROXY-CNAS|WEBSRV-CNAS"
```

### Elasticsearch won't start

```bash
docker logs es01 | tail -30
# Common causes:
# - Not enough memory: increase Docker Desktop memory to 8GB+
# - Data directory permissions: docker volume rm esdata (loses data) then restart
```

### Fleet Server keeps restarting

```bash
docker logs fleet-server 2>&1 | tail -20
# Check .env has FLEET_SERVICE_TOKEN set correctly
# Try regenerating: curl -X POST http://localhost:9200/_security/service/elastic/fleet-server/credential/token/fleet-token-2
```

### Agents show Offline in Fleet UI

```bash
# Check agent can reach fleet server
docker exec agent-ad curl -s http://fleet-server:8220/api/status

# Check enrollment token is valid (not expired or for wrong policy)
docker logs agent-ad 2>&1 | grep -i "error\|token\|enroll" | tail -20

# Re-enroll manually
docker exec agent-ad elastic-agent enroll \
  --url=http://fleet-server:8220 \
  --enrollment-token=<your_token> \
  --insecure
```

### Logstash not creating indices

```bash
# Check pipeline is running
docker exec logstash01 curl -s http://localhost:9600/_node/pipelines?pretty \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(list(d['pipelines'].keys()))"

# Check for errors
docker logs logstash01 2>&1 | grep -i "error\|exception\|failed" | tail -20

# Check Logstash can reach Elasticsearch
docker exec logstash01 curl -s -u elastic:changeme http://es01:9200/_cluster/health
```

### JSON parse errors in Logstash logs

```bash
docker logs logstash01 2>&1 | grep "JSON parse error" | tail -10
# If you see this, check the data field — it will show the broken JSON line
# Most likely cause: grep -c ... || echo "0" pattern in telemetry scripts
# Fix: replace all '|| echo "0"' after grep -c with '|| true'
```

### Check what a telemetry script actually writes

```bash
# Verify JSON is single-line (each line must be one complete object)
docker exec AD-CNAS-KOLEA python3 -c "
import json, sys
with open('/var/log/ad-telemetry.json') as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if not line: continue
        try:
            json.loads(line)
            print(f'Line {i}: OK')
        except json.JSONDecodeError as e:
            print(f'Line {i}: BROKEN — {e}')
"
```

### Completely reset and start fresh

```bash
# Stop everything
cd ~/ELK/elk_stack && docker compose down
cd ~/ELK/scripts && docker compose -f docker-compose.cnas.yml down

# Remove volumes (WARNING: deletes all Elasticsearch data)
docker volume rm esdata scripts_ad-json-logs scripts_wsus-json-logs \
  scripts_proxy-json-logs scripts_websrv-json-logs fleet-server-state

# Restart from Phase 1
cd ~/ELK/elk_stack && docker compose up -d es01 kibana01 logstash01
```

---

## 14. Credentials & Key Config Reference

| Service | URL | Username | Password |
|---------|-----|----------|----------|
| Elasticsearch | `http://localhost:9200` | `elastic` | `changeme` |
| Kibana | `http://localhost:5601` | `elastic` | `changeme` |
| Fleet Server | `http://localhost:8220` | — | — |
| Logstash monitoring API | `http://localhost:9600` | — | — |

### Fleet Policy IDs (set after Fleet setup — yours may differ)

| Policy | ID |
|--------|----|
| AD-CNAS Policy | `196abfa5-51c7-489e-92fc-26796fc3159a` |
| WSUS-CNAS Policy | `79099c35-ce56-4459-bef0-834e4c36cb60` |
| PROXY-CNAS Policy | `a9170b2a-2680-469d-af8a-caf67c02937e` |
| WEBSRV-CNAS Policy | `c9641f5f-68eb-473f-b540-a5fc08035f92` |

> Policy IDs are not portable — they will be different in a fresh deployment. Always get them from your Kibana Fleet UI.

### Quick health check — one command

```bash
echo "=== Elasticsearch ===" && \
curl -s -u elastic:changeme "http://localhost:9200/_cluster/health" | python3 -c "import sys,json; d=json.load(sys.stdin); print('Status:', d['status'], '| Nodes:', d['number_of_nodes'])" && \
echo "=== Indices ===" && \
curl -s -u elastic:changeme "http://localhost:9200/_cat/indices/sysmon-*,syslog-*,ad-cnas-*,wsus-cnas-*,proxy-cnas-*,websrv-cnas-*?h=index,docs.count&s=index" && \
echo "=== Fleet Agents ===" && \
curl -s -u elastic:changeme "http://localhost:5601/api/fleet/agents?perPage=10" -H "kbn-xsrf: true" | python3 -c "
import sys, json
for a in json.load(sys.stdin).get('list', []):
    print(' ', a.get('local_metadata',{}).get('host',{}).get('name','?'), '->', a.get('status','?'))
"
```

---

*ELK Stack 9.1.3 · Elastic Agent 9.1.3 · Ubuntu 22.04 CNAS containers · Docker Desktop Windows*

*⚠️ Lab environment — security is intentionally minimal (`xpack.security.enabled=true` with default credentials). Enable TLS, rotate credentials, and harden Fleet Server before any production use.*
