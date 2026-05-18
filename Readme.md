# PFE-SIEM — ELK Stack · CNAS Lab

A containerised SIEM lab built on **Elastic Stack**, simulating four CNAS agency nodes (AD, WSUS, Proxy, WebSrv), shipping live telemetry through Elastic Agent and Logstash, and running real-time attack detection via Elastic Security — all normalised to the **Elastic Common Schema (ECS)** and secured end-to-end with TLS.

> Built as a final-year project (PFE) to demonstrate a production-grade SIEM workflow on a single host. Detection rules written against this lab fire unchanged on real CNAS infrastructure — the only thing that changes is the data source.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Data Tiers — Production vs Lab](#3-data-tiers--production-vs-lab)
4. [Component Responsibilities](#4-component-responsibilities)
5. [ECS Normalisation](#5-ecs-normalisation)
6. [Indices & Data Streams Reference](#6-indices--data-streams-reference)
7. [Prerequisites](#7-prerequisites)
8. [Repository Layout](#8-repository-layout)
9. [Phase 1 — Core Stack (Elasticsearch, Kibana, Logstash)](#9-phase-1--core-stack)
10. [Phase 2 — Fleet Server & Agent Enrollment](#10-phase-2--fleet-server--agent-enrollment)
11. [Phase 3 — Logstash Syslog Pipeline](#11-phase-3--logstash-syslog-pipeline)
12. [Phase 4 — CNAS Service Containers (Squid & Nginx)](#12-phase-4--cnas-service-containers)
13. [Phase 5 — Windows VMs (AD & WSUS)](#13-phase-5--windows-vms)
14. [Phase 6 — VirtualBox Networking for VM ↔ Docker](#14-phase-6--virtualbox-networking)
15. [Phase 7 — Detection Rules & Elastic Security](#15-phase-7--detection-rules)
16. [Post-Deployment Hardening](#16-post-deployment-hardening)
17. [Operations & Verification](#17-operations--verification)
18. [Troubleshooting](#18-troubleshooting)
19. [Credentials & Quick Reference](#19-credentials--quick-reference)

---

## 1. Project Overview

**Goal.** Build a fully working SIEM that ingests real Windows Event Logs, real proxy access logs, real web-server access logs, endpoint telemetry from Elastic Defend, and arbitrary syslog — then detects attacks against all of them with prebuilt and custom rules.

**What's running.**

| Layer | Component | Version | Role |
|---|---|---|---|
| Storage & search | Elasticsearch | 9.1.3 | Indexes all telemetry, hosts detection engine |
| Visualisation | Kibana + Elastic Security | 9.1.3 | Dashboards, alerting, SOC workflow |
| Stream processor | Logstash | 9.1.3 | Receives raw syslog on UDP/TCP 514 |
| Agent fleet | Fleet Server | 9.1.3 | Manages agent policies and enrollment |
| Endpoints | Elastic Agent + Elastic Defend | 9.1.3 | Ships logs and endpoint telemetry from Windows VMs and Linux containers |
| Service nodes | Squid (Proxy), Nginx (WebSrv) | latest | Real services generating real access logs |

**Security posture.** TLS on every channel, secrets in `.env`, dropped Linux capabilities on agents, dedicated `logstash_writer` role with no superuser usage, `logs-system.syslog-*` on a custom ILM policy.

---

## 2. Architecture

```
┌───────────────────────────────── HOST PC ─────────────────────────────────┐
│                                                                           │
│  Docker Desktop (WSL2):                                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────────────┐   │
│  │     es01     │  │   kibana01   │  │           logstash01           │   │
│  │  HTTPS :9200 │  │     :5601    │  │   syslog UDP/TCP :514 · :9600  │   │
│  └──────────────┘  └──────────────┘  └────────────────────────────────┘   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌───────────┐      │
│  │ fleet-server │  │ proxy-cnas   │  │ websrv-cnas  │  │agent-     │      │
│  │ HTTPS :8220  │  │ Squid :3128  │  │  Nginx :80   │  │websrv     │      │
│  └──────────────┘  └──────────────┘  └──────────────┘  └───────────┘      │
│   ┌──────────┐                                                            │
│   │ agent-   │                                                            │
│   │ proxy    │                                                            │
│   └──────────┘                                                            │
│  VirtualBox Host-Only Adapter: 10.10.10.1   ◄──── VMs reach Docker here   │
└───────────────────────────────────────────────────────────────────────────┘

┌───────────────────────────── VirtualBox VMs ──────────────────────────────┐
│                                                                           │
│  AD-CNAS-KOLEA          (Windows Server 2025 · Elastic Agent + Defend)    │
│  WSUS-CNAS-KOLEA        (Windows Server 2025 · Elastic Agent + Defend)    │
│      └─► Fleet Server (10.10.10.1:8220) ─► Elasticsearch                  │
└───────────────────────────────────────────────────────────────────────────┘

DATA FLOW (ECS data streams)
────────────────────────────
Windows VMs (AD/WSUS) ─► Elastic Agent ─► logs-windows.* · logs-system.*
                                          metrics-system.* · metrics-windows.*
                      ─► Elastic Defend ─► logs-endpoint.events.* · logs-endpoint.alerts
                                          metrics-endpoint.*
Squid container       ─► agent-proxy   ─► logs-squid.log-default · metrics-system.*
Nginx container       ─► agent-websrv  ─► logs-nginx.access-default · logs-nginx.error-default
                                          metrics-nginx.stubstatus-default · metrics-system.*
Network devices       ─► Logstash :514 ─► logs-system.syslog-default
                                          logs-system.auth-default
Every agent           ─► self-monitor  ─► logs-elastic_agent.* · metrics-elastic_agent.*
                            ▼
                      Elastic Security
                  (prebuilt + custom rules)
                            ▼
                .alerts-security.alerts-default
```

A complete inventory of every data stream and index in the cluster — what creates them, what they're for, and how to inspect them — is in [§6](#6-indices--data-streams-reference).

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

### Elastic Agent (managed via Fleet)

Handles every modern, integration-supported source. Each agent enrolls into a Fleet policy and ships into the canonical data stream for its dataset.

| Source | Data stream(s) |
|---|---|
| Windows Security log (AD/WSUS) | `logs-system.security-default` |
| Windows Sysmon (AD/WSUS) | `logs-windows.sysmon_operational-default` |
| Windows PowerShell (AD/WSUS) | `logs-windows.powershell-default`, `logs-windows.powershell_operational-default` |
| Windows Defender (AD/WSUS) | `logs-windows.windows_defender-default` |
| Windows perfmon / services (AD/WSUS) | `metrics-windows.perfmon-default`, `metrics-windows.service-default` |
| Squid `access.log` | `logs-squid.log-default` |
| Nginx `access.log` / `error.log` | `logs-nginx.access-default`, `logs-nginx.error-default` |
| Nginx stub status | `metrics-nginx.stubstatus-default` |
| System integration (everywhere) | `logs-system.application/system/security-default`, `metrics-system.*` |

### Elastic Defend (deployed on AD and WSUS only)

Defend is the endpoint security component — kernel-level process, network, file, registry, library and security telemetry, plus malware/ransomware/memory verdicts.

| Source | Data stream |
|---|---|
| Process events | `logs-endpoint.events.process-default` |
| Network events | `logs-endpoint.events.network-default` |
| File events | `logs-endpoint.events.file-default` |
| Registry events | `logs-endpoint.events.registry-default` |
| Library load events | `logs-endpoint.events.library-default` |
| Windows API events | `logs-endpoint.events.api-default` |
| Security events | `logs-endpoint.events.security-default` |
| Malware / ransomware verdicts | `logs-endpoint.alerts-default` |
| Endpoint metadata / status | `metrics-endpoint.metadata-default`, `metrics-endpoint.policy-default`, `metrics-endpoint.metrics-default` |

Defend is **not** added to the Linux agent containers (`agent-proxy`, `agent-websrv`). The kernel-level monitoring it requires conflicts with the locked-down capabilities those containers run with (`cap_drop: ALL`, `no-new-privileges`, no `pid: host`). Endpoint visibility on the Linux services is provided by the System integration's process and network metric collectors, which work fine inside hardened containers.

### Logstash

Reserved exclusively for **raw syslog from network devices** — sources without an Elastic Agent integration. The pipeline writes to system data streams via the dedicated `logstash_writer` role (no superuser).

| Source | Data stream |
|---|---|
| Auth-related syslog (`sshd`, `sudo`, `su`) | `logs-system.auth-default` |
| Everything else on UDP/TCP :514 | `logs-system.syslog-default` |

### Why this split

Elastic Agent integrations come with curated parsers, ingest pipelines and ECS mappings out of the box. Defend adds kernel-grade telemetry that no log source can match. Logstash is only used where neither has a supported path — keeping the configuration surface as small as possible.

---

## 5. ECS Normalisation

Every event lands with ECS field names so detection rules query a single, stable schema across Windows, Linux services, endpoint telemetry and raw syslog.

### Raw → ECS field renames (most common)

The core mapping the lab relies on:

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

### ECS field reference for detection rules

The mapping above is just the rename layer. The full set of fields you'll actually query when writing or tuning rules, grouped by concern:

**Event semantics** — what happened, what kind of thing it is, and how it ended:
- `event.kind` (`event` · `alert` · `signal` · `metric`)
- `event.category` (`authentication` · `process` · `network` · `file` · `registry` · `iam` · `web` · `host` · `malware` · `intrusion_detection`)
- `event.type` (`start` · `end` · `creation` · `change` · `denied` · `info`)
- `event.action` (free-form action name e.g. `logged-in`, `process-started`, `file-created`)
- `event.outcome` (`success` · `failure` · `unknown`)
- `event.dataset` (which integration produced it, e.g. `system.security`, `windows.sysmon_operational`)
- `event.module` (the package, e.g. `system`, `windows`, `endpoint`)
- `event.code` (raw provider code — Windows EventID, Defend rule ID, etc.)
- `event.provider` (e.g. `Microsoft-Windows-Security-Auditing`)

**Time** — `@timestamp` (event time), `event.created` (agent collection time), `event.ingested` (cluster ingest time).

**Host** — `host.name`, `host.hostname`, `host.ip`, `host.mac`, `host.architecture`, `host.os.name`, `host.os.family`, `host.os.version`.

**User** — `user.name`, `user.domain`, `user.id`, `user.target.name` (for events that act *on* another user, e.g. account creation).

**Source / destination** — `source.ip`, `source.port`, `source.bytes`, `source.packets`, `destination.ip`, `destination.port`, `destination.bytes`.

**Network** — `network.protocol`, `network.transport` (`tcp` · `udp`), `network.direction` (`ingress` · `egress`), `network.bytes`.

**Process** — `process.name`, `process.pid`, `process.executable`, `process.command_line`, `process.args`, `process.parent.name`, `process.parent.pid`, `process.parent.executable`, `process.hash.sha256`, `process.hash.md5`.

**File** — `file.name`, `file.path`, `file.directory`, `file.extension`, `file.size`, `file.hash.sha256`, `file.hash.md5`.

**HTTP / URL** (Nginx, Squid) — `url.full`, `url.path`, `url.query`, `url.domain`, `http.request.method`, `http.response.status_code`, `http.request.body.bytes`, `user_agent.original`.

**Windows-specific** — `winlog.event_id`, `winlog.channel`, `winlog.provider_name`, `winlog.computer_name`, `winlog.logon.type` (string: `Interactive`, `Network`, `RemoteInteractive`…), `winlog.event_data.*` (raw event-specific fields not yet ECS-normalised, e.g. `winlog.event_data.LogonType` integer, `winlog.event_data.TicketEncryptionType`).

**MITRE ATT&CK** — `threat.framework` (always `MITRE ATT&CK` here), `threat.tactic.id` (e.g. `TA0006`), `threat.tactic.name`, `threat.tactic.reference`, `threat.technique.id` (e.g. `T1110`), `threat.technique.name`, `threat.technique.reference`, plus `.subtechnique.*` variants.

**Agent** — `agent.id`, `agent.name`, `agent.type` (`elastic-agent` · `endpoint`), `agent.version`.

**Schema marker** — `ecs.version` is on every doc, useful for sanity-checking ingest.

For the canonical field catalogue see <https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html>.

---

## 6. Indices & Data Streams Reference

This section is the back-pocket reference: what a "data stream" is vs an "index" vs an "alias", verification commands to inspect the cluster, and a complete inventory of everything the project produces — what creates each item, what's stored in it, and roughly how it behaves over time.

### 6.1 Concepts (3-minute orientation)

Three things live alongside each other in Elasticsearch:

- **Data stream** — a logical, append-only name (e.g. `logs-system.security-default`) that fronts one or more time-ordered backing indices. Every modern Elastic integration writes into a data stream, not an index. ILM rolls them over when they hit a size or age threshold and deletes them on schedule.
- **Backing index** — the actual physical index storing docs (e.g. `.ds-logs-system.security-default-2026.04.05-000001`). Always hidden, dot-prefixed, generation-numbered. You search the data stream, not the backing index.
- **Alias** — a named pointer to one or more indices, used heavily for security alerts and Kibana state (e.g. `.alerts-security.alerts-default` → `.internal.alerts-security.alerts-default-000003`).
- **Regular index** — a non-data-stream index. Internal Elastic state lives here: `.kibana_*`, `.security-7`, `.fleet-agents-7`, `.monitoring-es-7-*`, etc.

The `logs` and `metrics` index modes used by data streams are also worth knowing about. Logs streams use `logsdb` mode (compressed, optimised for log access patterns). Metrics streams use `time_series` mode (TSDB, optimised for high-cardinality numeric data). Both are the 9.x defaults for their respective integration types — no manual tuning required.

### 6.2 Verification commands

```bash
set -a && source .env && set +a

# Every data stream + its backing indices (verbose)
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  "https://localhost:9200/_data_stream?expand_wildcards=all&pretty"

# Just data-stream and index names with doc counts and size
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  "https://localhost:9200/_cat/indices/logs-*,metrics-*,.alerts-*?v&s=index&h=index,docs.count,store.size&expand_wildcards=all"

# Including hidden / system indices (.kibana, .security, .fleet-*, .ds-*)
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  "https://localhost:9200/_cat/indices?v&s=index&h=index,docs.count,store.size,health&expand_wildcards=all"

# Aliases (detection alerts, Kibana saved-object alias chain)
curl -sk -u elastic:${ELASTIC_PASSWORD} "https://localhost:9200/_cat/aliases?v"

# All index templates ES knows about (filtered to project-relevant ones)
curl -sk -u elastic:${ELASTIC_PASSWORD} "https://localhost:9200/_cat/templates?v" \
  | grep -E "logs-|metrics-"

# Which ILM policy a specific stream is using
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  "https://localhost:9200/_data_stream/logs-system.syslog-default?pretty" \
  | grep -E "ilm_policy|template"

# All ILM policies
curl -sk -u elastic:${ELASTIC_PASSWORD} "https://localhost:9200/_ilm/policy?pretty"
```

Data streams do **not** appear in **Kibana → Stack Management → Index Management → Indices**. Find them under the **Data Streams** tab.

### 6.3 Full inventory — what lives in the cluster, grouped by purpose

#### A. Project telemetry — the SIEM data you'll query

These are the streams detection rules and dashboards run against.

| Data stream | Source | Notes |
|---|---|---|
| `logs-system.security-default` | Windows Security log (AD/WSUS) | The primary detection target. Windows Server 2025 collects unfiltered (see [§13.6](#136-windows-server-2025-caveat--event-id-filters-silently-ignored)) — high volume. |
| `logs-system.application-default` | Windows Application log (AD/WSUS) | Service start/stop, app crashes, MSI installs. |
| `logs-system.system-default` | Windows System log (AD/WSUS) | Driver loads, time changes, service control manager. |
| `logs-system.auth-default` | Logstash (sshd / sudo / su syslog) | Linux auth events from network devices on :514. |
| `logs-system.syslog-default` | Logstash (everything else on :514) | Catch-all syslog. Custom ILM `syslog-policy` applied. |
| `logs-windows.sysmon_operational-default` | Sysmon channel (AD/WSUS) | Process creation, network connections, file/registry mods, DNS — the bedrock for most Windows detections. |
| `logs-windows.powershell-default` | PowerShell classic (AD/WSUS) | Engine state events. |
| `logs-windows.powershell_operational-default` | PowerShell Operational channel (AD/WSUS) | Script-block logging (EID 4104), module logging (EID 4103). Empty unless [§13.5](#135-powershell-logging) is configured. |
| `logs-windows.windows_defender-default` | Windows Defender Operational channel | Built-in AV events, complementary to Defend's stream. |
| `logs-squid.log-default` | Squid `access.log` via `agent-proxy` | One doc per HTTP/HTTPS proxy request. |
| `logs-nginx.access-default` | Nginx `access.log` via `agent-websrv` | Web requests. Requires `combined` log format (see [§12.3](#123-nginx-log-format)). |
| `logs-nginx.error-default` | Nginx `error.log` via `agent-websrv` | Web errors and warnings. |

#### B. Endpoint telemetry — Elastic Defend (AD/WSUS only)

Kernel-level data that no log source can produce. Heavy users of disk and CPU but the most signal-rich inputs you'll have.

| Data stream | What it captures |
|---|---|
| `logs-endpoint.events.process-default` | Every process create / fork / exec / exit, with full command line and parent chain |
| `logs-endpoint.events.network-default` | Every TCP/UDP connection initiation and accept |
| `logs-endpoint.events.file-default` | File create / modify / delete / rename |
| `logs-endpoint.events.registry-default` | Registry create / modify / delete (Windows) |
| `logs-endpoint.events.library-default` | DLL / SO load events |
| `logs-endpoint.events.api-default` | Selected sensitive Win32 API calls (LSASS access, etc.) |
| `logs-endpoint.events.security-default` | Defend's own security events — its take on the Windows Security channel |
| `logs-endpoint.alerts-default` | Malware / ransomware / memory-protection / behaviour-protection verdicts. Empty until something fires. |
| `metrics-endpoint.metadata-default` | Per-host endpoint metadata (OS, agent ID, configured policy) |
| `metrics-endpoint.metrics-default` | Endpoint agent's own performance counters |
| `metrics-endpoint.policy-default` | Active Defend policy snapshot per host |
| `.logs-endpoint.actions-default` *(hidden)* | Defend response actions sent from Kibana (isolate host, etc.) |
| `.logs-endpoint.action.responses-default` *(hidden)* | Action results coming back |
| `.logs-endpoint.diagnostic.collection-default` *(hidden)* | Defend self-diagnostics |

#### C. Host metrics — System integration

Useful for correlation (CPU spike alongside a suspicious process spawn), capacity planning, and the Stack Monitoring app. Lower per-event value, much higher cardinality than logs.

| Data stream | Cadence |
|---|---|
| `metrics-system.cpu-default` | Per-core CPU stats |
| `metrics-system.memory-default` | RAM, swap, page cache |
| `metrics-system.network-default` | Per-interface bytes/packets/errors |
| `metrics-system.diskio-default` | Per-device IOPS, throughput, queue depth |
| `metrics-system.filesystem-default` | Per-mount usage |
| `metrics-system.fsstat-default` | Filesystem aggregate |
| `metrics-system.load-default` | Linux load average |
| `metrics-system.process-default` | Per-process resource snapshots — **the largest stream in the cluster by volume**, see disk-tuning note below |
| `metrics-system.process.summary-default` | Process count by state |
| `metrics-system.uptime-default` | Boot time, uptime |
| `metrics-system.socket_summary-default` | Open socket counts |
| `metrics-windows.perfmon-default` | Windows performance counters (very chatty by default) |
| `metrics-windows.service-default` | Windows service state changes |
| `metrics-nginx.stubstatus-default` | Nginx active connections, requests/sec |

> **Disk-tuning note.** `metrics-system.process-default` and `metrics-windows.perfmon-default` are the two biggest disk consumers in this stack — together they typically use more space than every log stream combined. If a deployment doesn't actively use them for capacity dashboards, they're worth either disabling in the integration policy, increasing their sample interval (e.g. 10s → 60s), or putting on an aggressive ILM (rollover at 1 day, delete after 7).

#### D. Agent and Fleet self-monitoring

How the agents themselves are doing. Useful when troubleshooting why a stream is empty or an agent is degraded.

| Data stream | Purpose |
|---|---|
| `logs-elastic_agent-default` | Agent supervisor logs |
| `logs-elastic_agent.filebeat-default` | Per-input filebeat logs (which files, throughput, errors) |
| `logs-elastic_agent.metricbeat-default` | Per-input metricbeat logs |
| `logs-elastic_agent.fleet_server-default` | Fleet Server logs |
| `logs-elastic_agent.endpoint_security-default` | Defend agent-side logs |
| `metrics-elastic_agent.elastic_agent-default` | Agent supervisor metrics |
| `metrics-elastic_agent.filebeat-default` / `.filebeat_input-default` | Filebeat throughput / per-input lag |
| `metrics-elastic_agent.metricbeat-default` | Metricbeat throughput |
| `metrics-elastic_agent.fleet_server-default` | Fleet Server throughput |
| `metrics-elastic_agent.endpoint_security-default` | Defend agent metrics |
| `metrics-fleet_server.agent_status-default` | Per-agent online/offline counts |
| `metrics-fleet_server.agent_versions-default` | Version distribution across the fleet |

#### E. Detection alerts (created when rules fire)

| Alias | Backing index | Role |
|---|---|---|
| `.alerts-security.alerts-default` | `.internal.alerts-security.alerts-default-NNNNNN` | Live security alerts. Latest-numbered backing index is `is_write_index: true`. |
| `.siem-signals-default` | same | Legacy alias, kept for older saved searches and rules. |
| `.preview.alerts-security.alerts-default` | `.internal.preview.alerts-security.alerts-default-NNNNNN` | Rule preview output (not real alerts). |
| `.alerts-security.attack.discovery.alerts-default` | `.internal.alerts-security.attack.discovery.alerts-default-000001` | AI-driven attack discovery summaries. |

A handful of additional `.alerts-*` aliases exist for observability domains (logs, metrics, uptime, slo) and ML — they share the same alias-to-internal-index pattern but are unused in this lab unless those features are enabled.

#### F. Stack-internal indices — don't query directly

These are managed by Kibana, Fleet, security, ILM and Stack Monitoring. Listed here so they're not mistaken for telemetry.

| Family | Examples | Purpose |
|---|---|---|
| Fleet state | `.fleet-agents-7`, `.fleet-policies-7`, `.fleet-actions-7`, `.fleet-enrollment-api-keys-7`, `.fleet-artifacts-7` | Agent registry, policy storage, action queue, enrollment-token store, package artifacts |
| Fleet file transfers | `.ds-.fleet-fileds-fromhost-data-agent-*`, `.ds-.fleet-fileds-fromhost-meta-agent-*` | Diagnostics bundles uploaded from agents |
| Kibana | `.kibana_9.1.3_001`, `.kibana_alerting_cases_9.1.3_001`, `.kibana_security_solution_9.1.3_001`, `.kibana_ingest_9.1.3_001`, `.kibana_analytics_9.1.3_001`, `.kibana_task_manager_9.1.3_001` | Saved objects, dashboards, rule definitions, task queue |
| Kibana audit | `.ds-.kibana-event-log-ds-*` | Every action taken in Kibana — alerting executions, rule edits, etc. Can grow large on long-running stacks. |
| Security model | `.security-7`, `.security-profile-8`, `.kibana_security_session_1` | Users, roles, role mappings, login sessions |
| ES history | `.ds-ilm-history-7-*`, `.ds-.slm-history-7-*` | ILM transitions and snapshot history |
| Stack Monitoring | `.monitoring-es-7-*`, `.monitoring-kibana-7-*` | Heap, CPU, indexing rate, search rate timelines |
| Geo / inference | `.geoip_databases`, `.inference`, `.secrets-inference` | IP-to-location DBs and ML model artefacts |
| Detection rule migration | `.kibana-siem-rule-migrations-prebuiltrules`, `.kibana-siem-rule-migrations-integrations` | Used during prebuilt-rule package upgrades |
| Security workflow | `.ds-.edr-workflow-insights-default-*`, `.items-default`, `.lists-default`, `.asset-criticality.asset-criticality-default` | Defend workflow insights, value lists, asset criticality |
| Endpoint transforms | `metrics-endpoint.metadata_current_default`, `.metrics-endpoint.metadata_united_default` | Computed by transforms — current view of endpoint metadata, merged across hosts |
| Deprecation | `.ds-.logs-elasticsearch.deprecation-default-*` | ES warns about deprecated config here |

### 6.4 ILM policies in use

| Policy | Applied to |
|---|---|
| `logs` (built-in) | All `logs-*` streams except syslog |
| `metrics` (built-in) | All `metrics-*` streams |
| `syslog-policy` (custom — see [§16.1](#161-storage-hardening)) | `logs-system.syslog-default` (visible from generation 2 onward) |
| `logs-endpoint.collection-diagnostic` | `.logs-endpoint.diagnostic.collection-default` |
| `.fleet-actions-results-ilm-policy` | `.fleet-actions-results` |
| `.fleet-file-fromhost-data-ilm-policy` | `.fleet-fileds-fromhost-data-agent` |
| `.fleet-file-fromhost-meta-ilm-policy` | `.fleet-fileds-fromhost-meta-agent` |
| `.deprecation-indexing-ilm-policy` | `.logs-elasticsearch.deprecation-default` |

The remaining detection-relevant streams (`logs-system.security`, `logs-windows.sysmon_operational`, `metrics-windows.perfmon`, `metrics-system.process`) currently use the default `logs` / `metrics` policies. Tightening these is in [§16.1](#161-storage-hardening).

---

## 7. Prerequisites

| Requirement | Minimum |
|---|---|
| Docker Desktop (Windows, WSL2 backend) | 4.x |
| RAM for Docker | 8 GB |
| RAM available for VMs | 4 GB additional (2 GB per VM) |
| Disk | 50 GB free |
| VirtualBox | 7.x |
| Windows Server 2025 ISO | For AD and WSUS VMs |
| Git Bash / WSL shell | Required for `.env` editing (no Notepad — see [§16.3](#163-secrets-handling)) |
| Python 3 | 3.9+ |
| `curl`, `openssl` | Bundled with Git Bash / WSL |

Before booting any VM, confirm a VirtualBox **Host-Only network** exists at `10.10.10.1/24` (File → Tools → Network Manager). Without it, the VMs cannot reach Docker.

---

## 8. Repository Layout

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

## 9. Phase 1 — Core Stack

### 9.1 Provision secrets (one time)

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

### 9.2 Generate TLS certificates

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

### 9.3 Boot Elasticsearch and bootstrap built-in users

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

### 9.4 Bring up the rest

```bash
docker compose up -d
sleep 40
docker ps
```

Kibana: `https://localhost:5601` · login `elastic` / `${ELASTIC_PASSWORD}`.

---

## 10. Phase 2 — Fleet Server & Agent Enrollment

### 10.1 Generate the Fleet service token

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

### 10.2 Common Phase 2 issues (and the fixes that work)

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

### 10.3 Create agent policies in Kibana

**Management → Fleet → Agent Policies → Create agent policy**, then add integrations:

| Policy | Integrations |
|---|---|
| `AD-CNAS Policy` | System · Windows · **Elastic Defend** |
| `WSUS-CNAS Policy` | System · Windows · **Elastic Defend** |
| `PROXY-CNAS Policy` | System · Squid (custom log path `/var/log/squid/access.log`) |
| `WEBSRV-CNAS Policy` | System · Nginx (custom log path `/var/log/nginx/access.log`) |

Copy each policy's enrollment token into the matching `.env` variable.

#### Why Defend goes on the Windows VMs only

Elastic Defend hooks into the kernel for process / file / network / registry telemetry. On Linux it requires `SYS_ADMIN`, `SYS_PTRACE`, `SYS_RESOURCE`, `no-new-privileges:false`, and typically `pid: host` — every one of which is explicitly disabled on `agent-proxy` and `agent-websrv` by the runtime hardening in [§16.5](#165-runtime-hardening). Adding Defend to those policies would either silently fail or force a roll-back of the container security posture.

The Linux containers still get rich process and network telemetry through the System integration — they just don't get Defend's malware/ransomware/memory-protection layers. For lab demonstration that's a reasonable trade-off; if a production deployment needs Defend on Linux endpoints, run it on bare-metal or non-hardened hosts, not inside locked-down containers.

#### Configuring Defend's policy

When you add Elastic Defend to AD/WSUS, choose **Complete EDR (Endpoint Detection & Response)** as the preset. That enables all `logs-endpoint.events.*` streams plus the malware/ransomware/memory/behaviour protections. Tune the policy under **Fleet → Agent policies → AD-CNAS Policy → Elastic Defend** if specific event categories produce too much noise.

### 10.4 Start the Linux agents

```bash
docker compose up -d agent-proxy agent-websrv
docker logs agent-proxy   --tail 30 | grep -Ei "error|warn"
docker logs agent-websrv  --tail 30 | grep -Ei "error|warn"
```

Windows VM enrollment is covered in [Phase 5](#13-phase-5--windows-vms).

---

## 11. Phase 3 — Logstash Syslog Pipeline

`logstash/pipeline/logstash.conf` listens on UDP/TCP **514** and routes events to two ECS-correct data streams:

- `logs-system.auth-default` — events from `sshd`, `sudo`, `su`
- `logs-system.syslog-default` — everything else

Logstash authenticates as `logstash_writer` (created in [§16.4](#164-rbac-logstash-and-kibana-users)) over TLS. No superuser involved.

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

## 12. Phase 4 — CNAS Service Containers

### 12.1 Bring up Squid and Nginx

```bash
cd ../scripts
docker compose -f docker-compose.cnas.yml up -d
```

Verify real logs are being generated:

```bash
docker exec PROXY-CNAS-KOLEA  tail -f /var/log/squid/access.log
docker exec WEBSRV-CNAS-KOLEA tail -f /var/log/nginx/access.log
```

### 12.2 Volume wiring

The agents read service logs through Docker named volumes shared with the service containers:

```
WEBSRV-CNAS-KOLEA  ──► writes to elk_stack_websrv-logs → /var/log/nginx
agent-websrv       ──► reads  from elk_stack_websrv-logs → /var/log/nginx (read-only)

PROXY-CNAS-KOLEA   ──► writes to elk_stack_proxy-logs  → /var/log/squid
agent-proxy        ──► reads  from elk_stack_proxy-logs  → /var/log/squid  (read-only)
```

### 12.3 Nginx log format

The Elastic Nginx integration expects the `combined` format. `scripts/nginx/nginx.conf` already sets:

```nginx
access_log /var/log/nginx/access.log combined;
```

This file is bind-mounted into the container — no manual reload needed on a fresh build.

### 12.4 Why `logs-system.auth-default` is empty for service containers

Minimal Docker images (`nginx:latest`, `ubuntu/squid`) ship without `rsyslog` or an init system. There is no `auth.log` for the agent to read. Auth events come from the Windows VMs, from external syslog senders on port 514, and from any future host with a real init system.

---

## 13. Phase 5 — Windows VMs

### 13.1 VM creation

| Setting | Value |
|---|---|
| OS | Windows Server 2025 |
| RAM | 2048 MB minimum |
| CPU | 2 cores |
| Adapter 1 | NAT (internet) |
| Adapter 2 | **Host-Only Adapter → `VirtualBox Host-Only Ethernet Adapter` (10.10.10.1)** — mandatory |

### 13.2 hosts file on each VM (PowerShell as Administrator)

```powershell
$hosts = Get-Content "C:\Windows\System32\drivers\etc\hosts"
$hosts = $hosts | Where-Object { $_ -notmatch "es01|fleet-server" }
$hosts | Set-Content "C:\Windows\System32\drivers\etc\hosts"

Add-Content "C:\Windows\System32\drivers\etc\hosts" "10.10.10.1`tes01"
Add-Content "C:\Windows\System32\drivers\etc\hosts" "10.10.10.1`tfleet-server"

Test-NetConnection -ComputerName fleet-server -Port 8220   # TcpTestSucceeded : True
```

### 13.3 Trust the CA, then enroll

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

### 13.4 Audit policy

Without these subcategories enabled, the Windows Security log will not contain the events most detection rules query. The set below covers Microsoft's recommended security-monitoring baseline plus the additions Elastic's prebuilt rules expect (Kerberos, DS replication, handle manipulation, file/registry object access, audit-policy tampering).

Run the entire block as Administrator on each VM (AD and WSUS):

```cmd
@echo off
:: ── Account Logon ── 4768/4769/4776
:: Validation des informations d'identification
auditpol /set /subcategory:"{0CCE923F-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Service d'authentification Kerberos
auditpol /set /subcategory:"{0CCE9242-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Opérations de ticket du service Kerberos
auditpol /set /subcategory:"{0CCE9240-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Autres événements d'ouverture de session
auditpol /set /subcategory:"{0CCE9241-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable

:: ── Account Management ── 4720-4738, 4741, 4781
:: Gestion des comptes d'utilisateur
auditpol /set /subcategory:"{0CCE9235-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Gestion des comptes d'ordinateur
auditpol /set /subcategory:"{0CCE9236-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Gestion des groupes de sécurité
auditpol /set /subcategory:"{0CCE9237-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Gestion des groupes de distribution
auditpol /set /subcategory:"{0CCE9238-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Autres événements de gestion des comptes
auditpol /set /subcategory:"{0CCE923A-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable

:: ── Detailed Tracking ── 4688/4689/4703
:: Création du processus
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Fin du processus (success only — failure impossible)
auditpol /set /subcategory:"{0CCE922C-69AE-11D9-BED3-505054503030}" /success:enable
:: Activité DPAPI
auditpol /set /subcategory:"{0CCE922D-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Événements RPC
auditpol /set /subcategory:"{0CCE922E-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Événements de jeton ajustés à droite (success only)
auditpol /set /subcategory:"{0CCE924A-69AE-11D9-BED3-505054503030}" /success:enable

:: ── DS Access (DC only) ── 4662 DCSync, 5136 AD object change
:: Accès au service d'annuaire
auditpol /set /subcategory:"{0CCE923B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Modification du service d'annuaire
auditpol /set /subcategory:"{0CCE923C-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Réplication du service d'annuaire (success only)
auditpol /set /subcategory:"{0CCE923D-69AE-11D9-BED3-505054503030}" /success:enable

:: ── Logon/Logoff ── 4624/4625/4634/4647/4672/4740
:: Ouvrir la session
auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Fermer la session (success only)
auditpol /set /subcategory:"{0CCE9216-69AE-11D9-BED3-505054503030}" /success:enable
:: Verrouillage du compte
auditpol /set /subcategory:"{0CCE9217-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Ouverture de session spéciale
auditpol /set /subcategory:"{0CCE921B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Appartenance à un groupe (success only)
auditpol /set /subcategory:"{0CCE9249-69AE-11D9-BED3-505054503030}" /success:enable
:: Autres événements d'ouverture/fermeture de session
auditpol /set /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable

:: ── Object Access ── 4656/4663/5140/5145
:: Système de fichiers
auditpol /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Registre
auditpol /set /subcategory:"{0CCE921E-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Stockage amovible
auditpol /set /subcategory:"{0CCE9245-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Partage de fichiers
auditpol /set /subcategory:"{0CCE9224-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Partage de fichiers détaillé
auditpol /set /subcategory:"{0CCE9244-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: SAM
auditpol /set /subcategory:"{0CCE9220-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Objet de noyau
auditpol /set /subcategory:"{0CCE921F-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Manipulation de handle
auditpol /set /subcategory:"{0CCE9223-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Autres événements d'accès à l'objet
auditpol /set /subcategory:"{0CCE9227-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Connexion de la plateforme de filtrage
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable

:: ── Policy Change ── 4719 audit-policy tampering, 4670 perms
:: Modification de la stratégie d'audit
auditpol /set /subcategory:"{0CCE922F-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Modification de la stratégie d'authentification
auditpol /set /subcategory:"{0CCE9230-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Modification de la stratégie d'autorisation
auditpol /set /subcategory:"{0CCE9231-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Modification de la stratégie de niveau règle MPSSVC
auditpol /set /subcategory:"{0CCE9232-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Modification de la stratégie de plateforme de filtrage
auditpol /set /subcategory:"{0CCE9233-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Autres événements de modification de stratégie (failure only)
auditpol /set /subcategory:"{0CCE9234-69AE-11D9-BED3-505054503030}" /failure:enable

:: ── Privilege Use ── 4672/4673/4674
:: Utilisation de privilèges sensibles
auditpol /set /subcategory:"{0CCE9228-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Autres événements d'utilisation de privilèges
auditpol /set /subcategory:"{0CCE922A-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: NOTE: "Utilisation de privilèges non sensibles" {0CCE9229-...} laissé désactivé
::       (volume extrême, valeur de détection quasi-nulle)

:: ── System ── 4608/4609/4616/5478
:: Modification de l'état de la sécurité
auditpol /set /subcategory:"{0CCE9210-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Extension système de sécurité
auditpol /set /subcategory:"{0CCE9211-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Intégrité du système
auditpol /set /subcategory:"{0CCE9212-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Pilote IPSEC
auditpol /set /subcategory:"{0CCE9213-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
:: Autres événements système (failure only)
auditpol /set /subcategory:"{0CCE9214-69AE-11D9-BED3-505054503030}" /failure:enable

echo.
echo === Verification (toute ligne affichee doit montrer Succes/Echec/Reussite) ===

:: ── Verify
auditpol /get /category:* | findstr /v "No Auditing"
```

`Non Sensitive Privilege Use` is intentionally left disabled — it produces extreme volume with near-zero detection value. `Logoff` and `Process Termination` enable success only because failure is impossible for those events.

### 13.5 PowerShell logging

Without these registry keys, `logs-windows.powershell_operational-default` will be near-empty even on a busy host. Three things are needed: script-block logging (the actual script content, EID 4104), module logging (function names being invoked, EID 4103), and a large enough Operational channel so events aren't rotated out before the agent collects them.

Run as Administrator on each Windows VM:

```powershell
# ── Script Block Logging (EID 4104) — the main signal for malicious PS
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        /v EnableScriptBlockInvocationLogging /t REG_DWORD /d 1 /f

# ── Module Logging (EID 4103) — needs both the parent toggle and a wildcard
#    in the ModuleNames child key, otherwise nothing gets logged
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
        /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
        /v "*" /t REG_SZ /d "*" /f

# ── Transcription — full session capture to disk (separate from event log)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        /v EnableInvocationHeader /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        /v OutputDirectory /t REG_SZ /d "C:\PSTranscripts" /f

# ── Increase the Operational PowerShell channel to 1 GB so 4104 events
#    aren't rotated out before the agent ships them
wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:1073741824

# ── Verify
Get-WinEvent -ListLog Microsoft-Windows-PowerShell/Operational `
  | Select LogName, IsEnabled, MaximumSizeInBytes
```

### 13.6 Windows Server 2025 caveat — event ID filters silently ignored

WS2025 has a known Event Log API limitation: filters configured in the Windows integration are dropped server-side. **Workaround:** in Fleet → Windows integration, remove all event ID filters and let the agent collect everything.

⚠️ Unfiltered collection on a busy AD DC produces hundreds of events per minute (4634, 4648, 4776). After enabling, **immediately** apply a tighter ILM to `logs-system.security-default` (see [§16.1](#161-storage-hardening)) and consider explicit exclusions for the noisiest benign events at the integration level once you've measured the volume.

---

## 14. Phase 6 — VirtualBox Networking

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

## 15. Phase 7 — Detection Rules

### 15.1 Health gate (run before enabling rules)

Rules firing against empty indices produce false confidence. Verify everything is flowing:

```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  "https://localhost:9200/_cat/indices/logs-windows.*,logs-system.*,logs-squid.*,logs-nginx.*,logs-endpoint.*?v&h=index,docs.count&s=index"
```

All expected data streams must show non-zero `docs.count` ([§6.3](#63-full-inventory--what-lives-in-the-cluster-grouped-by-purpose) lists everything that should exist).

### 15.2 Load and enable rules

**Kibana → Security → Rules → Detection Rules → Add Elastic rules.** Then enable in priority order (Critical → High → review Medium individually). The exact rule list — verified against this architecture by running real attack tests from Kali — is being compiled separately. Skip rules tagged AWS / GCP / Kubernetes / Office365; they only generate noise here.

### 15.3 Index-pattern note

Do **not** alias `winlogbeat-*` onto data streams; this triggers `verification_exception` on rules referencing `process.name`. If a prebuilt rule needs a different index pattern, **duplicate the rule** and append the pattern to the copy.

### 15.4 Detection map per source

| Source | Examples |
|---|---|
| `AD-CNAS-KOLEA` (Win Sec + Sysmon + Defend) | 4625 brute force · 4740 lockout · 4769 Kerberoasting (RC4) · 4662 DCSync · 4728 Domain Admin add · LSASS access via Defend `events.api` |
| `WSUS-CNAS-KOLEA` (Win Sec + Sysmon + Defend) | Same Windows rule set; *IIS HTTP Logging Disabled* if IIS is installed |
| `PROXY-CNAS-KOLEA` (Squid) | DNS tunneling · connections to commonly abused web services |
| `WEBSRV-CNAS-KOLEA` (Nginx) | Web shell child process · unusual web-server command execution |
| Defend on AD/WSUS | Ransomware / malware verdicts in `logs-endpoint.alerts-default` |

---

## 16. Post-Deployment Hardening

The deployment as it stands is functional and TLS-secured.

| # | Item | Reference |
|---|---|---|
| 16.1 | ILM on `logs-system.syslog-*` (custom `syslog-policy`) | Storage |
| 16.1 | ILM tuning on `logs-system.security-*` (high-volume) | Storage |
| 16.1 | ILM tuning on heavy metrics streams (perfmon, system.process) | Storage |
| 16.1 | Snapshot repository registered + daily SLM running |Storage |
| 16.1 | Replicas = 0 globally (single-node) | Storage |
| 16.1 | Disk watermarks tuned for 50 GB disk | Storage |
| 16.2 | Legacy `syslog-*` index template guard | Schema |
| 16.3 | Secrets in `.env`, not in compose files | Security |
| 16.3 | TLS on ES, Kibana, Logstash, Fleet | Security |
| 16.3 | `.env` excluded from Git| Security |
| 16.4 | `logstash_writer` role (no superuser for ingest)| Security |
| 16.4 | `siem-analyst` Kibana role for evaluators | Security |
| 16.4 | Fleet enrollment tokens revoked after enrollment | Security |
| 16.5 | Container hardening (no `pid:host`, `cap_drop: ALL`) | Runtime |
| 16.5 | `restart: unless-stopped` on ES + Kibana | Runtime |
| 16.5 | `ulimits` on ES (memlock, nofile) | Runtime |
| 16.5 | `vm.max_map_count=262144` on host | Runtime |
| 16.6 | Stack Monitoring enabled in Kibana | Operations |
| 16.6 | Pre-demo health check script| Operations |

### 16.1 Storage hardening

**ILM tuning for `logs-system.security-default`** (the high-volume Windows Security stream — currently on the default `logs` policy with multi-million-doc backing indices):

```bash
# 1. Create a tighter ILM policy for the Windows Security stream
curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_ilm/policy/win-security-policy" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": { "phases": {
      "hot":    { "min_age":"0ms","actions":{"rollover":{"max_size":"5gb","max_age":"7d"}}},
      "delete": { "min_age":"30d","actions":{"delete":{}}}
    }}
  }'

# 2. Component template that injects only the policy name
curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_component_template/custom-win-security-ilm" \
  -H "Content-Type: application/json" \
  -d '{"template":{"settings":{"index.lifecycle.name":"win-security-policy"}}}'

# 3. Find the existing composed_of array, then PUT the template back with
#    "custom-win-security-ilm" appended (do NOT replace the others)
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  "https://localhost:9200/_index_template/logs-system.security?pretty" \
  | grep -A 20 '"composed_of"'
```

The same three-step pattern (policy → component template → append) tames `metrics-windows.perfmon-*`, `metrics-system.process-*`, and `logs-windows.sysmon_operational-*` if those grow uncontrolled.

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

### 16.2 Legacy `syslog-*` index template (guard)

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

### 16.3 Secrets handling

`.env` already holds every credential; verify it never reaches Git:

```bash
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

### 16.4 RBAC: Logstash and Kibana users

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

**Revoke Fleet enrollment tokens** once all four agents (AD, WSUS, proxy, websrv) are healthy: Kibana → Fleet → Enrollment tokens → Revoke. Already-enrolled agents keep working; only new enrollments are blocked.

### 16.5 Runtime hardening

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

### 16.6 Operational

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

## 17. Operations & Verification

### Cluster snapshot

```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} "https://localhost:9200/_cluster/health?pretty"
```

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
| Linux — All | `logs-squid.log-default,logs-nginx.access-default,logs-nginx.error-default,logs-system.auth-default` |
| Endpoint (Defend) | `logs-endpoint.events.*,logs-endpoint.alerts-default` |
| Raw Syslog | `logs-system.syslog-default` |
| Fleet Telemetry | `metrics-elastic_agent.*,logs-elastic_agent.*` |
| All Security | `logs-*,logs-endpoint.*` |

### Useful KQL

```kql
host.name : "AD-CNAS-KOLEA"
event.category : "authentication" and event.outcome : "failure"
event.code : "4769"               # Kerberoasting indicator
event.code : "4662"               # DCSync indicator
event.dataset : "endpoint.events.process" and process.name : "lsass.exe"
threat.tactic.name : *            # Anything MITRE-tagged
```

---

## 18. Troubleshooting

**VM cannot reach Docker (`Test-NetConnection` fails).** NAT (`10.0.2.2`) does not work — see [§14](#14-phase-6--virtualbox-networking). Use the Host-Only adapter at `10.10.10.1`. Do not use `networkingMode=mirrored` or `netsh portproxy`.

**`401 Unauthorized` from Kibana or Logstash.** Built-in user passwords are out of sync with `.env`. Reset `kibana_system` / `logstash_system` via the API (see [§10.2](#102-common-phase-2-issues-and-the-fixes-that-work) and [§9.3](#93-boot-elasticsearch-and-bootstrap-built-in-users)) and `--force-recreate` the affected container.

**Fleet Server `invalid token`.** The token was deleted server-side or Elasticsearch was wiped. Recreate per [§10.2](#102-common-phase-2-issues-and-the-fixes-that-work).

**Indices show as YELLOW.** Single-node cluster; replicas can never be assigned. Apply `number_of_replicas: 0` (see [§16.1](#161-storage-hardening)).

**Nginx logs not appearing despite the volume mount.** The Elastic integration parses `combined`, not `main`. The fix is already in `scripts/nginx/nginx.conf`; rebuild the container if you changed the format manually:
```bash
docker compose -f scripts/docker-compose.cnas.yml up -d --build websrv-cnas
```

**`logs-system.auth-default` is empty for the Linux agents.** Expected — minimal Squid/Nginx images have no `rsyslog`. Auth events come from the Windows VMs and from external syslog on port 514.

**`logs-windows.powershell_operational-default` is empty.** Either [§13.5](#135-powershell-logging) was not run as Administrator, or the `ModuleNames` child key is missing — `EnableModuleLogging=1` alone does nothing. Re-run the full block.

**`_grokparsefailure` tag in Logstash.** Caused by a syslog payload that doesn't match `<PRI>TIMESTAMP HOST PROG[PID]: MSG`. Confirm the sender is RFC 3164 compliant; the lab's pipeline only rewrites `message` when the grok succeeds.

**Windows Server 2025 filter warning.** Known WS2025 Event Log API limitation — see [§13.6](#136-windows-server-2025-caveat--event-id-filters-silently-ignored).

**`logs-system.security-default` is exploding in size.** WS2025 unfiltered collection on a busy DC. Apply the per-stream ILM in [§16.1](#161-storage-hardening) and add explicit exclusions for high-noise benign EventIDs (4634, 4776, 5156) at the integration level once you've measured volume.

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

## 19. Credentials & Quick Reference

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

*Elastic Stack 9.1.3 · Elastic Agent 9.1.3 · Elastic Defend · Elastic Security · Docker Desktop (WSL2) · VirtualBox 7.x · Windows Server 2025*

*Lab environment — credentials in `.env` are unique per deployment. Rotate everything before any external exposure.*
