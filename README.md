# PFE-SIEM — ELK Stack 9.x CNAS Lab

A fully containerised SIEM lab built on **ELK Stack 9.1.3**, simulating four CNAS agency nodes (AD, WSUS, Proxy, WebSrv), collecting **real live telemetry** from Windows VMs and Docker services, and running Elastic Security detections with all useful events normalized to **Elastic Common Schema (ECS)**.

> **Read this first.** This README separates:
> - **Target architecture** — the intended final design
> - **Verified deployed state** — what was actually confirmed working
> - **Current gaps / in-progress sources** — integrations that are configured but not yet fully verified
>
> For fresh deployment, follow the target architecture.
> For troubleshooting and rule validation, trust the **verified deployed state** first.

---

## 1. Architecture Overview

### Core stack
- **Elasticsearch** (`es01`)
- **Kibana** (`kibana01`)
- **Logstash** (`logstash01`)
- **Fleet Server** (`fleet-server`)

### Live sources
- **AD-CNAS-KOLEA** — real Windows Server 2025 VM
- **WSUS-CNAS-KOLEA** — real Windows Server 2025 VM
- **PROXY-CNAS-KOLEA** — Squid container
- **WEBSRV-CNAS-KOLEA** — Nginx container

### Important container design
Elastic Agent does **not** run inside the Squid or Nginx service containers.

It runs in two separate containers:
- `agent-proxy`
- `agent-websrv`

Those agent containers read service logs through shared Docker volumes mounted read-only.

### Data paths
- **Windows VMs** → Elastic Agent → Windows / System data streams
- **Squid / Nginx containers** → Elastic Agent containers → service log data streams
- **Optional syslog sources** → Logstash → `syslog-*`
- **Elastic Security** reads from both live data streams and any retained classic indices

### Important note on data streams
Many live integrations write to **data streams**, not classic indices.  
For example, `logs-windows.sysmon_operational-default` is a **data stream** and will appear under:

**Kibana → Stack Management → Index Management → Data Streams**

It may **not** appear where classic indices appear.

---

## 2. Data Tiers — Live-first model

### Tier 1 — Real live Windows telemetry
AD-CNAS-KOLEA and WSUS-CNAS-KOLEA are real Windows Server 2025 VMs in VirtualBox, each running Elastic Agent natively and sending Security, System, PowerShell, Sysmon, and Defender events to Fleet.

### Tier 2 — Real live Docker service logs
PROXY-CNAS-KOLEA runs real **Squid** and WEBSRV-CNAS-KOLEA runs real **Nginx**.  
Their logs are read by **separate Elastic Agent containers** through shared volumes.

### Tier 3 — Optional Logstash ingestion
Logstash remains available for:
- raw syslog
- any legacy replay workflow you still want to keep
- future enrichment / transform pipelines

> **Current lab direction:** EVTX and CICIDS replay setup is no longer the main path. Keep those notes only as optional legacy/reference material.

---

## 3. Elastic Agent vs Logstash — Who Does What

### Elastic Agent handles
- Windows Security events
- Windows System and Application events
- PowerShell logs
- PowerShell Operational logs
- Sysmon logs
- Windows Defender logs
- Squid access logs
- Nginx access / error logs
- Fleet telemetry and host metrics

### Logstash handles
- Raw syslog on UDP/TCP 514
- Optional legacy replay or transformation workflows
- Any future custom parsing pipeline that is easier to implement in Logstash than in Fleet

### Rule of thumb
- **Live endpoint/service telemetry** → Elastic Agent
- **Replay / transformation / custom ingestion** → Logstash

---

## 4. ECS Normalization — Core Requirement

Every event used for detections should land in ECS-compatible fields.  
This allows one rule style to work across:
- Windows live data
- service logs
- future replayed data
- custom syslog sources

### Examples of fields to rely on in rules
- `@timestamp`
- `event.code`
- `event.category`
- `event.action`
- `event.outcome`
- `host.name`
- `user.name`
- `source.ip`
- `destination.ip`
- `process.name`
- `process.pid`
- `threat.tactic.name`
- `threat.technique.name`

### Rule-writing principle
Prefer ECS fields over source-specific field names whenever possible.

---

## 5. Current Deployed State

### Core components

| Component | Status | Notes |
|-----------|--------|-------|
| Elasticsearch (`es01`) | ✅ Running | Security enabled |
| Kibana (`kibana01`) | ✅ Running | Fleet + Security enabled |
| Logstash (`logstash01`) | ✅ Running | Available for syslog / custom pipelines |
| Fleet Server | ✅ Running | Port 8220 |
| AD-CNAS-KOLEA | ✅ Running | Windows Server 2025 VM, Elastic Agent native |
| WSUS-CNAS-KOLEA | ✅ Running | Windows Server 2025 VM, Elastic Agent native |
| PROXY-CNAS-KOLEA | ✅ Running | Squid service container |
| WEBSRV-CNAS-KOLEA | ✅ Running | Nginx service container |
| `agent-proxy` | ✅ Enrolled | Separate Elastic Agent container |
| `agent-websrv` | ✅ Enrolled | Separate Elastic Agent container |

### Confirmed working data streams
- `logs-system.security-default`
- `logs-system.application-default`
- `logs-system.system-default`
- `logs-windows.powershell-default`
- `logs-windows.powershell_operational-default`
- `logs-windows.sysmon_operational-default`
- `logs-windows.windows_defender-default`
- `logs-squid.log-default`

### Still under diagnosis / not fully verified
- `logs-nginx.access-default`
- `logs-nginx.error-default`
- `logs-system.auth-default`
- `logs-system.syslog-default`

### Important cluster note
A **single-node Elasticsearch lab** may show **YELLOW** health because replica shards cannot be assigned.  
This is expected and is not automatically a failure.

---

## 6. Phase 5 — CNAS Containers (Proxy & WebSrv)

AD and WSUS are real Windows VMs.  
Only Proxy and WebSrv remain as Docker services.

```bash
cd ~/ELK/elk_stack
docker compose -f docker-compose.cnas.yml up -d
docker compose up -d agent-proxy agent-websrv
```

### Verify that service logs exist
```bash
docker exec -it PROXY-CNAS-KOLEA ls -lh /var/log/squid/
docker exec -it WEBSRV-CNAS-KOLEA ls -lh /var/log/nginx/
```

### Verify that the agent containers can read them
```bash
docker inspect agent-proxy | grep -A 20 "Mounts"
docker inspect agent-websrv | grep -A 20 "Mounts"

docker exec -it agent-proxy ls -lh /var/log/squid/
docker exec -it agent-websrv ls -lh /var/log/nginx/

docker exec -it agent-proxy tail -5 /var/log/squid/access.log
docker exec -it agent-websrv tail -5 /var/log/nginx/access.log
```

### Important operational rule
Do **not** check Elastic Agent status inside:
- `PROXY-CNAS-KOLEA`
- `WEBSRV-CNAS-KOLEA`

Those are service containers only.

Always inspect:
- `agent-proxy`
- `agent-websrv`

### Minimal-container warning
Minimal Docker images may **not** contain:
- `systemctl`
- `service`
- `rsyslog`
- `/var/log/auth.log`
- `/var/log/syslog`

So missing Linux auth/syslog files in containers is not always a broken setup.

---

## 7. Phase 6 — Windows VMs Setup (AD & WSUS)

### Windows integrations to enable
In Kibana Fleet, the Windows VM policies should include:

- **Security**
- **System**
- **Application**
- **Windows PowerShell**
- **PowerShell Operational**
- **Sysmon Operational**
- **Windows Defender**

### Windows Server 2025 note
On Windows Server 2025, you may see warnings about **skipping query filters** due to Event Log API behavior.  
This means configured Event ID filters may not behave exactly as expected.

### Practical rule
If Event IDs are required in the policy, keep them configured.  
But always validate by checking the **actual arriving data stream events**, not only the policy screen.

---

## 8. Phase 8 — Shared Volume Wiring

```bash
docker volume create proxy-logs
docker volume create websrv-logs
```

### Verify mounts from the agent side
```bash
docker inspect agent-proxy | grep -A 20 "Mounts"
docker inspect agent-websrv | grep -A 20 "Mounts"
```

### Why this matters
The service container writing the log is **not** the same container as the Elastic Agent reading it.  
If the volume is missing, the agent can be healthy but still ingest nothing.

---

## 9. Phase 9 — Ingest & Verify

### Step 1 — Check cluster health
```bash
curl -s -u elastic:changeme "http://localhost:9200/_cluster/health?pretty"
```

### Step 2 — Check data streams
```bash
curl -s -u elastic:changeme "http://localhost:9200/_data_stream?pretty"
```

### Step 3 — Check specific important streams
```bash
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-system.security-default?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-windows.sysmon_operational-default?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-squid.log-default?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-nginx.access-default?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-system.auth-default?pretty"
```

### Step 4 — Check data stream stats
```bash
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-system.security-default/_stats?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-windows.sysmon_operational-default/_stats?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-squid.log-default/_stats?pretty"
```

### Step 5 — Check latest events
```bash
curl -s -u elastic:changeme "http://localhost:9200/logs-system.security-default/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 3,
    "sort": [{"@timestamp":"desc"}]
  }'

curl -s -u elastic:changeme "http://localhost:9200/logs-windows.sysmon_operational-default/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 3,
    "sort": [{"@timestamp":"desc"}]
  }'
```

### Step 6 — Check classic indices only where still relevant
```bash
curl -s -u elastic:changeme \
  "http://localhost:9200/_cat/indices/syslog-*?v&h=index,docs.count&s=index"
```

### Validation rule
A source is considered **working** only if:
1. the stream exists
2. docs are present
3. recent events can be queried

A healthy Fleet agent alone is **not** enough.

---

## 10. Kibana Data Views

Create these manually before dashboards, hunting, or rule validation.

| Data View name | Index pattern | Time field | Purpose |
|----------------|---------------|------------|---------|
| CNAS — Live Security | `logs-system.*,logs-windows.*,logs-squid.*,logs-nginx.*` | `@timestamp` | Main live investigation view |
| Windows Live | `logs-system.*,logs-windows.*` | `@timestamp` | AD / WSUS hunting |
| Proxy + Web | `logs-squid.*,logs-nginx.*` | `@timestamp` | Container service logs |
| Fleet Telemetry | `logs-elastic_agent.*,metrics-*` | `@timestamp` | Agent health and stack monitoring |
| Raw Syslog | `syslog-*` | `@timestamp` | Logstash syslog receiver |

### Useful KQL checks
```kql
host.name: "AD-CNAS-KOLEA"
```

```kql
event.category: "authentication" and event.outcome: "failure"
```

```kql
event.code: "4740"
```

```kql
event.code: "4769"
```

```kql
event.code: "4662"
```

```kql
event.code: "4672"
```

```kql
event.code: "4728"
```

```kql
event.dataset: "windows.sysmon_operational"
```

```kql
data_stream.dataset: "squid.log"
```

---

## 11. Phase 10 — Elastic Security & Detection Rules

### Enable Elastic Security
Kibana → **Security** → **Get started**

### Prebuilt rule categories to enable first
Start with rules that match your confirmed live Windows and service data.

#### Windows / identity focused
Enable first:
- **Account Lockout**
- **Multiple Failed Logons / Brute Force**
- **Kerberoasting**
- **DCSync / Directory Replication**
- **Sensitive Privilege Use**
- **User Added to Privileged Group**
- **Explicit Credential Use**
- **PowerShell suspicious execution**
- **Defender alert / malware-related rules**
- **Sysmon-based suspicious process/file activity**

### Critical detections to validate first
Use these event-code anchors:

| Detection goal | Event code / logic | Why it matters |
|----------------|--------------------|----------------|
| Failed logon activity | `4625` | Password spray / brute force |
| Account lockout | `4740` | High-confidence auth abuse |
| Kerberos service ticket anomalies | `4769` | Kerberoasting |
| Directory replication access | `4662` | DCSync-style behavior |
| Special privileges assigned | `4672` | Privileged logon |
| Privileged group membership changes | `4728` | Persistence / privilege escalation |
| Explicit credential use | `4648` | Credential misuse |
| Sysmon file / process activity | `11`, `1`, etc. | Host-level detection |
| PowerShell suspicious behavior | PowerShell + Operational logs | Script abuse |
| Defender alerts | Defender logs | Malware / AV findings |

### Suggested index patterns for custom rules
Use live patterns like:
```text
logs-system.*, logs-windows.*, logs-squid.*, logs-nginx.*
```

### Example custom rule — brute force
- **Index patterns:** `logs-system.*,logs-windows.*`
- **KQL:** `event.code: "4625" and event.category: "authentication"`
- **Group by:** `source.ip`
- **Threshold:** `>= 5 events in 5 minutes`
- **Severity:** High
- **MITRE:** Credential Access / T1110

### Example custom rule — account lockout
- **Index patterns:** `logs-system.*,logs-windows.*`
- **KQL:** `event.code: "4740"`
- **Severity:** High

### Example custom rule — suspicious privileged use
- **Index patterns:** `logs-system.*,logs-windows.*`
- **KQL:** `event.code: "4672"`
- **Severity:** Medium to High

### Example custom rule — DCSync-style access
- **Index patterns:** `logs-system.*,logs-windows.*`
- **KQL:** `event.code: "4662"`
- **Severity:** Critical

---

## 12. Known Issues & Fixes

### Sysmon stream not visible in index list
**Cause:** `logs-windows.sysmon_operational-default` is a data stream.  
**Fix:** check **Data Streams**, not only classic indices.

### Elasticsearch is YELLOW
**Cause:** single-node lab cannot assign replicas.  
**Fix:** expected in lab.

### Agent healthy but no logs arriving
**Cause:** agent health does not prove file access, parser success, or stream creation.  
**Fix:** verify mounts, file contents, `_data_stream`, `_stats`, and recent `_search`.

### Nginx logs still missing
**Cause:** common causes include wrong path, wrong dataset, wrong parser expectation, or stream not created yet.  
**Fix:** verify:
```bash
docker inspect agent-websrv | grep -A 20 "Mounts"
docker exec -it agent-websrv tail -5 /var/log/nginx/access.log
docker logs agent-websrv --tail 50
```

### Linux auth/syslog missing
**Cause:** minimal containers may not run rsyslog or even create those files.  
**Fix:** only treat as broken if the image is expected to provide them.

### Windows Server 2025 query-filter warning
**Cause:** known Event Log API behavior.  
**Fix:** validate actual incoming event data rather than trusting policy filtering alone.

### Do not test agent commands in service containers
**Cause:** the Elastic Agent is not installed inside Squid/Nginx service containers.  
**Fix:** run checks in `agent-proxy` and `agent-websrv`.

---

## 13. Troubleshooting Reference

### All containers
```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### Check Fleet-visible agents from Kibana API
```bash
curl -s -u elastic:changeme "http://localhost:5601/api/fleet/agents?perPage=20" \
  -H "kbn-xsrf: true"
```

### Check agent container logs
```bash
docker logs agent-proxy --tail 50
docker logs agent-websrv --tail 50
```

### Check Windows VM connectivity
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
That source is **not ingesting yet**, even if Fleet shows the agent as healthy.

---

## 14. Legacy / archived sections

The old EVTX and CICIDS replay sections are no longer the main operating path for this lab.  
Do **not** fully delete them if you still want them for historical reference, but move them into an appendix such as:

- `Appendix A — Legacy EVTX replay workflow`
- `Appendix B — Legacy CICIDS replay workflow`

That keeps the README clean while preserving previous useful work.
