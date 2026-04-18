# PFE-SIEM — ELK Stack 9.x CNAS Lab

A fully containerised SIEM lab built on **ELK Stack 9.1.3**, simulating four CNAS agency nodes (AD, WSUS, Proxy, WebSrv), ingesting historical attack datasets and live service logs, and running Elastic Security detections with ECS-normalized data.

> **Read this first.** This README separates:
> - **Target architecture** — the intended final design
> - **Verified deployed state** — what was actually confirmed working
> - **Current gaps** — sources that are enabled or expected, but not yet fully verified
>
> For deployment, follow the target architecture.
> For troubleshooting and detection engineering, trust the verified state first.

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

### Windows live outputs
Windows VM events are collected through Elastic Agent and land in data streams such as:
- `logs-system.security-default`
- `logs-system.application-default`
- `logs-system.system-default`
- `logs-windows.powershell-default`
- `logs-windows.powershell_operational-default`
- `logs-windows.sysmon_operational-default`
- `logs-windows.windows_defender-default`

### Historical datasets
Historical attack data is still ingested through Logstash into classic indices:
- `sysmon-*`
- `network-cnas-*`
- `proxy-cnas-*`
- `auth-cnas-*`
- `syslog-*`

---

## 2. Verified Deployed State

### Confirmed working
- Elasticsearch running
- Kibana running
- Logstash running
- Fleet Server running
- Windows VMs enrolled to Fleet
- `logs-system.security-default` receiving data
- `logs-system.application-default` present
- `logs-system.system-default` present
- `logs-windows.powershell-default` present
- `logs-windows.powershell_operational-default` present
- `logs-windows.sysmon_operational-default` receiving live data
- `logs-windows.windows_defender-default` present
- `logs-squid.log-default` receiving data
- Historical `sysmon-*` ingestion working
- Raw `syslog-*` ingestion working

### Still under diagnosis / not fully verified
- `logs-nginx.access-default`
- `logs-nginx.error-default`
- `logs-system.auth-default`
- `logs-system.syslog-default`
- `network-cnas-*` if CICIDS CSVs were not yet dropped
- `auth-cnas-*` if Faker data was not yet generated

### Important interpretation notes
- `logs-windows.sysmon_operational-default` is a **data stream**, not a classic index.
- It must be checked in **Kibana → Stack Management → Index Management → Data Streams**.
- On a single-node lab cluster, **YELLOW** health is expected because replica shards cannot be assigned.

---

## 3. Elastic Agent vs Logstash

### Elastic Agent handles
- Live Windows logs from AD and WSUS
- Live Squid logs from the proxy container
- Live Nginx logs from the web container
- Fleet / agent telemetry
- System metrics

### Logstash handles
- EVTX historical samples
- CICIDS network CSVs
- CICIDS web attack CSVs
- Faker auth baseline events
- Raw syslog on UDP/TCP 514

### Rule of thumb
- **Live machine/service logs** → Elastic Agent
- **Static datasets / transforms / replay** → Logstash

---

## 4. Phase 5 — CNAS Containers (Proxy & WebSrv)

AD and WSUS are real Windows VMs.
Only Proxy and WebSrv remain as Docker services.

```bash
cd ~/ELK/elk_stack
docker compose -f docker-compose.cnas.yml up -d
docker compose up -d agent-proxy agent-websrv
```

### Verify the services generate logs
```bash
docker exec PROXY-CNAS-KOLEA tail -f /var/log/squid/access.log
docker exec WEBSRV-CNAS-KOLEA tail -f /var/log/nginx/access.log
```

### Verify the agent containers can read those logs
```bash
docker inspect agent-proxy | grep -A 20 "Mounts"
docker inspect agent-websrv | grep -A 20 "Mounts"

docker exec -it agent-proxy ls -lh /var/log/squid/
docker exec -it agent-websrv ls -lh /var/log/nginx/

docker exec -it agent-proxy tail -5 /var/log/squid/access.log
docker exec -it agent-websrv tail -5 /var/log/nginx/access.log
```

### Important limitation
Do **not** run Elastic Agent diagnostics inside `PROXY-CNAS-KOLEA` or `WEBSRV-CNAS-KOLEA`.
Those are service containers, not agent containers.

Always inspect:
- `agent-proxy`
- `agent-websrv`

### Minimal-container limitation
Minimal Linux containers may not contain:
- `systemctl`
- `service`
- `rsyslog`
- `/var/log/auth.log`
- `/var/log/syslog`

So missing Linux auth/syslog logs in those containers may be normal unless the image explicitly provides them.

---

## 5. Windows Server 2025 note

When using the Windows integration on Windows Server 2025, Elastic Agent may log a warning similar to:

`skipping query filters for Windows Server 2025 due to known issue with Event Log API and forwarded events`

### What this means
- Event ID filters may not behave exactly as expected.
- If your lab requires specific Event IDs in policy, you can still configure them.
- But you must validate real behavior from the resulting data stream, not only from the Fleet policy screen.

### Practical validation
Check whether expected events are really arriving:
- `event.code: "4634"`
- `event.code: "11"`
- `event.code: "4769"`
- `event.code: "4740"`

---

## 6. Phase 9 — Ingest & Verify

### Step 1 — Check data streams
```bash
curl -s -u elastic:changeme "http://localhost:9200/_data_stream?pretty"
```

### Step 2 — Check stream stats
```bash
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-windows.sysmon_operational-default/_stats?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-system.security-default/_stats?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-squid.log-default/_stats?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-nginx.access-default/_stats?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-system.auth-default/_stats?pretty"
```

### Step 3 — Check recent events
```bash
curl -s -u elastic:changeme "http://localhost:9200/logs-windows.sysmon_operational-default/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 1,
    "sort": [{"@timestamp":"desc"}]
  }'

curl -s -u elastic:changeme "http://localhost:9200/logs-system.security-default/_search?pretty" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 1,
    "sort": [{"@timestamp":"desc"}]
  }'
```

### Step 4 — Check classic indices for Logstash-fed datasets
```bash
curl -s -u elastic:changeme \
  "http://localhost:9200/_cat/indices/sysmon-*,syslog-*,*-cnas-*?v&h=index,docs.count&s=index"
```

### Validation rule
A source is considered **working** only if all three are true:
1. the stream or index exists
2. documents are present
3. recent events can be queried

Healthy agent status alone is **not enough**.

---

## 7. Logstash re-ingest and replay notes

### Clear sincedb and force re-read
```bash
MSYS_NO_PATHCONV=1 docker exec logstash01 sh -c "rm -f /usr/share/logstash/data/sincedb-*"
docker restart logstash01
```

### If replay created duplicates in a data stream
Use `_delete_by_query` before re-running the test.

### Sysmon naming fix
When sending to the live Sysmon destination, the correct target name is:

```ruby
index => "logs-windows.sysmon_operational-default"
```

### Important note
That destination is a **data stream-style name** in your workflow and must be validated from the resulting data stream view, not only from classic index lists.

---

## 8. Kibana Data Views

Create data views manually before running detections or validation queries.

| Data View name | Index pattern | Time field | Purpose |
|----------------|---------------|------------|---------|
| CNAS — Historical + Live | `*-cnas-*,sysmon-*,auth-cnas-*,logs-system.*,logs-windows.*,logs-squid.*,logs-nginx.*` | `@timestamp` | Main investigation view |
| Windows Live | `logs-system.*,logs-windows.*` | `@timestamp` | AD / WSUS live events |
| Proxy + Web | `logs-squid.*,logs-nginx.*` | `@timestamp` | Container service logs |
| Fleet Telemetry | `logs-elastic_agent.*,metrics-*` | `@timestamp` | Agent and stack health |
| Raw Syslog | `syslog-*` | `@timestamp` | Logstash syslog receiver |

### Important notes
- Many live sources are **data streams**, not classic indices.
- Historical EVTX timestamps are from **2020**, so use **All time** or explicitly include 2020 in the time picker.

---

## 9. Detection readiness

Do not enable or trust detection rules until these are confirmed:

- Historical `sysmon-*` present
- Live Windows security data present
- Live Sysmon data present
- Squid logs present
- Nginx logs present if that part is required
- Required Data Views created
- Time picker covers both historical and live ranges when needed

### Example first rules to validate
- `event.code: "4740"` — account lockout
- `event.code: "4625"` — failed login
- `event.code: "4769"` — Kerberos ticket requests
- `event.code: "4662"` — DCSync-related access
- `event.code: "4672"` — special privileges assigned

---

## 10. Known Issues & Fixes

### Sysmon stream does not appear in index list
**Cause:** it is a data stream.  
**Fix:** check **Data Streams**, not only classic indices.

### Elasticsearch health is YELLOW
**Cause:** single-node lab cannot assign replicas.  
**Fix:** expected in lab.

### Agent is healthy but no logs appear
**Cause:** agent health does not prove the file path, parser, or dataset is correct.  
**Fix:** validate mounts, file contents, stream existence, and recent events.

### Nginx logs still missing
**Cause:** can be a path issue, dataset issue, or parser/format mismatch.  
**Fix:** verify volume mount, verify file contents from `agent-websrv`, then verify stream creation in Elasticsearch.

### Linux auth/syslog missing in containers
**Cause:** minimal service containers may not run rsyslog or create those files at all.  
**Fix:** only treat this as a failure if the container image is actually designed to emit those logs.

### Windows Server 2025 query-filter warning
**Cause:** known Event Log API behavior.  
**Fix:** validate actual arriving events rather than trusting policy filtering alone.

### Logstash does not re-read files
**Cause:** `sincedb` remembers read position.  
**Fix:** delete `sincedb-*` and restart Logstash.

---

## 11. Troubleshooting Reference

### All containers
```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### Check agent mounts
```bash
docker inspect agent-proxy | grep -A 20 "Mounts"
docker inspect agent-websrv | grep -A 20 "Mounts"
```

### Check readable log files from agent side
```bash
docker exec -it agent-proxy tail -5 /var/log/squid/access.log
docker exec -it agent-websrv tail -5 /var/log/nginx/access.log
```

### Check agent logs
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

### Check stream existence
```bash
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-system.security-default?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-windows.sysmon_operational-default?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-squid.log-default?pretty"
curl -s -u elastic:changeme "http://localhost:9200/_data_stream/logs-nginx.access-default?pretty"
```

### If a stream returns 404
That source is **not ingesting yet**, even if Fleet shows the agent as healthy.
