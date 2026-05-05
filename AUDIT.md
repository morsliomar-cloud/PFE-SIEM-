# PFE-SIEM Pre-Production Readiness Audit
## ELK Stack 9.1.3 — CNAS Lab · April 2026

**Scope:** All project files analyzed: `docker-compose.yml`, `docker-compose.cnas.yml` (both copies), `logstash/pipeline/logstash.conf`, `logstash/pipelines.yml`, `fleet-server/elastic-agent.yml`, Nginx and Squid Dockerfiles, entrypoints and configs, plus all telemetry and setup scripts in `elk_stack/scripts/`.

**Generated against:** Current deployed state as documented in README §6.

**Legend:** 🔴 CRITICAL · 🟠 HIGH · 🟡 MEDIUM · 🟢 LOW

---

## Executive Summary

| Severity | Count | Blocks Deployment? |
|---|---|---|
| 🔴 CRITICAL | 14 | YES — fix before any production exposure |
| 🟠 HIGH | 18 | YES — fix before internet-facing deployment |
| 🟡 MEDIUM | 16 | Conditional — fix within first sprint |
| 🟢 LOW | 12 | Optimization backlog |
| **TOTAL** | **60** | |

## Domain 1 — Data Ingestion & Stream Integrity

### 1.5 🟡 Nginx Data Stream Pending
| Field | Detail |
|---|---|
| **Status** | INCOMPLETE |
| **Finding** | README §6 marks `logs-nginx.access-default` as Pending. `scripts/nginx/nginx.conf` has the `combined` log format fix applied but `elk_stack/docker-compose.cnas.yml` uses stock `nginx:latest` without this config. |
| **Risk** | MEDIUM |
| **Fix** | Mount corrected `nginx.conf` into `websrv-cnas` in `elk_stack/docker-compose.cnas.yml`. |

---

### 1.9 🟡 Port 5000 Exposed on Logstash with No Pipeline Input
| Field | Detail |
|---|---|
| **Status** | MISCONFIGURED |
| **Finding** | `docker-compose.yml` exposes `5000:5000` on `logstash01`, but `logstash.conf` has no input on port 5000. All data sent there is silently dropped. |
| **Risk** | MEDIUM |
| **Fix** | Remove `- "5000:5000"` from `logstash01.ports` unless a pipeline input is added. |

---

## Domain 2 — Schema & Data Structuring

### 2.1 🔴 `manage_template: false` with No Pre-Created Index Template
| Field | Detail |
|---|---|
| **Status** | MISCONFIGURED |
| **Finding** | `manage_template: false` disables automatic template creation. Without a pre-created `syslog-*` template, IP addresses map as text and numeric fields map as keywords, breaking all KQL range queries and aggregations. |
| **Risk** | CRITICAL |

```bash
curl -u elastic:${ELASTIC_PASSWORD} -X PUT http://localhost:9200/_index_template/syslog-template \
  -H "Content-Type: application/json" -d '{
    "index_patterns": ["syslog-*"],
    "template": {
      "settings": {"number_of_replicas": 0},
      "mappings": {"properties": {
        "@timestamp": {"type": "date"},
        "source.ip": {"type": "ip"},
        "host.name": {"type": "keyword"},
        "process.name": {"type": "keyword"},
        "facility": {"type": "integer"},
        "severity": {"type": "integer"},
        "message": {"type": "text"}
      }}
    }
  }'
```

### 2.4 🟡 syslog_alert.sh Verification Script Checks Wrong Index
| Field | Detail |
|---|---|
| **Status** | MISCONFIGURED |
| **Finding** | `syslog_alert.sh` checks `GET /syslog-{today}`. If Logstash routes to data streams (current state), this always returns zero docs — a dangerous false-negative. |
| **Risk** | MEDIUM |
| **Fix** | After applying fix 1.2 (route to `syslog-*`), this script works correctly. As a defensive measure, make the index check dynamic: `curl -s localhost:9200/_cat/indices/syslog-*?v`. |

## Domain 3 — Indexing & Storage

### 3.1 🔴 No Index Lifecycle Management (ILM) Policies
| Field | Detail |
|---|---|
| **Status** | MISSING |
| **Finding** | No ILM policies exist. `syslog-*` indices grow indefinitely. On a 50 GB disk, uncontrolled growth hits the flood-stage watermark (95% by default = ~47.5 GB) and Elasticsearch enters read-only mode, blocking all writes. |
| **Risk** | CRITICAL |

```bash
# 1. Create a custom component template that only sets ILM — nothing else
curl -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "http://localhost:9200/_component_template/custom-syslog-ilm" \
  -H "Content-Type: application/json" \
  -d '{
    "template": {
      "settings": {
        "index.lifecycle.name": "syslog-policy"
      }
    }
  }'

  Verify the Existing Composed_of First

Before running step 2, check what's currently in the template so you don't miss any components:

bash
curl -u elastic:${ELASTIC_PASSWORD} \
  "http://localhost:9200/_index_template/logs-system.syslog?pretty" \
  | grep -A 20 "composed_of"

Copy that composed_of array exactly, then append "custom-syslog-ilm" to it.


# 2. Inject it into the managed template via composed_of — append only
curl -u elastic:changeme -X PUT \
  "http://localhost:9200/_index_template/logs-system.syslog" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["logs-system.syslog-*"],
    "data_stream": {},
    "composed_of": [
      "logs@mappings",
      "logs@settings",
      "logs-system.syslog@package",
      "ecs@mappings",
      ".fleet_globals-1",
      ".fleet_agent_id_verification-1",
      "custom-syslog-ilm"
    ],
    "priority": 500
  }'

  curl -u elastic:changeme -X PUT \
  "http://localhost:9200/_ilm/policy/syslog-policy" \
  -H "Content-Type: application/json" \
  -d '{
    "policy": {
      "phases": {
        "hot": {
          "min_age": "0ms",
          "actions": {
            "rollover": {
              "max_size": "5gb",
              "max_age": "7d"
            }
          }
        },
        "delete": {
          "min_age": "30d",
          "actions": {
            "delete": {}
          }
        }
      }
    }
  }'
```

---

### 3.2 🔴 No Backup or Snapshot Repository
| Field | Detail |
|---|---|
| **Status** | MISSING |
| **Finding** | The `esdata` Docker volume is the only persistence layer. `docker compose down -v` permanently deletes all security events, dashboards, Fleet enrollments, and detection rule state. |
| **Risk** | CRITICAL |

```bash
    Registered the repository:

bash
curl -u elastic:changeme -X PUT \
  "http://localhost:9200/_snapshot/local_backup" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "fs",
    "settings": {
      "location": "/usr/share/elasticsearch/snapshots",
      "compress": true
    }
  }'

    Created daily SLM policy — runs at 01:30 AM, retains 14 days, minimum 3 snapshots:

bash
curl -u elastic:changeme -X PUT \
  "http://localhost:9200/_slm/policy/daily-snapshots" \
  -H "Content-Type: application/json" \
  -d '{
    "schedule": "0 30 1 * * ?",
    "name": "<daily-snap-{now/d}>",
    "repository": "local_backup",
    "config": { "include_global_state": true },
    "retention": { "expire_after": "14d", "min_count": 3, "max_count": 14 }
  }'

To trigger a manual snapshot immediately (optional):

bash
curl -u elastic:changeme -X POST \
  "http://localhost:9200/_slm/policy/daily-snapshots/_execute?pretty"

Then check it completed:

bash
curl -u elastic:changeme \
  "http://localhost:9200/_snapshot/local_backup/_all?pretty" | grep -E "state|snapshot"
```

---

### 3.3 🟡 Single-Node Cluster — No Replica Strategy
| Field | Detail |
|---|---|
| **Status** | INCOMPLETE |
| **Finding** | No `number_of_replicas: 0` is set globally. Elasticsearch defaults to 1 replica, so every index starts yellow. Prebuilt "Cluster Status Changed to Red or Yellow" detection rules fire immediately and permanently, masking real alerts. |
| **Fix** | `What was done:

    Applied to all existing indices:

bash
curl -u elastic:changeme -X PUT \
  "http://localhost:9200/_settings" \
  -H "Content-Type: application/json" \
  -d '{"index": {"number_of_replicas": "0"}}'

    Set default for all future indices:

bash
curl -u elastic:changeme -X PUT \
  "http://localhost:9200/_template/default-no-replicas" \
  -H "Content-Type: application/json" \
  -d '{
    "index_patterns": ["*"],
    "order": 0,
    "settings": {
      "number_of_replicas": "0"
    }
  }'

    Targeted remaining unassigned Endpoint backing indices directly:

bash
curl -u elastic:changeme -X PUT \
  "http://localhost:9200/.ds-.logs-endpoint.action.responses-default-2026.04.11-000001,.ds-.logs-endpoint.diagnostic.collection-default-2026.04.11-000001,.ds-.logs-endpoint.actions-default-2026.04.05-000001/_settings" \
  -H "Content-Type: application/json" \
  -d '{"index": {"number_of_replicas": "0"}}'

Result: "status": "green", "unassigned_shards": 0 ✅` |

---

### 3.4 🟡 No Disk Watermark Configuration
| Field | Detail |
|---|---|
| **Status** | MISSING |
| **Finding** | Default watermarks (low: 85%, high: 90%, flood: 95%) on a 50 GB disk mean read-only lockout at 47.5 GB used with no warning. |
| **Fix** |  |
```bash
curl -u elastic:changeme -X PUT \
  "http://localhost:9200/_cluster/settings" \
  -H "Content-Type: application/json" \
  -d '{
    "persistent": {
      "cluster.routing.allocation.disk.watermark.low": "10gb",
      "cluster.routing.allocation.disk.watermark.high": "5gb",
      "cluster.routing.allocation.disk.watermark.flood_stage": "2gb"
    }
  }'

  2 : CHECK
curl -u elastic:changeme \
  "http://localhost:9200/_cluster/settings?pretty"

You'll see the full output like this:

json
{
  "persistent" : {
    "cluster" : {
      "routing" : {
        "allocation" : {
          "disk" : {
            "watermark" : {
              "low" : "10gb",
              "high" : "5gb",
              "flood_stage" : "2gb"
            }
          }
        }
      }
    }
  },
  "transient" : { }
}
```



---

## Domain 4 — Configuration Files & Settings

### 4.1 🔴 Hardcoded Credentials in Version-Controlled Files
| Field | Detail |
|---|---|
| **Status** | CRITICAL SECURITY VIOLATION |
| **Finding** | `ELASTIC_PASSWORD=changeme`, `ELASTICSEARCH_PASSWORD=changeme` (kibana_system), `password: changeme` (Logstash output), and three Kibana encryption keys using sequential hex patterns are all hardcoded in `docker-compose.yml` and `logstash.conf`. |
| **Risk** | CRITICAL |

```bash
Step 1 — Generate .env with Strong Secrets

Run this once in elk_stack/:

bash
cd ~/pfe-siem-project/elk_stack

cat > .env << 'EOF'
# === Elastic Stack Credentials ===
ELASTIC_PASSWORD=<generate: openssl rand -base64 24 | tr -d /+=>
KIBANA_SYSTEM_PASSWORD=<generate: openssl rand -base64 24 | tr -d /+=>
LOGSTASH_PASSWORD=<generate: openssl rand -base64 24 | tr -d /+=>

# === Fleet Tokens (fill after first stack boot) ===
FLEET_SERVICE_TOKEN=
PROXY_ENROLLMENT_TOKEN=
WEBSRV_ENROLLMENT_TOKEN=
AD_ENROLLMENT_TOKEN=
WSUS_ENROLLMENT_TOKEN=

# === Kibana Encryption Keys ===
XPACK_ENCRYPTED_SAVED_OBJECTS_KEY=
XPACK_REPORTING_KEY=
XPACK_SECURITY_KEY=
EOF

# Now fill the generated values inline
sed -i "s|ELASTIC_PASSWORD=.*|ELASTIC_PASSWORD=$(openssl rand -base64 24 | tr -d /+=)|" .env
sed -i "s|KIBANA_SYSTEM_PASSWORD=.*|KIBANA_SYSTEM_PASSWORD=$(openssl rand -base64 24 | tr -d /+=)|" .env
sed -i "s|LOGSTASH_PASSWORD=.*|LOGSTASH_PASSWORD=$(openssl rand -base64 24 | tr -d /+=)|" .env
sed -i "s|XPACK_ENCRYPTED_SAVED_OBJECTS_KEY=.*|XPACK_ENCRYPTED_SAVED_OBJECTS_KEY=$(openssl rand -hex 32)|" .env
sed -i "s|XPACK_REPORTING_KEY=.*|XPACK_REPORTING_KEY=$(openssl rand -hex 32)|" .env
sed -i "s|XPACK_SECURITY_KEY=.*|XPACK_SECURITY_KEY=$(openssl rand -hex 32)|" .env

    ⚠️ Always use Linux/WSL to generate and edit .env — never open it in Notepad. Windows editors save CRLF (\r\n) line endings which embed invisible \r characters into variable values, causing JSON parse errors in curl requests (exactly what happened in this session).

Step 2 — Sanitize Line Endings (Critical on WSL)

bash
# Strip any \r that Windows editors may have introduced
sed -i 's/\r//' .env

# Verify: every line must end with $ not ^M$
cat -A .env | grep -E "PASSWORD|KEY"

Load into current shell:

bash
set -a && source .env && set +a

# Sanity check — brackets must be tight with no space/garbage
echo "[${ELASTIC_PASSWORD}]"
echo "[${KIBANA_SYSTEM_PASSWORD}]"
echo "[${LOGSTASH_PASSWORD}]"

Step 3 — Lock .env Out of Git

bash
echo ".env" >> .gitignore

# Remove it if it was ever accidentally committed
git rm --cached .env 2>/dev/null || true
git rm --cached elk_stack/.env 2>/dev/null || true

git add .gitignore
git commit -m "sec: add .env to .gitignore"

    ⚠️ Even after git rm --cached, the old values remain in git history. If changeme was ever pushed, treat those credentials as permanently compromised and rotate them — which this guide does.

Step 4 — Update docker-compose.yml

Replace every hardcoded value with ${VAR} references. Key changes per service:

es01:

text
- ELASTIC_PASSWORD=${ELASTIC_PASSWORD}

Also replace the broken healthcheck:

text
healthcheck:
  test: ["CMD-SHELL", "curl -sk -u elastic:${ELASTIC_PASSWORD} https://localhost:9200/_cluster/health | grep -q status"]
  interval: 15s
  timeout: 10s
  retries: 20
  start_period: 120s

kibana01:

text
- ELASTICSEARCH_PASSWORD=${KIBANA_SYSTEM_PASSWORD}
- XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=${XPACK_ENCRYPTED_SAVED_OBJECTS_KEY}
- XPACK_REPORTING_ENCRYPTIONKEY=${XPACK_REPORTING_KEY}
- XPACK_SECURITY_ENCRYPTIONKEY=${XPACK_SECURITY_KEY}

logstash01:

text
- LOGSTASH_PASSWORD=${LOGSTASH_PASSWORD}

fleet-server:

text
- FLEET_SERVER_SERVICE_TOKEN=${FLEET_SERVICE_TOKEN}

agent-proxy / agent-websrv:

text
- FLEET_ENROLLMENT_TOKEN=${PROXY_ENROLLMENT_TOKEN}
- FLEET_ENROLLMENT_TOKEN=${WEBSRV_ENROLLMENT_TOKEN}

Step 5 — Update logstash.conf

In logstash/pipeline/logstash.conf, the output block must use the env var:

ruby
output {
  elasticsearch {
    hosts => ["https://es01:9200"]
    user  => "logstash_system"
    password => "${LOGSTASH_PASSWORD}"
    ssl_enabled => true
    ssl_certificate_authorities => ["/usr/share/logstash/config/certs/elastic-ca.pem"]
  }
}

Step 6 — Verify No Hardcoded Secrets Remain

bash
grep -rn "changeme" docker-compose.yml logstash/
grep -rn "password.*=.*[a-zA-Z0-9]\{8,\}" docker-compose.yml logstash/ \
  | grep -v '\${' | grep -v '#'

Both commands must return empty output.
Step 7 — First Boot & Password Activation

    ⚠️ ELASTIC_PASSWORD in the env var only takes effect on first volume initialization. If the esdata volume already exists with a different password, the env var is silently ignored. You must reset via the keystore tool.

bash
# Start ES only first
sudo docker compose up -d es01
sleep 40

# If this is a fresh volume, the env var password should work:
curl -sk -u elastic:${ELASTIC_PASSWORD} https://localhost:9200/_cluster/health

# If you get 401, the volume has a stale password — reset it:
sudo docker exec -it es01 \
  bin/elasticsearch-reset-password -u elastic \
  --url https://localhost:9200 --batch
# → Copy the printed password into .env ELASTIC_PASSWORD, then re-source

Step 8 — Set Built-in User Passwords via API

After ES is healthy and you can authenticate:

bash
# kibana_system
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  -X POST https://localhost:9200/_security/user/kibana_system/_password \
  -H 'Content-Type: application/json' \
  -d "{\"password\": \"${KIBANA_SYSTEM_PASSWORD}\"}"

# logstash_system
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  -X POST https://localhost:9200/_security/user/logstash_system/_password \
  -H 'Content-Type: application/json' \
  -d "{\"password\": \"${LOGSTASH_PASSWORD}\"}"

Both must return {}.
Step 9 — Bring Up Full Stack

bash
sudo docker compose up -d
sleep 40
sudo docker ps
sudo docker logs kibana01 --tail 20

Kibana should connect to ES without auth errors. If it still fails, force-recreate it to reload the new password:

bash
sudo docker compose up -d --force-recreate kibana01
```

---

### 4.2 🔴 No TLS/SSL on Any Communication Channel
| Field | Detail |
|---|---|
| **Status** | CRITICAL |
| **Finding** | `xpack.security.http.ssl.enabled=false` on ES, `FLEET_SERVER_INSECURE_HTTP=1` on Fleet, Kibana → ES over HTTP, Logstash → ES over HTTP. All credentials transmitted in plaintext. |
| **Risk** | CRITICAL — acceptable for isolated local lab, **mandatory to fix before any external exposure** (university demo on shared network). |
| **Fix** | 
```bash
1. Generate CA (PEM format)
bashdocker run --rm \
  -v "$(pwd)/certs:/certs" \
  docker.elastic.co/elasticsearch/elasticsearch-wolfi:9.1.3 bash -c "
    cd /usr/share/elasticsearch
    bin/elasticsearch-certutil ca \
      --pem --out /certs/ca.zip --pass '' --silent
    cd /certs && unzip -o ca.zip
    cp ca/ca.crt elastic-ca.pem
    cp ca/ca.key elastic-ca.key
  "
2. Generate ES + Fleet certs
bashdocker run --rm \
  -v "$(pwd)/certs:/certs" \
  docker.elastic.co/elasticsearch/elasticsearch-wolfi:9.1.3 bash -c "
    cd /usr/share/elasticsearch

    bin/elasticsearch-certutil cert \
      --ca-cert /certs/elastic-ca.pem \
      --ca-key /certs/elastic-ca.key \
      --pem --out /certs/es01.zip \
      --name es01 \
      --dns es01 --dns localhost --ip 127.0.0.1 \
      --pass 'temp123' --silent
    cd /certs && unzip -o es01.zip
    cp es01/es01.crt es01.crt

    cd /usr/share/elasticsearch
    bin/elasticsearch-certutil cert \
      --ca-cert /certs/elastic-ca.pem \
      --ca-key /certs/elastic-ca.key \
      --pem --out /certs/fleet.zip \
      --name fleet-server \
      --dns fleet-server --dns localhost --ip 127.0.0.1 \
      --pass 'temp123' --silent
    cd /certs && unzip -o fleet.zip
    cp fleet-server/fleet-server.crt fleet-server.crt
  "
3. Strip passwords from keys
bashdocker run --rm -v "$(pwd)/certs:/certs" alpine/openssl rsa \
  -in /certs/es01/es01.key -out /certs/es01.key -passin pass:temp123

docker run --rm -v "$(pwd)/certs:/certs" alpine/openssl rsa \
  -in /certs/fleet-server/fleet-server.key -out /certs/fleet-server.key -passin pass:temp123

# Verify both say "BEGIN RSA PRIVATE KEY"
head -2 certs/es01.key
head -2 certs/fleet-server.key
4. Fix file permissions
bashdocker run --rm -v "$(pwd)/certs:/certs" \
  alpine sh -c "chmod 644 /certs/*.pem /certs/*.crt /certs/*.key"
5. Configure Fleet output with CA fingerprint
⚠️ Critical: Do NOT configure the Fleet output using a file path (ssl.certificate_authorities). File paths are Linux container paths and will silently break any agent running on a different OS (e.g. Windows). Use ca_trusted_fingerprint instead — it works on every platform without requiring a file on disk.
Get the fingerprint from your CA:
bashopenssl x509 -noout -fingerprint -sha256 \
  -in certs/elastic-ca.pem | sed 's/.*=//;s/://g'
Set it in docker-compose.yml on the kibana01 service:
yaml- 'XPACK_FLEET_OUTPUTS=[{"id": "fleet-default-output", "name": "default", "is_default": true, "is_default_monitoring": true, "type": "elasticsearch", "hosts": ["https://es01:9200"], "ca_trusted_fingerprint": "<SHA256_HEX>"}]'

Note: Setting XPACK_FLEET_OUTPUTS via environment variable locks the output as read-only in the Kibana UI. This is intentional — it prevents accidental misconfiguration but means all output changes must go through docker-compose.yml followed by docker compose up -d --force-recreate kibana01.

6. Bring up the stack
bashdocker compose down && docker compose up -d
sleep 40
docker ps
7. Final certs/ layout
elastic-ca.pem       ← CA certificate
elastic-ca.key       ← CA private key
es01.crt             ← ES node certificate
es01.key             ← ES node key (unencrypted, RSA PRIVATE KEY)
fleet-server.crt     ← Fleet Server certificate
fleet-server.key     ← Fleet Server key (unencrypted, RSA PRIVATE KEY)

Enrolling agents on non-Linux hosts (Windows)
Agents on Windows (or any OS without access to the container filesystem) cannot use a file-based CA path. The ca_trusted_fingerprint in the Fleet output handles the ES connection, but you must also trust the CA for the Fleet Server TLS handshake at enrollment time.
Recommended approach — import CA into the Windows trust store once:
powershell# Run as Administrator on the Windows VM
# Copy elastic-ca.pem to the VM first, then:
Import-Certificate `
  -FilePath "C:\elastic-ca.pem" `
  -CertStoreLocation Cert:\LocalMachine\Root

# Verify
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*Elastic*" }
Once imported, enroll the agent without needing --certificate-authorities:
powershell# Run as Administrator from the agent installer directory
.\elastic-agent.exe install `
  --url=https://fleet-server:8220 `
  --enrollment-token=<YOUR_POLICY_TOKEN> `
  --non-interactive
  ```

## Domain 5 — Alerting, Monitoring & Detection

### 5.1 🟠 No Kibana Stack Monitoring Enabled
| Field | Detail |
|---|---|
| **Status** | MISSING |
| **Finding** | No visibility into Elasticsearch heap usage, Logstash event drop rate, or Fleet Server degradation without going to CLI. |
| **Fix** | Enable in Kibana: **Stack Management → Stack Monitoring → Turn on monitoring**. |


### 5.6 🟡 Windows Server 2025 Unfiltered Event Collection
| Field | Detail |
|---|---|
| **Status** | INCOMPLETE |
| **Finding** | README §14.4 documents removing all EventID filters. Without filtering, an AD DC generates Event IDs 4634, 4648, 4776 at hundreds per minute, overwhelming the 1 GB ES heap. |
| **Fix** | After removing filters, immediately apply ILM to `logs-system.security-default` (see 3.1) and monitor doc count growth rate for the first 24 hours. Re-add explicit exclusion filters for high-noise benign events (4634, 4776, 5156). |

---

## Domain 7 — Security & Compliance

---

### 7.2 🔴 `elastic` Superuser Used for Logstash Output
| Field | Detail |
|---|---|
| **Status** | CRITICAL |
| **Finding** | A Logstash compromise via malicious syslog payload gives an attacker full `elastic` superuser access to Elasticsearch — reading all alerts, deleting indices, creating backdoor users. |
| **Fix** |

```bash
Here's the complete 7.2 fix from scratch:

## 1 — Create the role
```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_security/role/logstash_writer" \
  -H 'Content-Type: application/json' \
  -d '{
    "cluster": ["monitor", "manage_index_templates", "manage_ilm", "manage_pipeline"],
    "indices": [{
      "names": ["logs-*", ".ds-logs-*"],
      "privileges": ["create_doc", "create_index", "manage", "auto_configure", "create", "index", "write"]
    }]
  }'
```
Expected: `{"role":{"created":true}}`

## 2 — Create the user
```bash
curl -sk -u elastic:${ELASTIC_PASSWORD} -X PUT \
  "https://localhost:9200/_security/user/logstash_writer" \
  -H 'Content-Type: application/json' \
  -d "{
    \"password\": \"${LOGSTASH_PASSWORD}\",
    \"roles\": [\"logstash_writer\"],
    \"full_name\": \"Logstash Output User\"
  }"
```
Expected: `{"created":true}`

## 3 — Update logstash.conf
```bash
sed -i 's/user     => "elastic"/user     => "logstash_writer"/' logstash/pipeline/logstash.conf
sed -i 's/password => "${ELASTIC_PASSWORD}"/password => "${LOGSTASH_PASSWORD}"/' logstash/pipeline/logstash.conf
grep -E "user|password" logstash/pipeline/logstash.conf
```
Expected: both blocks show `logstash_writer` and `${LOGSTASH_PASSWORD}`

## 4 — Update docker-compose.yml
In `logstash01` environment, change:
```yaml
- ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
```
to:
```yaml
- LOGSTASH_PASSWORD=${LOGSTASH_PASSWORD}
```

## 5 — Ensure .env has LOGSTASH_PASSWORD
```bash
grep "LOGSTASH_PASSWORD" .env
# If missing:
echo "LOGSTASH_PASSWORD=LogstashSecure123!" >> .env
```

## 6 — Apply and verify
```bash
sudo docker compose up -d --force-recreate logstash01
sleep 20
sudo docker logs logstash01 --tail 5
# Should show: Pipelines running, NO 403 errors
```

## 7 — Confirm ingestion works
```bash
python -c "
import socket
msg = '<34>May 2 21:00:00 test-host sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(msg.encode(), ('127.0.0.1', 514))
s.close()
print('sent')
"
sleep 5
curl -sk -u elastic:${ELASTIC_PASSWORD} \
  "https://localhost:9200/logs-system.auth-default/_count" | python -m json.tool
# Count should increment → finding 7.2 resolved ✅
```
```

---

### 7.3 🟠 No RBAC for Kibana Users
| Field | Detail |
|---|---|
| **Status** | MISSING |
| **Finding** | Only the `elastic` superuser account is documented. Giving evaluators/professors superuser access risks accidental deletion of dashboards or detection rules. |
| **Fix** | Create a `siem-analyst` role in **Kibana → Stack Management → Security → Roles** with read-only access to `logs-*`, `syslog-*`, `.alerts-*` and create a `analyst` user with that role. |

---

### 7.4 🔴 `.env` File — No `.gitignore` Entry Confirmed
| Field | Detail |
|---|---|
| **Status** | CRITICAL |
| **Finding** | No `.gitignore` file was verified. The `.env` contains Fleet service tokens, enrollment tokens, and (post-fix 4.1) all passwords and Kibana encryption keys. One `git add .` permanently exposes all secrets. |
| **Fix** |

```bash
echo ".env"  >> .gitignore
echo "*.key" >> .gitignore
echo "*.pem" >> .gitignore
git status --short | grep ".env"   # Must return nothing
# If .env appears in git log: git filter-repo --path .env --invert-paths
```

---

### 7.5 🟡 Fleet Enrollment Tokens Unrevoked
| Field | Detail |
|---|---|
| **Status** | MEDIUM |
| **Finding** | Enrollment tokens in `.env` remain valid indefinitely. A leaked `.env` lets an attacker enroll a rogue agent into your Fleet. |
| **Fix** | After confirming all agents are enrolled and healthy, revoke tokens in **Kibana → Fleet → Enrollment Tokens → Revoke**. Enrolled agents are unaffected. |


---

### 7.7 🟡 Kibana Encryption Keys Below Minimum Entropy
| Field | Detail |
|---|---|
| **Status** | MEDIUM |
| **Finding** | Hardcoded keys use sequential hex patterns (`a7f3c1d2e4b5a6f7...`) — not cryptographically random. |
| **Fix** | 1 — Generate 3 new keys

bash
echo "New XPACK_ENCRYPTED_SAVED_OBJECTS_KEY:"
openssl rand -hex 32

echo "New XPACK_REPORTING_KEY:"
openssl rand -hex 32

echo "New XPACK_SECURITY_KEY:"
openssl rand -hex 32

2 — Update .env

bash
nano .env

Replace the 3 lines:

text
XPACK_ENCRYPTED_SAVED_OBJECTS_KEY=<paste first output>
XPACK_REPORTING_KEY=<paste second output>
XPACK_SECURITY_KEY=<paste third output>

Verify no old sequential patterns remain:

bash
grep -E "XPACK_ENCRYPTED|XPACK_REPORTING|XPACK_SECURITY" .env

3 — Apply

bash
sudo docker compose up -d --force-recreate kibana01
sleep 20
sudo docker logs kibana01 --tail 5
# Should show: Kibana is now available |

---

## Domain 8 — Missing Documentation & Operational Gaps

---

### 8.4 🟡 No Pre-Demo Health Check Script
| Field | Detail |
|---|---|
| **Status** | MISSING |
| **Finding** | No single command confirms all containers healthy, all data streams receiving recent data, all Fleet agents online, and detection rules enabled. |
| **Fix** | Create `scripts/setup/pre-demo-check.sh` that runs all health checks and exits non-zero if any critical check fails. |

---

## Prioritized Remediation Roadmap

### Phase A — Before Any External Network Exposure (Do Today)

| # | Finding | Action | Est. Time |
|---|---|---|---|
| A1 | 4.6 | Set `vm.max_map_count=262144` | 5 min |
| A2 | 3.1 | Create ILM policy — prevents disk-full write lockout | 15 min |
| A3 | 3.2 | Register snapshot repository + daily SLM | 20 min |
| A4 | 4.1 | Move all credentials to `.env`, verify `.gitignore` | 30 min |
| A5 | 7.4 | Confirm `.env` not tracked in git | 5 min |
| A6 | 7.2 | Create `logstash_writer` user, remove superuser from Logstash | 15 min |

---

### Phase B — Fix Data Pipeline (This Week)

| # | Finding | Action | Est. Time |
|---|---|---|---|
| B1 | 1.1 | Canonicalize pipeline filename in `pipelines.yml` | 5 min |
| B2 | 1.2 | Fix Logstash output to write to `syslog-*` | 10 min |
| B3 | 2.1 | Create `syslog-*` index template with correct mappings | 20 min |
| B4 | 2.2 | Add ECS field renaming to Logstash filter | 15 min |
| B5 | 1.6 | Fix Squid log format to native (kills `_grokparsefailure`) | 10 min |
| B6 | 2.3 | Designate one canonical `docker-compose.cnas.yml` | 30 min |
| B7 | 1.4 | Fix agent hostnames to CNAS naming scheme | 5 min |
| B8 | 1.7 | Fix Fleet Server healthcheck endpoint | 5 min |

---

### Phase C — Harden & Optimize Before Demo

| # | Finding | Action | Est. Time |
|---|---|---|---|
| C1 | 6.1 | Add `restart: unless-stopped` to ES and Kibana | 5 min |
| C2 | 4.9 | Add `ulimits` to `es01` | 10 min |
| C3 | 4.7 | Increase ES heap to 2 GB | 5 min |
| C4 | 3.3 | Set `number_of_replicas: 0` globally | 5 min |
| C5 | 3.4 | Configure disk watermarks | 10 min |
| C6 | 7.3 | Create `siem-analyst` role and `analyst` viewer user | 20 min |
| C7 | 5.1 | Enable Stack Monitoring | 15 min |
| C8 | 8.4 | Create `pre-demo-check.sh` | 45 min |
| C9 | 4.3 | Drop `pid: host`, remove `SYS_MODULE`/`SYS_ADMIN` from agents | 10 min |
| C10 | 5.4 | Duplicate Linux detection rules, add `syslog-*` index pattern | 30 min |

---

## Appendix — Full Finding Index

| ID | Domain | Severity | Title |
|---|---|---|---|
| 1.1 | Ingestion | 🔴 | Pipeline file identity conflict |
| 1.2 | Ingestion | 🔴 | Syslog output routing contradicts README |
| 1.3 | Ingestion | 🟠 | Orphaned Logstash volume mounts |
| 1.4 | Ingestion | 🟠 | agent-proxy hostname mismatch |
| 1.5 | Ingestion | 🟡 | Nginx data stream pending |
| 1.6 | Ingestion | 🔴 | Squid custom log format incompatible with Elastic |
| 1.7 | Ingestion | 🟠 | Fleet Server healthcheck endpoint unverified |
| 1.8 | Ingestion | 🟢 | Unused fleet-server/elastic-agent.yml |
| 1.9 | Ingestion | 🟡 | Port 5000 exposed, no pipeline input |
| 2.1 | Schema | 🔴 | manage_template false with no index template |
| 2.2 | Schema | 🟠 | Logstash filter produces no ECS fields |
| 2.3 | Schema | 🔴 | Two conflicting docker-compose.cnas.yml files |
| 2.4 | Schema | 🟡 | Verification script checks wrong index |
| 2.5 | Schema | — | run-elasticsearch.sh — DELETED |
| 3.1 | Storage | 🔴 | No ILM policies defined |
| 3.2 | Storage | 🔴 | No backup/snapshot repository |
| 3.3 | Storage | 🟡 | No replica-0 strategy for single-node cluster |
| 3.4 | Storage | 🟡 | No disk watermark configuration |
| 4.1 | Config | 🔴 | Hardcoded credentials in version-controlled files |
| 4.2 | Config | 🔴 | No TLS on any communication channel |
| 4.3 | Config | 🟠 | privileged+pid:host on agent containers |
| 4.4 | Config | 🟡 | /proc/host/proc mount unreliable on WSL2 |
| 4.5 | Config | 🟢 | Deprecated version 3.8 compose syntax |
| 4.6 | Config | 🔴 | No vm.max_map_count for Elasticsearch |
| 4.7 | Config | 🟡 | ES heap at 1 GB insufficient |
| 4.8 | Config | 🟡 | No container memory limits |
| 4.9 | Config | 🟠 | No ulimits for Elasticsearch |
| 4.10 | Config | 🟢 | Single Logstash worker thread |
| 5.1 | Alerting | 🟠 | No Kibana Stack Monitoring |
| 5.2 | Alerting | 🟡 | Detection rules enabled before stream verification |
| 5.3 | Alerting | 🟡 | No notification connector |
| 5.4 | Alerting | 🟠 | Prebuilt rules miss syslog-* index pattern |
| 5.5 | Alerting | 🟡 | No ML anomaly detection jobs |
| 5.6 | Alerting | 🟡 | WS2025 unfiltered collection may overwhelm heap |
| 6.1 | Performance | 🟠 | No restart policy on ES and Kibana |
| 6.2 | Performance | 🟢 | Syslog RFC 3164 timestamp edge case |
| 6.3 | Performance | 🟢 | No Kibana query timeout |
| 7.1 | Security | 🟠 | Elasticsearch audit logging not enabled |
| 7.2 | Security | 🔴 | elastic superuser used for Logstash output |
| 7.3 | Security | 🟠 | No RBAC roles for Kibana users |
| 7.4 | Security | 🔴 | .env not confirmed absent from git history |
| 7.5 | Security | 🟡 | Fleet enrollment tokens unrevoked |
| 7.6 | Security | 🟡 | No network segmentation between services |
| 7.7 | Security | 🟡 | Kibana encryption keys use patterned hex |
| 8.1 | Ops | 🟠 | No Sysmon installation script |
| 8.2 | Ops | 🟡 | No VM agent re-enrollment procedure |
| 8.3 | Ops | 🟢 | Telemetry scripts not scheduled |
| 8.4 | Ops | 🟡 | No pre-demo health check script |

---

*Audit generated against ELK Stack 9.1.3 — CNAS Lab — April 2026*
*Total findings: 47 unique issues across 8 domains (1 resolved by deletion)*
