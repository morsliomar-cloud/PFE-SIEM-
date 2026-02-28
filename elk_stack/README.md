# ELK Stack Security Monitoring: Build Your Own SIEM

Docker-based security monitoring solution using **Elasticsearch, Logstash, and Kibana (ELK Stack)**. Includes ready-to-use telemetry scripts for Linux, Windows, and macOS systems to monitor authentication events, network activity, and suspicious behavior.

> **📖 Complete Tutorial:** For detailed explanations, security baseline interpretation, and advanced SIEM concepts, see our [ELK Stack Security Monitoring Tutorial](https://blog.cyberdesserts.com/elk-stack-security-monitoring-tutorial/)

## Table of Contents

- [What is a SIEM?](#what-is-a-siem)
- [Quick Start](#quick-start)
- [Security Metrics Monitored](#security-metrics-monitored)
- [Telemetry Scripts](#telemetry-scripts)
- [Kibana Setup](#kibana-setup)
- [Troubleshooting](#troubleshooting)
- [Automation](#automation)
- [Stack Management](#stack-management)
- [Resources](#resources)

## What is a SIEM?

A **Security Information and Event Management (SIEM)** system aggregates and analyzes security logs from multiple sources to detect threats in real-time. This project provides a hands-on ELK Stack SIEM for:

- Learning security monitoring and threat detection concepts
- Building a home lab or proof-of-concept environment
- Understanding log aggregation, parsing, and visualization
- Practicing SOC analyst skills

**Why ELK?** Open-source, cost-free alternative to commercial solutions like Splunk, with the same core capabilities for learning and small-scale deployments.

## Quick Start

### Prerequisites

- [Docker Desktop](https://docs.docker.com/get-docker/) installed and running
- Basic command line familiarity

### 1. Clone or Download

```bash
git clone <repository-url>
cd ELK-Docker
```

### 2. Start the Stack

```bash
# Launch all containers
docker compose up -d

# Verify Elasticsearch is running
curl localhost:9200
```

**Access Points:**
- Elasticsearch: http://localhost:9200
- Kibana: http://localhost:5601

### 3. Run Telemetry Scripts

**Linux:**
```bash
./scripts/telemetry/linux_telemetry.sh [HOST] [PORT]
# Example: ./scripts/telemetry/linux_telemetry.sh localhost 514
```

**macOS:**
```bash
./scripts/telemetry/cyber_security_mvp.sh [HOST] [PORT]
```

**Windows (PowerShell as Administrator):**
```powershell
.\scripts\telemetry\windows_telemetry.ps1 [-TargetHost "HOST"] [-Port PORT]
```

## Security Metrics Monitored

| Metric | Description | Baseline Range |
|--------|-------------|----------------|
| **Failed Logins** | Authentication failures | 0-2/hour normal, >10/hour suspicious |
| **Active Connections** | Established TCP connections | 10-50 typical workstation |
| **Network Processes** | Processes with network activity | 5-20 baseline |
| **Temp Files** | New files in /tmp or %TEMP% | 0-5/hour normal |
| **System Load** | CPU load average | <1.0 baseline, >3.0 investigate |

### What's Collected:

- **Authentication Events**: Login failures, SSH sessions, sudo usage
- **Network Activity**: TCP connections, listening ports, active processes
- **File Changes**: New temporary files (malware staging indicator)
- **System Performance**: Load averages, CPU usage

## Telemetry Scripts

### Linux (`linux_telemetry.sh`)

Supports Ubuntu/Debian, RHEL/CentOS, and systemd-based distributions.

**Usage:**
```bash
./scripts/telemetry/linux_telemetry.sh [HOST] [PORT]
```

**Default:** localhost:514

**Collects:** Failed logins, network connections, processes, /tmp files, load average, SSH sessions, sudo usage, listening ports

### macOS (`cyber_security_mvp.sh`)

Uses macOS Unified Logging system.

**Usage:**
```bash
./scripts/telemetry/cyber_security_mvp.sh [HOST] [PORT]
```

**Collects:** Failed auth, TCP connections, network processes, /tmp files, load average

### Windows (`windows_telemetry.ps1`)

Requires Administrator privileges.

**Usage:**
```powershell
.\scripts\telemetry\windows_telemetry.ps1 -TargetHost "HOST" -Port PORT
```

**Collects:** Failed logins (Event ID 4625), TCP connections, network processes, temp files, CPU usage

### Utility Scripts

**Test Syslog:** `scripts/setup/syslog_alert.sh` - Sends test messages to verify connectivity

**Standalone ES:** `scripts/setup/run-elasticsearch.sh` - Run only Elasticsearch for testing

## Kibana Setup

### Create Data View

1. Open Kibana: http://localhost:5601
2. Go to **Stack Management** → **Data Views**
3. Create new view:
   - Pattern: `syslog-*`
   - Timestamp: `@timestamp`

### Example KQL Queries

```kql
# Authentication events
syslog_program:"auth-monitor"

# High network activity (>50 connections)
syslog_program:"network-monitor" AND message:>50

# Files in temp directories
syslog_program:"file-monitor" AND NOT message:"0"

# High system load
syslog_program:"load-monitor" AND message:>2.0
```

## Troubleshooting

### No Data in Elasticsearch

```bash
# Check indices
curl "localhost:9200/_cat/indices/syslog-*?v"

# Verify Logstash is listening
docker exec logstash01 netstat -tlun | grep 514

# Send test message
echo "<34>$(date '+%b %d %H:%M:%S') test myapp: Test" | nc -u localhost 514
```

### Port 514 Permission Denied

Ports <1024 require root/sudo:
```bash
sudo ./scripts/telemetry/linux_telemetry.sh
```

Or edit `docker-compose.yml` to use port 5140 instead.

### Container Issues

```bash
# View logs
docker logs logstash01
docker logs es01
docker logs kibana01

# Restart services
docker compose restart
```

> **📖 Detailed Troubleshooting:** See our [complete troubleshooting guide](https://blog.cyberdesserts.com/elk-stack-security-monitoring-tutorial/#troubleshooting) for advanced debugging steps.

## Automation

### Linux/macOS (cron)

```bash
crontab -e
# Run every 5 minutes
*/5 * * * * /path/to/scripts/telemetry/linux_telemetry.sh localhost 514 >> /var/log/elk.log 2>&1
```

### Windows (Task Scheduler)

1. Create Basic Task
2. Trigger: Daily, repeat every 5 minutes
3. Action: Start program
   - Program: `powershell.exe`
   - Arguments: `-ExecutionPolicy Bypass -File "C:\path\to\windows_telemetry.ps1"`

## Stack Management

### Common Commands

```bash
# Start/Stop
docker compose up -d          # Start all
docker compose down           # Stop all
docker compose restart        # Restart all

# View Logs
docker logs -f logstash01
docker logs -f es01
docker logs -f kibana01

# Clean Up (removes all data)
docker compose down -v
```

### Query Elasticsearch

```bash
# Cluster health
curl "localhost:9200/_cluster/health?pretty"

# List indices
curl "localhost:9200/_cat/indices?v"

# Search today's logs
curl "localhost:9200/syslog-$(date '+%Y.%m.%d')/_search?pretty&size=5"
```

## Stack Components

| Service | Port | Purpose |
|---------|------|---------|
| Elasticsearch | 9200 | Data storage and search |
| Kibana | 5601 | Visualization and dashboards |
| Logstash | 514 (TCP/UDP) | Syslog ingestion and parsing |

## Project Structure

```
├── docker-compose.yml          # ELK stack configuration
├── logstash/
│   └── pipeline/
│       └── logstash.conf       # Grok patterns and parsing rules
├── scripts/
│   ├── telemetry/
│   │   ├── linux_telemetry.sh      # Linux monitoring
│   │   ├── cyber_security_mvp.sh   # macOS monitoring
│   │   ├── syslog_mac.sh          # macOS (alternative)
│   │   └── windows_telemetry.ps1   # Windows monitoring
│   └── setup/
│       ├── run-elasticsearch.sh    # Standalone ES
│       └── syslog_alert.sh         # Test utility
└── README.md
```

## Learning Objectives

This hands-on project teaches:

- **SIEM Fundamentals**: Log aggregation, correlation, and analysis
- **ELK Stack Architecture**: How Elasticsearch, Logstash, and Kibana integrate
- **Security Monitoring**: Detecting authentication failures, network anomalies, suspicious activity
- **Log Parsing**: Syslog protocol and Grok patterns
- **Data Visualization**: Building dashboards with KQL queries
- **Cross-Platform Scripting**: Bash and PowerShell for security telemetry

**Relevant for:** SOC analyst training, Security+ certification labs, cybersecurity education, SIEM skill development

## Resources

### Tutorial & Documentation
- **[ELK Stack Security Monitoring Tutorial](https://blog.cyberdesserts.com/elk-stack-security-monitoring-tutorial/)** - Complete guide with security baselines, advanced queries, and production deployment
- [Elastic Stack Documentation](https://www.elastic.co/guide/index.html)
- [Docker Compose Reference](https://docs.docker.com/compose/)

### Security Frameworks
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls)

---

**Stack Version:** Elasticsearch 9.1.3, Logstash 9.1.3, Kibana 9.1.3
**License:** Educational use
**Maintained by:** [Cyber Desserts](https://blog.cyberdesserts.com)

**⚠️ Note:** This is a development/education environment. For production, enable authentication, TLS, and proper security hardening.
