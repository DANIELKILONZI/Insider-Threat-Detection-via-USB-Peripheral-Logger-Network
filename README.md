# Insider Threat Detection via USB/Peripheral Logger Network (ITDN)

> **Detect, alert on, and audit USB and Bluetooth peripheral activity across
> hundreds of endpoints — purpose-built for SCIFs, air-gapped labs, and
> high-security enterprise environments.**

ITDN catches the class of insider threat that traditional DLP solutions miss:
physical data exfiltration via thumb drives, mobile phones in MTP mode, and
rogue Bluetooth devices. A lightweight Python agent runs silently on every
workstation, streams tamper-evident event logs to a central SIEM server over
mutual TLS, and fires real-time anomaly alerts that land in the SOC dashboard,
Splunk, or Elasticsearch within seconds.

---

## Table of Contents

- [Highlights](#highlights)
- [Architecture](#architecture)
- [Components](#components)
  - [Endpoint Agent](#endpoint-agent)
  - [Central Server](#central-server)
  - [Anomaly Detection Rules](#anomaly-detection-rules)
  - [Risk Scoring & Anomaly Detection](#risk-scoring--anomaly-detection)
  - [Attack Graph Analysis](#attack-graph-analysis)
  - [Audit Chain & Tamper Evidence](#audit-chain--tamper-evidence)
  - [Remote Log Anchoring](#remote-log-anchoring)
  - [Agent Integrity Verification](#agent-integrity-verification)
  - [Honeypot Device Traps](#honeypot-device-traps)
  - [SOC Dashboard](#soc-dashboard)
  - [Prometheus Metrics](#prometheus-metrics)
  - [Splunk Integration](#splunk-integration)
  - [Elasticsearch Integration](#elasticsearch-integration)
- [Quick Start (Docker Compose)](#quick-start-docker-compose)
- [Production Deployment](#production-deployment)
- [Configuration Reference](#configuration-reference)
- [REST API Reference](#rest-api-reference)
- [Running Tests](#running-tests)
- [CI / GitHub Actions](#ci--github-actions)
- [Directory Structure](#directory-structure)
- [Author](#author)

---

## Highlights

| Capability | Detail |
|---|---|
| **Cross-platform monitoring** | Linux udev / eBPF, Windows WMI, Bluetooth on both |
| **Tamper-evident logs** | SHA-256 hash-chained JSON-Lines with optional AES-256-GCM encryption |
| **Remote anchoring** | HMAC-signed chain-head hashes submitted to the server every 5 min |
| **6 detection rules** | After-hours, unknown device, high-volume, rapid-cycle, cross-host lateral movement, honeypot |
| **Risk scoring** | Per-host cumulative score weighted by alert severity |
| **Statistical anomaly detection** | Z-score over rolling hourly event windows |
| **Attack graph builder** | Identifies multi-host lateral movement patterns |
| **Agent self-integrity** | SHA-256 hash of the agent binary registered and re-checked at runtime |
| **mTLS everywhere** | Client certificate auth between every agent and the server |
| **SOC dashboard** | Live alert feed, colour-coded risk gauges, anomaly σ column |
| **SIEM integrations** | Splunk HEC, Elasticsearch Bulk API |
| **Prometheus metrics** | Scrape-ready `/metrics` endpoint |
| **116 automated tests** | Unit + full-stack integration, Python 3.11 & 3.12, CodeQL on every PR |

---

## Architecture

```
 ┌─────────────────────────────────────────────────────────────┐
 │  Endpoints (1 000+ workstations)                            │
 │                                                             │
 │  ┌───────────────┐   USB/BT events   ┌────────────────────┐ │
 │  │  USB Monitor  │──────────────────▶│                    │ │
 │  ├───────────────┤                   │  Endpoint Agent    │ │
 │  │  BT Monitor   │──────────────────▶│                    │ │
 │  ├───────────────┤                   │  • Hash-chain log  │ │
 │  │  eBPF Monitor │──────────────────▶│  • Disk retry Q    │ │
 │  └───────────────┘                   │  • mTLS transport  │ │
 │                                      │  • Log anchoring   │ │
 │                                      │  • Self-integrity  │ │
 │                                      └────────┬───────────┘ │
 └───────────────────────────────────────────────┼─────────────┘
                         Isolated VLAN │ HTTPS / mTLS
                                       ▼
 ┌─────────────────────────────────────────────────────────────┐
 │  Central SIEM Server                                        │
 │                                                             │
 │  ┌──────────────┐  ┌──────────┐  ┌────────────────────┐    │
 │  │ Flask REST   │  │  Rules   │  │   Alert Manager    │    │
 │  │ API          │─▶│  Engine  │─▶│   (dedup + store)  │    │
 │  │ /api/v1/…    │  │  6 rules │  └──────────┬─────────┘    │
 │  └──────┬───────┘  └──────────┘             │              │
 │         │                                   ▼              │
 │         ▼          ┌──────────┐  ┌──────────────────────┐  │
 │  ┌──────────────┐  │  Risk    │  │  Splunk HEC /        │  │
 │  │  SQLite /    │  │  Scorer  │  │  Elasticsearch API   │  │
 │  │  PostgreSQL  │  ├──────────┤  └──────────────────────┘  │
 │  │              │  │ Anomaly  │                             │
 │  │  • events    │  │ Detector │  ┌──────────────────────┐  │
 │  │  • alerts    │  ├──────────┤  │  SOC Dashboard       │  │
 │  │  • audit     │  │ Attack   │  │  /dashboard          │  │
 │  │  • risk      │  │ Graph    │  └──────────────────────┘  │
 │  │  • anchors   │  └──────────┘                            │
 │  └──────────────┘                                          │
 └─────────────────────────────────────────────────────────────┘
```

---

## Components

### Endpoint Agent

Located in `agent/`. Runs as a non-root system service on each workstation.

| File | Purpose |
|------|---------|
| `agent/usb_monitor.py` | Real-time USB monitoring via Linux udev (pyudev) or Windows WMI |
| `agent/bt_monitor.py` | Bluetooth monitoring via `bluetoothctl` (Linux) or WMI (Windows) |
| `agent/ebpf_monitor.py` | Kernel-level USB event capture for Linux kernels with BPF support |
| `agent/logger.py` | Local tamper-evident JSON-Lines audit log with SHA-256 hash chaining and optional AES-256-GCM encryption |
| `agent/crypto.py` | AES-256-GCM encrypt/decrypt helpers |
| `agent/retry_queue.py` | SQLite-backed persistent retry queue — events survive restarts and network outages |
| `agent/transport.py` | Batched event delivery over mTLS with disk-backed retry |
| `agent/anchor_scheduler.py` | Periodic HMAC-signed chain-head submission to the server |
| `agent/integrity.py` | Hashes the running agent binary and registers/re-checks against the server |
| `agent/logging_config.py` | Structured JSON logging |
| `agent/config.py` | All settings via environment variables (Pydantic BaseSettings) |
| `agent/main.py` | Entry point — starts all monitors, waits for SIGTERM/SIGINT |

**Event schema**

```json
{
  "event_type": "connected",
  "device_id": "0781:5567",
  "serial": "4C530001234567",
  "manufacturer": "SanDisk",
  "product": "Ultra USB 3.0",
  "bus_path": "/sys/bus/usb/devices/1-1.2",
  "timestamp": "2024-01-15T23:32:44Z",
  "hostname": "ws-classified-042",
  "transfer_bytes": 0
}
```

---

### Central Server

Located in `server/`. Runs as a single Flask process backed by SQLite (default)
or PostgreSQL.

| File | Purpose |
|------|---------|
| `server/app.py` | Flask REST API — ingest, alerts, timeline, audit, config, risk, anomaly, attack graph, anchoring, integrity, dashboard, metrics |
| `server/database.py` | SQLAlchemy 2 persistence (SQLite default; PostgreSQL via `ITDN_DATABASE_URL`) |
| `server/rules.py` | 6-rule anomaly detection engine |
| `server/alert_manager.py` | Alert deduplication, persistence, and SIEM forwarding |
| `server/risk_scoring.py` | Per-host cumulative risk score weighted by alert severity |
| `server/anomaly.py` | Z-score statistical anomaly detector over rolling hourly windows |
| `server/baseline.py` | First-seen / last-seen device baseline per host |
| `server/attack_graph.py` | Lateral-movement attack graph builder and pattern detector |
| `server/honeypot.py` | Honeypot device detection against `ITDN_HONEYPOT_VIDS` |
| `server/normalized_event.py` | Canonical event normalisation shared by rules and scoring |
| `server/schema.py` | Pydantic v2 input validation for event batches |
| `server/auth.py` | Bearer-token API authentication + per-IP rate limiting |
| `server/rule_config.py` | Runtime-adjustable detection thresholds |
| `server/metrics.py` | In-process Prometheus-format metrics |
| `server/splunk_forwarder.py` | Splunk HTTP Event Collector (HEC) client |
| `server/es_forwarder.py` | Elasticsearch Bulk API client |
| `server/logging_config.py` | Structured JSON logging |
| `server/config.py` | All settings via environment variables (Pydantic BaseSettings) |
| `server/templates/dashboard.html` | SOC alert dashboard with risk gauges and anomaly indicators |

---

### Anomaly Detection Rules

All six rules run on every ingested event. Thresholds are adjustable at runtime
via `PATCH /api/v1/config` without redeploying.

| Rule | Severity | Trigger |
|------|----------|---------|
| `after_hours_device` | HIGH | USB/BT device connected outside business hours (default 22:00–06:00 UTC) |
| `unknown_device` | MEDIUM | Device ID never previously seen on this host |
| `high_volume_transfer` | CRITICAL | Cumulative bytes transferred in the last hour > 1 GB (configurable) |
| `rapid_cycle` | HIGH | ≥ 5 connect/disconnect events within 5 minutes — classic tap-and-go exfil |
| `cross_agent_device` | CRITICAL | Same device ID seen on a second host within the last hour — possible lateral movement |
| `honeypot_device` | CRITICAL | Device VID matches a configured honeypot — indicates device cloning or a targeted attack |

---

### Risk Scoring & Anomaly Detection

- **`GET /api/v1/risk?hostname=<host>`** — returns a cumulative integer risk
  score weighted by the severity of all past alerts for that host
  (CRITICAL = 100 pts, HIGH = 50, MEDIUM = 20, LOW = 5).
- **`GET /api/v1/anomaly?hostname=<host>`** — runs a z-score detector over the
  last hour of events and returns a float anomaly score. Scores > 2.0 are
  highlighted in the SOC dashboard.

---

### Attack Graph Analysis

`GET /api/v1/attack_graph?hostname=<host>` builds a directed graph of device
movements across hosts derived from the event history and detects known
exfiltration patterns (e.g. a device seen on a classified host and then on a
networked printer). The response includes both the raw graph and a list of
human-readable findings.

---

### Audit Chain & Tamper Evidence

Both the agent and the server maintain independent SHA-256 hash-chained records:

- **Agent chain** (`/var/log/itdn/agent.log`) — each JSON-Lines record embeds
  the hash of the previous record. Breaking the chain is detectable by replaying
  it with `tools/verify_chain.py`.
- **Server chain** (`audit_chain` DB table) — mirrors the same pattern
  server-side for independent corroboration.

**Encryption at rest** — set `ITDN_LOG_KEY` to a 64-hex-character AES-256 key
to encrypt every agent log record with AES-256-GCM. The key never leaves the
agent host.

```bash
# Generate a key
python -c "import secrets; print(secrets.token_hex(32))"

# Verify an encrypted or plaintext local log
ITDN_LOG_KEY=<hex-key> python -m tools.verify_chain --file /var/log/itdn/agent.log

# Verify the server-side audit chain for a hostname
python -m tools.verify_chain --server https://siem.internal:8443 --hostname ws-042

# Verify chain AND display the last 5 remote anchors
python -m tools.verify_chain --server https://siem.internal:8443 --hostname ws-042 --anchors
```

Exit codes: `0` = intact, `1` = tamper/gap detected, `2` = usage or connectivity error.

---

### Remote Log Anchoring

Every `ITDN_ANCHOR_INTERVAL` seconds (default 300 s) the agent computes an
HMAC-SHA256 of its current chain-head hash and `POST`s it to
`/api/v1/anchor`. The server countersigns with `ITDN_API_KEY` and stores the
anchor.

A SOC analyst can retrieve anchors with `GET /api/v1/anchors?agent_id=<hostname>`
or pass `--anchors` to `tools/verify_chain.py` to display them alongside the
chain verification output. This detects offline log tampering even when an
agent was temporarily isolated from the network.

---

### Agent Integrity Verification

At startup the agent hashes its own binary and calls
`POST /api/v1/integrity/register` to establish a trusted baseline. On every
subsequent start it calls `POST /api/v1/integrity/check`; a hash mismatch fires
an alert and can block the agent from submitting events, guarding against
agent binary substitution attacks.

---

### Honeypot Device Traps

Set `ITDN_HONEYPOT_VIDS` to a comma-separated list of USB vendor IDs (the first
four hex characters of a `device_id`, e.g. `0781,058f`). Any connection of a
device whose VID appears in this list fires a CRITICAL `honeypot_device` alert,
indicating that an attacker may be cloning a known-safe device to bypass the
`unknown_device` rule.

---

### SOC Dashboard

Available at `/dashboard` (and at `/`). Auto-refreshes every 30 seconds and
shows:

- **Open Alerts** table — sortable by severity, with one-click ACK per row.
- **Top Risk Hosts** — colour-coded risk score gauge (green → amber → red) plus
  a per-host anomaly σ indicator for each affected hostname.
- **Top Offending Hosts** — ranked by open alert count.

---

### Prometheus Metrics

`GET /metrics` returns Prometheus text format:

| Metric | Type | Description |
|--------|------|-------------|
| `itdn_events_ingested_total` | counter | Raw device events received |
| `itdn_alerts_fired_total` | counter | Alerts persisted (labelled `severity`, `rule_name`) |
| `itdn_rule_fires_total` | counter | Rule fires before deduplication (labelled `rule_name`) |
| `itdn_alerts_active` | gauge | Current unacknowledged alert count |

---

### Splunk Integration

Events and alerts are forwarded to Splunk Enterprise Security via HEC:

- **`itdn:device_event`** sourcetype — every raw USB/BT event
- **`itdn:alert`** sourcetype — every fired anomaly alert

Example saved searches and the `itdn` index definition live in
`deploy/splunk_config/`.

---

### Elasticsearch Integration

An optional ELK sink (`server/es_forwarder.py`) indexes events and alerts to an
Elasticsearch cluster using the Document API (no extra Python package needed).

| Variable | Purpose |
|----------|---------|
| `ES_URL` | Cluster base URL, e.g. `https://es.internal:9200` |
| `ES_API_KEY` | `id:api_key` format (recommended) |
| `ES_EVENTS_INDEX` | Destination index for raw events (default `itdn-events`) |
| `ES_ALERTS_INDEX` | Destination index for alerts (default `itdn-alerts`) |

---

## Quick Start (Docker Compose)

```bash
# 1. Clone
git clone https://github.com/DANIELKILONZI/Insider-Threat-Detection-via-USB-Peripheral-Logger-Network
cd Insider-Threat-Detection-via-USB-Peripheral-Logger-Network

# 2. Configure
cp .env.example .env
$EDITOR .env           # set ITDN_API_KEY at minimum

# 3. Start server + agent
docker compose up --build

# 4. Health check
curl http://localhost:8443/api/v1/health
# → {"status": "ok"}

# 5. View alerts
curl http://localhost:8443/api/v1/alerts | python -m json.tool

# 6. SOC dashboard
open http://localhost:8443/dashboard

# 7. Prometheus metrics
curl http://localhost:8443/metrics
```

### Enable API Authentication

```bash
# Generate a strong random key
python -c "import secrets; print(secrets.token_hex(32))"

# Add to .env
ITDN_API_KEY=<generated-key>

# Agents and CLI tools must supply:
#   Authorization: Bearer <key>
```

### Switch to PostgreSQL

```bash
# In .env
ITDN_DATABASE_URL=postgresql+psycopg2://itdn:${POSTGRES_PASSWORD}@db:5432/itdn
POSTGRES_PASSWORD=changeme
```

---

## Production Deployment

### TLS Certificate Provisioning

```bash
# Generate a CA, server cert, and one client cert per agent hostname
./deploy/gen_certs.sh agent-ws001 agent-ws002 agent-laptop01
```

### Server — systemd service

```ini
[Unit]
Description=ITDN Central Server
After=network.target

[Service]
EnvironmentFile=/etc/itdn/server.env
ExecStart=/usr/bin/python -m server.app
WorkingDirectory=/opt/itdn
Restart=always
User=itdn

[Install]
WantedBy=multi-user.target
```

### Agent — deploy via Ansible

```bash
ansible-playbook deploy/ansible/deploy_agent.yml -i inventory.ini
```

---

## Configuration Reference

### Agent (`agent/config.py`)

| Variable | Default | Description |
|----------|---------|-------------|
| `ITDN_SERVER_URL` | `https://siem.internal:8443` | Central server base URL |
| `ITDN_SERVER_CERT` | `/etc/itdn/siem-ca.crt` | CA cert for server TLS verification |
| `ITDN_AGENT_CERT` | `/etc/itdn/agent.crt` | Agent mTLS client certificate |
| `ITDN_AGENT_KEY` | `/etc/itdn/agent.key` | Agent mTLS private key |
| `ITDN_HOSTNAME` | system hostname | Override the hostname reported in events |
| `ITDN_LOG_DIR` | `/var/log/itdn` | Local audit log directory |
| `ITDN_LOG_KEY` | _(empty)_ | 64-hex AES-256 key for audit-log encryption at rest |
| `ITDN_RETRY_DB` | `<LOG_DIR>/retry.db` | SQLite path for the disk-backed retry queue |
| `ITDN_FLUSH_INTERVAL` | `10` | Seconds between event batch flushes |
| `ITDN_MAX_QUEUE_SIZE` | `500` | Max buffered events before oldest are dropped |
| `ITDN_POLL_INTERVAL` | `2.0` | USB poll interval in seconds (non-udev fallback) |
| `ITDN_BT_ENABLED` | `true` | Enable Bluetooth monitoring |
| `ITDN_ANCHOR_INTERVAL` | `300` | Seconds between log-chain anchor submissions |
| `ITDN_LOG_LEVEL` | `INFO` | Log verbosity |
| `ITDN_LOG_JSON` | `true` | Emit structured JSON logs (`false` = plain text) |

### Server (`server/config.py`)

| Variable | Default | Description |
|----------|---------|-------------|
| `ITDN_DB_PATH` | `/var/lib/itdn/itdn.db` | SQLite database file path |
| `ITDN_DATABASE_URL` | _(SQLite at DB_PATH)_ | Full SQLAlchemy URL; override for PostgreSQL |
| `ITDN_SERVER_HOST` | `0.0.0.0` | Bind address |
| `ITDN_SERVER_PORT` | `8443` | Bind port |
| `ITDN_API_KEY` | _(empty)_ | Bearer token for authenticated endpoints and anchor signing; empty = auth disabled |
| `ITDN_RATE_LIMIT_MAX` | `200` | Max requests per IP per window |
| `ITDN_RATE_LIMIT_WINDOW_SECS` | `60` | Rate-limit window in seconds |
| `ITDN_AFTER_HOURS_START` | `22` | After-hours window start (hour 0–23) |
| `ITDN_AFTER_HOURS_END` | `6` | After-hours window end (hour 0–23) |
| `ITDN_VOLUME_THRESHOLD_BYTES` | `1073741824` | High-volume transfer threshold (bytes/hr) |
| `ITDN_RAPID_CYCLE_COUNT` | `5` | Event count threshold for rapid-cycle rule |
| `ITDN_RAPID_CYCLE_WINDOW_SECS` | `300` | Rapid-cycle detection window in seconds |
| `ITDN_ALERT_DEDUP_SECS` | `3600` | Alert deduplication window in seconds |
| `ITDN_HONEYPOT_VIDS` | _(empty)_ | Comma-separated USB VIDs treated as honeypot (e.g. `0781,058f`) |
| `SPLUNK_HEC_URL` | _(internal URL)_ | Splunk HEC endpoint |
| `SPLUNK_HEC_TOKEN` | _(empty)_ | Splunk HEC token; empty = forwarding disabled |
| `SPLUNK_INDEX` | `itdn` | Splunk destination index |
| `ES_URL` | _(empty)_ | Elasticsearch base URL; empty = forwarding disabled |
| `ES_API_KEY` | _(empty)_ | Elasticsearch API key (`id:key` format) |
| `ES_EVENTS_INDEX` | `itdn-events` | ES index for raw events |
| `ES_ALERTS_INDEX` | `itdn-alerts` | ES index for alerts |
| `ITDN_LOG_LEVEL` | `INFO` | Log verbosity |
| `ITDN_LOG_JSON` | `true` | Emit structured JSON logs |

---

## REST API Reference

All endpoints are served on the port set by `ITDN_SERVER_PORT` (default 8443).
Endpoints marked **🔒** require `Authorization: Bearer <ITDN_API_KEY>` when a
key is configured.

| Method | Path | Description |
|--------|------|-------------|
| POST 🔒 | `/api/v1/events` | Ingest a batch of device events from an agent |
| GET | `/api/v1/alerts` | List alerts (`hostname`, `ack`, `limit` query params) |
| PATCH | `/api/v1/alerts/<id>/ack` | Acknowledge a specific alert |
| GET | `/api/v1/timeline` | Chronological event + alert timeline (`hostname`, `device_id`, `since`, `limit`) |
| GET | `/api/v1/audit` | Server-side audit chain records (`hostname` required, `limit`) |
| GET | `/api/v1/risk` | Per-host cumulative risk score (`hostname` required) |
| GET | `/api/v1/baseline` | Device first-seen / last-seen baseline (`hostname` required) |
| GET | `/api/v1/anomaly` | Statistical anomaly score for a host (`hostname` required) |
| GET | `/api/v1/attack_graph` | Lateral-movement attack graph + findings (`hostname` required) |
| POST 🔒 | `/api/v1/anchor` | Submit a signed log-chain anchor (`agent_id`, `chain_head_hash`) |
| GET | `/api/v1/anchors` | List stored anchors for an agent (`agent_id` required) |
| POST 🔒 | `/api/v1/integrity/register` | Register a trusted agent binary hash |
| POST 🔒 | `/api/v1/integrity/check` | Verify an agent binary hash against the trusted baseline |
| GET | `/api/v1/config` | Current runtime detection thresholds |
| PATCH | `/api/v1/config` | Update thresholds at runtime (no restart needed) |
| GET | `/api/v1/health` | Liveness probe — returns `{"status": "ok"}` |
| GET | `/metrics` | Prometheus-format metrics |
| GET | `/dashboard` | SOC alert dashboard (HTML) |

---

## Running Tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

The suite contains **116 tests** covering unit behaviour and full-stack
integration against a real in-memory SQLite database.

---

## CI / GitHub Actions

The pipeline at `.github/workflows/ci.yml` runs automatically on every push and
pull request:

| Job | Description |
|-----|-------------|
| `test` | Installs `requirements.txt`, runs `pytest` with line-level coverage on Python 3.11 and 3.12, uploads `coverage.xml` as a build artefact |
| `docker-build` | Builds both `Dockerfile.server` and `Dockerfile.agent` to catch image regressions |
| `codeql` | GitHub CodeQL SAST scan (Python, `security-and-quality` query suite) |

---

## Directory Structure

```
.
├── agent/                          # Endpoint agent
│   ├── config.py                   # Pydantic BaseSettings configuration
│   ├── crypto.py                   # AES-256-GCM helpers
│   ├── logging_config.py           # Structured JSON logging
│   ├── logger.py                   # Tamper-evident hash-chained audit log
│   ├── retry_queue.py              # SQLite-backed persistent retry queue
│   ├── transport.py                # mTLS event transport with disk-backed retry
│   ├── usb_monitor.py              # USB event monitor
│   ├── bt_monitor.py               # Bluetooth event monitor
│   ├── ebpf_monitor.py             # eBPF-based USB monitor (Linux)
│   ├── anchor_scheduler.py         # Periodic log-chain anchor submission
│   ├── integrity.py                # Agent self-integrity checker
│   └── main.py                     # Agent entry point
│
├── server/                         # Central SIEM server
│   ├── config.py                   # Pydantic BaseSettings configuration
│   ├── logging_config.py           # Structured JSON logging
│   ├── database.py                 # SQLAlchemy 2 (SQLite / PostgreSQL)
│   ├── schema.py                   # Pydantic v2 event-batch validation
│   ├── normalized_event.py         # Canonical event normalisation
│   ├── rules.py                    # 6-rule anomaly detection engine
│   ├── rule_config.py              # Runtime-adjustable thresholds
│   ├── alert_manager.py            # Alert dedup, persistence, and forwarding
│   ├── risk_scoring.py             # Per-host cumulative risk scoring
│   ├── anomaly.py                  # Z-score statistical anomaly detector
│   ├── baseline.py                 # Device baseline tracking
│   ├── attack_graph.py             # Lateral-movement attack graph builder
│   ├── honeypot.py                 # Honeypot VID detection
│   ├── auth.py                     # API key auth + per-IP rate limiting
│   ├── metrics.py                  # Prometheus-format metrics
│   ├── splunk_forwarder.py         # Splunk HEC client
│   ├── es_forwarder.py             # Elasticsearch Bulk API client
│   ├── app.py                      # Flask REST API (all endpoints)
│   └── templates/
│       └── dashboard.html          # SOC alert dashboard
│
├── tests/                          # 116 unit + integration tests
│   ├── conftest.py
│   ├── test_api.py
│   ├── test_rules.py
│   ├── test_alert_manager.py
│   ├── test_audit_logger.py
│   ├── test_auth.py
│   ├── test_schema.py
│   ├── test_rule_config.py
│   ├── test_ack_endpoint.py
│   ├── test_verify_chain.py
│   ├── test_risk_scoring.py
│   ├── test_anomaly.py
│   ├── test_baseline.py
│   ├── test_attack_graph.py
│   ├── test_honeypot.py
│   ├── test_cross_agent.py
│   ├── test_anchoring.py
│   ├── test_integrity.py
│   ├── test_normalized_event.py
│   └── test_integration.py         # Full-stack integration (real SQLite)
│
├── tools/
│   └── verify_chain.py             # Audit-chain integrity verifier (--file / --server / --anchors)
│
├── deploy/
│   ├── gen_certs.sh                # CA + server + per-agent cert generation
│   ├── ansible/                    # Ansible agent deployment playbook
│   └── splunk_config/              # Splunk index config + saved searches
│
├── .github/
│   └── workflows/
│       └── ci.yml                  # CI: test, docker-build, CodeQL
│
├── Dockerfile.agent                # Agent container image (non-root)
├── Dockerfile.server               # Server container image (non-root)
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

---

## Author

**Daniel Kilonzi** ([@DANIELKILONZI](https://github.com/DANIELKILONZI))

ITDN is an original research and engineering project designed, architected, and
implemented in its entirety by Daniel Kilonzi. The project covers four
implementation phases — from the core USB/BT monitoring agent and tamper-evident
audit chain, through SIEM integrations and production hardening, to Phase 4's
advanced threat-intelligence features: statistical anomaly detection, cumulative
risk scoring, lateral-movement attack graphs, honeypot device traps, remote log
anchoring, and agent self-integrity verification.

---

*Licensed under the MIT License. See `LICENSE` for details.*
