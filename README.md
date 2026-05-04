# Insider Threat Detection via USB/Peripheral Logger Network (ITDN)

> Monitors data exfiltration in SCIFs and high-security facilities via USB and
> Bluetooth peripheral logs. Catches insider leaks missed by traditional DLP
> software. Designed for air-gapped, VLAN-isolated enterprise deployments.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Components](#components)
  - [Endpoint Agent](#endpoint-agent)
  - [Central Server](#central-server)
  - [Anomaly Detection Rules](#anomaly-detection-rules)
  - [Splunk Integration](#splunk-integration)
  - [Elasticsearch Integration](#elasticsearch-integration)
  - [Audit Chain](#audit-chain)
  - [SOC Dashboard](#soc-dashboard)
  - [Prometheus Metrics](#prometheus-metrics)
- [Quick Start (Docker Compose)](#quick-start-docker-compose)
- [Production Deployment](#production-deployment)
- [Configuration Reference](#configuration-reference)
- [REST API Reference](#rest-api-reference)
- [Running Tests](#running-tests)
- [Directory Structure](#directory-structure)

---

## Architecture Overview

```
 ┌─────────────────────────────────────────────────────────┐
 │  Endpoints (1 000+ workstations)                        │
 │                                                         │
 │  ┌───────────────┐   USB/BT events   ┌──────────────┐  │
 │  │  USB Monitor  │──────────────────▶│              │  │
 │  ├───────────────┤                   │  Endpoint    │  │
 │  │   BT Monitor  │──────────────────▶│  Agent       │  │
 │  └───────────────┘                   │              │  │
 │                                      │  • Local     │  │
 │                                      │    hash-     │  │
 │                                      │    chain log │  │
 │                                      │  • Disk-     │  │
 │                                      │    backed    │  │
 │                                      │    retry Q   │  │
 │                                      │  • mTLS      │  │
 │                                      │    transport │  │
 │                                      └──────┬───────┘  │
 └─────────────────────────────────────────────┼───────────┘
                         Isolated VLAN │ HTTPS/mTLS
                                       ▼
 ┌─────────────────────────────────────────────────────────┐
 │  Central SIEM Server                                    │
 │                                                         │
 │  ┌────────────────┐  ┌────────────┐  ┌──────────────┐  │
 │  │  Flask REST API│  │   Rules    │  │    Alert     │  │
 │  │  /api/v1/      │─▶│   Engine   │─▶│   Manager    │  │
 │  │  events        │  │            │  │  (dedup)     │  │
 │  │  alerts        │  │ • After    │  └──────┬───────┘  │
 │  │  timeline      │  │   hours    │         │          │
 │  │  audit         │  │ • Unknown  │         ▼          │
 │  │  config        │  │   device   │  ┌──────────────┐  │
 │  │  metrics       │  │ • High vol │  │  Splunk HEC  │  │
 │  └────────┬───────┘  │ • Rapid    │  │  ES Bulk API │  │
 │           │          │   cycle    │  └──────────────┘  │
 │           ▼          └────────────┘         │          │
 │  ┌────────────────┐                          ▼          │
 │  │  SQLite /      │               ┌──────────────────┐  │
 │  │  PostgreSQL    │               │  Splunk / ELK    │  │
 │  │  • events      │               │  Enterprise      │  │
 │  │  • alerts      │               │  Security        │  │
 │  │  • audit chain │               └──────────────────┘  │
 │  └────────────────┘                                     │
 └─────────────────────────────────────────────────────────┘
```

---

## Components

### Endpoint Agent

Located in `agent/`.

| File | Purpose |
|------|---------|
| `agent/usb_monitor.py` | Real-time USB device monitoring via Linux udev (pyudev) or WMI on Windows |
| `agent/bt_monitor.py` | Bluetooth device monitoring via `bluetoothctl` (Linux) or WMI (Windows) |
| `agent/logger.py` | Local tamper-evident JSON-Lines audit log with SHA-256 hash chaining; optional AES-256-GCM encryption at rest |
| `agent/crypto.py` | AES-256-GCM encrypt/decrypt helpers for the audit log |
| `agent/retry_queue.py` | SQLite-backed persistent retry queue – events survive agent restarts and network outages |
| `agent/transport.py` | Batched event transport over mTLS to the central server with disk-backed retry |
| `agent/logging_config.py` | Structured JSON logging setup |
| `agent/config.py` | All settings via environment variables (Pydantic BaseSettings) |
| `agent/main.py` | Entry point – starts all monitors and waits for SIGTERM/SIGINT |

Each device event has the following schema:

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

### Central Server

Located in `server/`.

| File | Purpose |
|------|---------|
| `server/app.py` | Flask REST API (ingest, alerts, timeline, audit, config, metrics, dashboard) |
| `server/database.py` | SQLAlchemy 2 persistence layer (SQLite default; PostgreSQL via `ITDN_DATABASE_URL`) |
| `server/rules.py` | Anomaly detection rules engine |
| `server/alert_manager.py` | Alert deduplication, persistence, and forwarding |
| `server/splunk_forwarder.py` | Splunk HTTP Event Collector (HEC) client |
| `server/es_forwarder.py` | Elasticsearch Bulk API client (ELK alternative/complement) |
| `server/auth.py` | Bearer-token API authentication + per-IP rate limiting |
| `server/schema.py` | Pydantic v2 input validation for event batches |
| `server/rule_config.py` | Runtime-adjustable detection thresholds |
| `server/metrics.py` | In-process Prometheus-format metrics counters |
| `server/logging_config.py` | Structured JSON logging setup |
| `server/config.py` | All settings via environment variables (Pydantic BaseSettings) |
| `server/templates/dashboard.html` | SOC alert dashboard |

### Anomaly Detection Rules

| Rule | Severity | Trigger |
|------|----------|---------|
| `after_hours_device` | HIGH | USB/BT device connected outside business hours (default 22:00–06:00 UTC) |
| `unknown_device` | MEDIUM | Device ID never previously seen on this host |
| `high_volume_transfer` | CRITICAL | Cumulative bytes transferred in last hour > 1 GB (configurable) |
| `rapid_cycle` | HIGH | ≥ 5 connect/disconnect events within 5 minutes (tap-and-go exfil pattern) |

All thresholds are adjustable **at runtime** via `PATCH /api/v1/config` without
redeploying the service, or at startup via environment variables.

### Splunk Integration

Events and alerts are forwarded to Splunk Enterprise Security via the HTTP
Event Collector (HEC):

- **sourcetype `itdn:device_event`** – every raw USB/BT event
- **sourcetype `itdn:alert`** – every fired anomaly alert

Example Splunk saved searches and the `itdn` index definition are in `deploy/splunk_config/`.

### Elasticsearch Integration

An optional Elasticsearch sink (`server/es_forwarder.py`) indexes events and
alerts directly to an ELK cluster using the Elasticsearch Document API
(no extra Python package required).

Configure via:
- `ES_URL` – cluster base URL, e.g. `https://es.internal:9200`
- `ES_API_KEY` – `id:api_key` format (recommended)
- `ES_EVENTS_INDEX` / `ES_ALERTS_INDEX` – destination index names

### Audit Chain

Both the agent and the server maintain independent SHA-256 hash chains:

- **Agent chain** (`/var/log/itdn/agent.log`): each JSON-Lines record includes
  the hash of the previous record. Detectable by replaying with
  `tools/verify_chain.py`.
- **Server chain** (`audit_chain` table): mirrors the same pattern server-side.

**Optional encryption at rest**: set `ITDN_LOG_KEY` to a 64-hex-character
AES-256 key to encrypt agent log records with AES-256-GCM.

```bash
# Generate a key
python -c "import secrets; print(secrets.token_hex(32))"

# Verify an encrypted or plaintext log
ITDN_LOG_KEY=<hex-key> python -m tools.verify_chain --file /var/log/itdn/agent.log

# Verify the server-side chain
python -m tools.verify_chain --server https://siem.internal:8443 --hostname ws-042
```

### SOC Dashboard

Available at `/dashboard` (also root `/`). Auto-refreshes every 30 seconds,
shows open alerts with per-row ACK buttons.

### Prometheus Metrics

`GET /metrics` serves Prometheus text format:

| Metric | Type | Description |
|--------|------|-------------|
| `itdn_events_ingested_total` | counter | Raw device events received |
| `itdn_alerts_fired_total` | counter | Alerts persisted (labelled by `severity`, `rule_name`) |
| `itdn_rule_fires_total` | counter | Rule fires before dedup (labelled by `rule_name`) |
| `itdn_alerts_active` | gauge | Current unacknowledged alert count |

---

## Quick Start (Docker Compose)

```bash
# 1. Clone the repo
git clone https://github.com/DANIELKILONZI/Insider-Threat-Detection-via-USB-Peripheral-Logger-Network
cd Insider-Threat-Detection-via-USB-Peripheral-Logger-Network

# 2. Configure
cp .env.example .env
$EDITOR .env

# 3. Start server + agent
docker compose up --build

# 4. Check health
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
# Generate a strong key and add to .env
python -c "import secrets; print(secrets.token_hex(32))"
# ITDN_API_KEY=<key>

# Agents must send:  Authorization: Bearer <key>
```

### Switch to PostgreSQL

```bash
# In .env
ITDN_DATABASE_URL=postgresql+psycopg2://itdn:secret@db:5432/itdn
```

---

## Production Deployment

### TLS Certificate Provisioning

```bash
# Generate CA + server cert + per-agent certs
./deploy/gen_certs.sh agent-ws001 agent-ws002 agent-laptop01
```

### Server systemd service

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

### Agent deployment via Ansible

```bash
ansible-playbook deploy/ansible/deploy_agent.yml -i inventory.ini
```

---

## Configuration Reference

### Agent (`agent/config.py`)

| Variable | Default | Description |
|----------|---------|-------------|
| `ITDN_SERVER_URL` | `https://siem.internal:8443` | Central server URL |
| `ITDN_SERVER_CERT` | `/etc/itdn/siem-ca.crt` | CA cert for verifying server |
| `ITDN_AGENT_CERT` | `/etc/itdn/agent.crt` | Agent client certificate (mTLS) |
| `ITDN_AGENT_KEY` | `/etc/itdn/agent.key` | Agent private key |
| `ITDN_HOSTNAME` | system hostname | Override reported hostname |
| `ITDN_LOG_DIR` | `/var/log/itdn` | Local audit log directory |
| `ITDN_LOG_KEY` | _(empty)_ | 64-hex AES-256 key for audit-log encryption at rest |
| `ITDN_RETRY_DB` | `\<ITDN_LOG_DIR\>/retry.db` | SQLite path for disk-backed retry queue |
| `ITDN_FLUSH_INTERVAL` | `10` | Seconds between event flushes |
| `ITDN_MAX_QUEUE_SIZE` | `500` | Max events in retry queue before oldest is dropped |
| `ITDN_POLL_INTERVAL` | `2.0` | USB poll interval (non-udev fallback) |
| `ITDN_BT_ENABLED` | `true` | Enable Bluetooth monitoring |
| `ITDN_LOG_LEVEL` | `INFO` | Log level |
| `ITDN_LOG_JSON` | `true` | Emit structured JSON logs (`false` = plain text) |

### Server (`server/config.py`)

| Variable | Default | Description |
|----------|---------|-------------|
| `ITDN_DB_PATH` | `/var/lib/itdn/itdn.db` | SQLite database path |
| `ITDN_DATABASE_URL` | _(SQLite at DB_PATH)_ | Full SQLAlchemy URL; set for PostgreSQL |
| `ITDN_SERVER_HOST` | `0.0.0.0` | Bind address |
| `ITDN_SERVER_PORT` | `8443` | Bind port |
| `ITDN_API_KEY` | _(empty)_ | Bearer token for `POST /api/v1/events`; empty = disabled |
| `ITDN_RATE_LIMIT_MAX` | `200` | Max requests per IP per window |
| `ITDN_RATE_LIMIT_WINDOW_SECS` | `60` | Rate-limit window in seconds |
| `SPLUNK_HEC_URL` | _(internal URL)_ | Splunk HEC endpoint |
| `SPLUNK_HEC_TOKEN` | _(empty)_ | Splunk HEC token; empty = disabled |
| `SPLUNK_INDEX` | `itdn` | Splunk destination index |
| `ES_URL` | _(empty)_ | Elasticsearch base URL; empty = disabled |
| `ES_API_KEY` | _(empty)_ | Elasticsearch API key |
| `ES_EVENTS_INDEX` | `itdn-events` | ES index for raw events |
| `ES_ALERTS_INDEX` | `itdn-alerts` | ES index for alerts |
| `ITDN_AFTER_HOURS_START` | `22` | After-hours start (hour, 0–23) |
| `ITDN_AFTER_HOURS_END` | `6` | After-hours end (hour, 0–23) |
| `ITDN_VOLUME_THRESHOLD_BYTES` | `1073741824` | 1 GB/hr transfer alert threshold |
| `ITDN_RAPID_CYCLE_COUNT` | `5` | Events within window to trigger rapid-cycle alert |
| `ITDN_RAPID_CYCLE_WINDOW_SECS` | `300` | Rapid-cycle detection window (seconds) |
| `ITDN_ALERT_DEDUP_SECS` | `3600` | Alert deduplication window (seconds) |
| `ITDN_LOG_LEVEL` | `INFO` | Log level |
| `ITDN_LOG_JSON` | `true` | Emit structured JSON logs |

---

## REST API Reference

### `POST /api/v1/events`

Ingest device events from agents. Requires `Authorization: Bearer \<ITDN_API_KEY\>` when key is set.

### `GET /api/v1/alerts`

List alerts. Query params: `hostname`, `ack` (true/false), `limit`.

### `PATCH /api/v1/alerts/\<id\>/ack`

Acknowledge an alert. Returns `{"ok": true, "alert_id": \<id\>}`.

### `GET /api/v1/timeline`

Chronological incident timeline (events + alerts interleaved).
Query params: `hostname`, `device_id`, `since` (ISO-8601), `limit`.

### `GET /api/v1/audit`

Server-side audit chain. Query params: `hostname` (required), `limit`.

### `GET /api/v1/config`

Current runtime anomaly-detection thresholds.

### `PATCH /api/v1/config`

Update thresholds at runtime. Body: `{"rapid_cycle_count": 3, ...}`.

### `GET /metrics`

Prometheus-format metrics.

### `GET /api/v1/health`

Liveness probe. Returns `{"status": "ok"}`.

### `GET /dashboard`

SOC alert dashboard (HTML).

---

## Running Tests

```bash
pip install -r requirements.txt
python -m pytest tests/ -v
```

---

## Directory Structure

```
.
├── agent/                      # Endpoint agent
│   ├── config.py               # Pydantic BaseSettings configuration
│   ├── crypto.py               # AES-256-GCM encryption helpers
│   ├── logging_config.py       # Structured JSON logging
│   ├── logger.py               # Tamper-evident audit log (+ optional encryption)
│   ├── retry_queue.py          # SQLite-backed persistent retry queue
│   ├── transport.py            # mTLS event transport with disk-backed retry
│   ├── usb_monitor.py          # USB event monitor
│   ├── bt_monitor.py           # Bluetooth event monitor
│   └── main.py                 # Agent entry point
│
├── server/                     # Central SIEM server
│   ├── config.py               # Pydantic BaseSettings configuration
│   ├── logging_config.py       # Structured JSON logging
│   ├── database.py             # SQLAlchemy 2 (SQLite / PostgreSQL)
│   ├── rules.py                # Anomaly detection rules engine
│   ├── rule_config.py          # Runtime-adjustable thresholds
│   ├── alert_manager.py        # Alert dedup and forwarding
│   ├── schema.py               # Pydantic v2 input validation
│   ├── auth.py                 # API key auth + rate limiting
│   ├── metrics.py              # Prometheus-format metrics
│   ├── splunk_forwarder.py     # Splunk HEC client
│   ├── es_forwarder.py         # Elasticsearch client
│   ├── app.py                  # Flask REST API
│   └── templates/
│       └── dashboard.html      # SOC alert dashboard
│
├── tests/                      # Unit + integration tests
│   ├── conftest.py
│   ├── test_audit_logger.py
│   ├── test_rules.py
│   ├── test_alert_manager.py
│   ├── test_api.py
│   ├── test_auth.py
│   ├── test_schema.py
│   ├── test_rule_config.py
│   ├── test_ack_endpoint.py
│   ├── test_verify_chain.py
│   └── test_integration.py     # Full-stack integration (real SQLite)
│
├── tools/
│   └── verify_chain.py         # Audit chain integrity verifier CLI
│
├── deploy/
│   ├── gen_certs.sh            # CA + server + agent cert provisioning
│   ├── ansible/                # Ansible deployment playbook
│   └── splunk_config/          # Splunk index + saved-search configs
│
├── Dockerfile.agent            # Agent container (non-root user)
├── Dockerfile.server           # Server container (non-root user)
├── docker-compose.yml
├── requirements.txt
└── .env.example
```
