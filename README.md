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
  - [Audit Chain](#audit-chain)
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
 │  │  audit         │  │   hours    │         │          │
 │  └────────┬───────┘  │ • Unknown  │         ▼          │
 │           │          │   device   │  ┌──────────────┐  │
 │           ▼          │ • High vol │  │   Splunk HEC │  │
 │  ┌────────────────┐  │ • Rapid    │  │   Forwarder  │  │
 │  │  SQLite / DB   │  │   cycle    │  └──────────────┘  │
 │  │  • events      │  └────────────┘         │          │
 │  │  • alerts      │                          ▼          │
 │  │  • audit chain │               ┌──────────────────┐  │
 │  └────────────────┘               │  Splunk          │  │
 │                                   │  Enterprise      │  │
 └───────────────────────────────────│  Security        │  │
                                     └──────────────────┘
```

---

## Components

### Endpoint Agent

Located in `agent/`.

| File | Purpose |
|------|---------|
| `agent/usb_monitor.py` | Real-time USB device monitoring via Linux udev (pyudev) or polling fallback for Windows |
| `agent/bt_monitor.py` | Bluetooth device monitoring via `bluetoothctl` (Linux) or WMI (Windows) |
| `agent/logger.py` | Local tamper-evident JSON-Lines audit log with SHA-256 hash chaining |
| `agent/transport.py` | Batched event transport over mTLS to the central server |
| `agent/config.py` | All settings via environment variables |
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
| `server/app.py` | Flask REST API (ingest, alerts, audit endpoints) |
| `server/database.py` | SQLite persistence: events, alerts, server-side audit chain |
| `server/rules.py` | Anomaly detection rules engine |
| `server/alert_manager.py` | Alert deduplication, persistence, and Splunk forwarding |
| `server/splunk_forwarder.py` | Splunk HTTP Event Collector (HEC) client |
| `server/config.py` | All settings via environment variables |

### Anomaly Detection Rules

| Rule | Severity | Trigger |
|------|----------|---------|
| `after_hours_device` | HIGH | USB/BT device connected outside business hours (default 22:00–06:00 UTC) |
| `unknown_device` | MEDIUM | Device ID never previously seen on this host |
| `high_volume_transfer` | CRITICAL | Cumulative bytes transferred in last hour > 1 GB (configurable) |
| `rapid_cycle` | HIGH | ≥ 5 connect/disconnect events within 5 minutes (tap-and-go exfil pattern) |

All thresholds are configurable via environment variables – see
[Configuration Reference](#configuration-reference).

### Splunk Integration

Events and alerts are forwarded to Splunk Enterprise Security via the HTTP
Event Collector (HEC):

- **sourcetype `itdn:device_event`** – every raw USB/BT event
- **sourcetype `itdn:alert`** – every fired anomaly alert

Example Splunk saved searches and the `itdn` index definition are in
`deploy/splunk_config/`.

### Audit Chain

Both the agent and the server maintain independent SHA-256 hash chains:

- **Agent chain** (`/var/log/itdn/agent.log`): each JSON-Lines record includes
  the hash of the previous record. Any modification to a historical record
  breaks the chain, which is detectable by replaying the file.
- **Server chain** (`audit_chain` table in SQLite): mirrors the same pattern
  server-side so chain integrity can be verified even if an endpoint is
  compromised.

---

## Quick Start (Docker Compose)

```bash
# 1. Clone the repo
git clone https://github.com/DANIELKILONZI/Insider-Threat-Detection-via-USB-Peripheral-Logger-Network
cd Insider-Threat-Detection-via-USB-Peripheral-Logger-Network

# 2. Configure (optional – Splunk token, thresholds, etc.)
cp .env.example .env
$EDITOR .env

# 3. Start server + agent
docker compose up --build

# 4. Check server health
curl http://localhost:8443/api/v1/health
# → {"status": "ok"}

# 5. View alerts
curl http://localhost:8443/api/v1/alerts | python -m json.tool
```

---

## Production Deployment

### Server

1. Provision a hardened Linux VM on an isolated VLAN (no internet access).
2. Generate TLS certificates (CA + server cert + per-agent client certs).
3. Set environment variables (see [Configuration Reference](#configuration-reference)).
4. Run the Docker image or install as a systemd service:

```ini
# /etc/systemd/system/itdn-server.service
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

### Endpoint Agent (1 000+ workstations)

Deploy via your enterprise endpoint management tool (GPO, Ansible, SCCM):

```bash
# Install on each Linux endpoint
pip install pyudev

# /etc/itdn/agent.env
ITDN_SERVER_URL=https://siem.internal:8443
ITDN_SERVER_CERT=/etc/itdn/ca.crt
ITDN_AGENT_CERT=/etc/itdn/agent-ws042.crt
ITDN_AGENT_KEY=/etc/itdn/agent-ws042.key
ITDN_HOSTNAME=ws-classified-042
```

```ini
# /etc/systemd/system/itdn-agent.service
[Unit]
Description=ITDN Endpoint Agent
After=network.target

[Service]
EnvironmentFile=/etc/itdn/agent.env
ExecStart=/usr/bin/python -m agent.main
WorkingDirectory=/opt/itdn
Restart=always
User=root

[Install]
WantedBy=multi-user.target
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
| `ITDN_FLUSH_INTERVAL` | `10` | Seconds between event flushes |
| `ITDN_MAX_QUEUE_SIZE` | `500` | Max events buffered in memory |
| `ITDN_POLL_INTERVAL` | `2.0` | USB poll interval (non-udev fallback) |
| `ITDN_BT_ENABLED` | `true` | Enable Bluetooth monitoring |

### Server (`server/config.py`)

| Variable | Default | Description |
|----------|---------|-------------|
| `ITDN_DB_PATH` | `/var/lib/itdn/itdn.db` | SQLite database path |
| `ITDN_SERVER_HOST` | `0.0.0.0` | Bind address |
| `ITDN_SERVER_PORT` | `8443` | Bind port |
| `SPLUNK_HEC_URL` | _(empty)_ | Splunk HEC endpoint URL |
| `SPLUNK_HEC_TOKEN` | _(empty)_ | Splunk HEC authentication token |
| `SPLUNK_INDEX` | `itdn` | Splunk destination index |
| `ITDN_AFTER_HOURS_START` | `22` | After-hours start (hour, 0–23) |
| `ITDN_AFTER_HOURS_END` | `6` | After-hours end (hour, 0–23) |
| `ITDN_VOLUME_THRESHOLD_BYTES` | `1073741824` | 1 GB/hr transfer alert threshold |
| `ITDN_RAPID_CYCLE_COUNT` | `5` | Events within window to trigger rapid-cycle alert |
| `ITDN_RAPID_CYCLE_WINDOW_SECS` | `300` | Rapid-cycle detection window (seconds) |
| `ITDN_ALERT_DEDUP_SECS` | `3600` | Alert deduplication window (seconds) |

---

## REST API Reference

### `POST /api/v1/events`

Ingest device events from agents.

**Request body:**
```json
{
  "events": [
    {
      "event_type": "connected",
      "device_id": "0781:5567",
      "hostname": "ws-042",
      "timestamp": "2024-01-15T23:32:44Z",
      "transfer_bytes": 0
    }
  ]
}
```

**Response:**
```json
{"ok": true, "stored": 1}
```

---

### `GET /api/v1/alerts`

List alerts.

**Query parameters:**
- `hostname` – filter by host
- `ack` – `true` or `false` to filter by acknowledgement status
- `limit` – max results (default 200)

**Response:**
```json
{
  "alerts": [
    {
      "id": 1,
      "created_at": "2024-01-15 23:32:45",
      "hostname": "ws-042",
      "device_id": "0781:5567",
      "rule_name": "after_hours_device",
      "severity": "HIGH",
      "description": "Device 0781:5567 connected at 23:32 on ws-042 – outside business hours.",
      "acknowledged": 0
    }
  ],
  "count": 1
}
```

---

### `GET /api/v1/audit`

Retrieve the server-side audit chain for a host.

**Query parameters:**
- `hostname` – **required**
- `limit` – max records (default 500)

**Response:**
```json
{
  "hostname": "ws-042",
  "count": 3,
  "records": [
    {
      "id": 1,
      "recorded_at": "2024-01-15 23:32:45",
      "hostname": "ws-042",
      "prev_hash": "0000...0000",
      "event_json": "{...}",
      "record_hash": "a3f2..."
    }
  ]
}
```

---

### `GET /api/v1/health`

Liveness probe. Returns `{"status": "ok"}` with HTTP 200.

---

## Running Tests

```bash
pip install flask pytest pytest-cov
python -m pytest tests/ -v
```

All 33 tests cover:
- Hash-chain integrity and tamper detection (audit logger)
- All four anomaly detection rules
- Alert deduplication logic
- REST API endpoints (ingest, alerts, audit, health)

---

## Directory Structure

```
.
├── agent/                      # Endpoint agent
│   ├── config.py               # Agent configuration
│   ├── usb_monitor.py          # USB event monitor (udev / poll)
│   ├── bt_monitor.py           # Bluetooth event monitor
│   ├── logger.py               # Local tamper-evident audit log
│   ├── transport.py            # mTLS event transport
│   └── main.py                 # Agent entry point
│
├── server/                     # Central SIEM server
│   ├── config.py               # Server configuration
│   ├── database.py             # SQLite persistence layer
│   ├── rules.py                # Anomaly detection rules engine
│   ├── alert_manager.py        # Alert dedup and forwarding
│   ├── splunk_forwarder.py     # Splunk HEC client
│   └── app.py                  # Flask REST API
│
├── tests/                      # Unit + integration tests
│   ├── test_audit_logger.py
│   ├── test_rules.py
│   ├── test_alert_manager.py
│   └── test_api.py
│
├── deploy/
│   └── splunk_config/
│       ├── indexes.conf        # Splunk index definition
│       └── saved_searches.conf # Splunk correlation searches
│
├── Dockerfile.agent            # Agent container image
├── Dockerfile.server           # Server container image
├── docker-compose.yml          # Dev / small-scale deployment
├── requirements.txt            # Python dependencies
└── .env.example                # Environment variable template
```
