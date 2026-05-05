# Insider Threat Detection via USB Peripheral Logger Network

Real-time insider threat detection for SCIFs and high-security environments.
Monitors USB and Bluetooth peripherals across a fleet of endpoints, correlates
events, scores risk, and alerts on anomalous behaviour — catching the 95% of
data-exfiltration attempts that traditional DLP software misses.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Endpoints (agents)                                             │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────────────────┐ │
│  │ USB Mon  │  │  BT Mon  │  │  eBPF / ETW Monitor           │ │
│  └────┬─────┘  └────┬─────┘  └───────────────┬───────────────┘ │
│       │              │                        │                 │
│       └──────────────┴────────────────────────┘                 │
│                NormalizedEvent (signed, chained)                │
│                       │ HTTPS mTLS                              │
└───────────────────────│─────────────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────────────┐
│  Detection Server                                               │
│                                                                 │
│  ┌──────────────┐  ┌────────────────┐  ┌─────────────────────┐ │
│  │ Honeypot     │  │ Risk Engine    │  │ ML Anomaly          │ │
│  │ (bait VIDs)  │  │ (rules+score)  │  │ (IsolationForest)   │ │
│  └──────┬───────┘  └───────┬────────┘  └──────────┬──────────┘ │
│         │                  │                      │             │
│  ┌──────▼──────────────────▼──────────────────────▼──────────┐ │
│  │  Attack Graph + Cross-Agent Correlation                   │ │
│  └─────────────────────────────┬─────────────────────────────┘ │
│                                │                               │
│  ┌─────────────────────────────▼─────────────────────────────┐ │
│  │  Notification Bus (Email · Slack · CEF Syslog)            │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Dashboard  /dashboard   WebSocket  /ws/alerts          │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  PostgreSQL  ·  mTLS CA  ·  Alembic migrations                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start (Docker Compose)

```bash
# 1. Clone the repository
git clone https://github.com/DANIELKILONZI/Insider-Threat-Detection-via-USB-Peripheral-Logger-Network.git
cd Insider-Threat-Detection-via-USB-Peripheral-Logger-Network

# 2. Copy and edit environment variables
cp .env.example .env
# Edit .env — at minimum set SERVER_API_KEY

# 3. Start the server + PostgreSQL
docker compose up -d

# 4. Check health
curl http://localhost:8443/health
# → {"status": "ok"}

# 5. Open the dashboard
open http://localhost:8443/dashboard
```

### Running without Docker

```bash
pip install -r requirements.txt

# SQLite (development)
export SERVER_DATABASE_URL="sqlite+aiosqlite:///./threatdb.db"
export SERVER_API_KEY="your-secret-key"

# Apply migrations (optional — server auto-creates tables on first run)
alembic upgrade head

uvicorn server.main:app --host 0.0.0.0 --port 8443
```

---

## Agent Installation

### Linux

```bash
pip install -r requirements.txt

# Run as a service
sudo cp agent/service/agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now agent
```

### macOS

```bash
cp agent/service/agent.plist ~/Library/LaunchAgents/com.insider-threat.agent.plist
launchctl load ~/Library/LaunchAgents/com.insider-threat.agent.plist
```

### Windows

```powershell
pip install -r requirements.txt pywin32
python agent/service/agent_windows_service.py install
net start InsiderThreatAgent
```

---

## Environment Variables

All server variables are prefixed with `SERVER_`.

| Variable | Default | Description |
|---|---|---|
| `SERVER_DATABASE_URL` | `sqlite+aiosqlite:///./threatdb.db` | Database connection string |
| `SERVER_API_KEY` | `changeme` | Protect all endpoints. Set to non-default to enable enforcement. |
| `SERVER_RISK_THRESHOLD` | `80.0` | Cumulative score that triggers an alert |
| `SERVER_ROLLING_WINDOW_SECONDS` | `3600` | Alert score accumulation window |
| `SERVER_ANOMALY_CONTAMINATION` | `0.1` | IsolationForest contamination rate |
| `SERVER_REQUIRE_MTLS` | `false` | Enable mutual-TLS client authentication |
| `SERVER_CA_CERT_PATH` | `ca/ca.crt` | Path to CA certificate |
| `SERVER_CA_KEY_PATH` | `ca/ca.key` | Path to CA private key |
| `SERVER_RATE_LIMIT_REQUESTS` | `200` | Max requests per IP per window |
| `SERVER_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit sliding window |
| `SERVER_NOTIFICATION_SINKS` | `` | Comma-separated sinks: `email`, `slack`, `syslog` |
| `SERVER_SMTP_HOST` | `localhost` | SMTP server |
| `SERVER_SMTP_PORT` | `587` | SMTP port |
| `SERVER_SMTP_FROM` | `alerts@threat-detection.local` | Sender address |
| `SERVER_SMTP_TO` | `` | Comma-separated recipients |
| `SERVER_SLACK_WEBHOOK_URL` | `` | Slack Incoming Webhook URL |
| `SERVER_SYSLOG_HOST` | `localhost` | CEF syslog collector host |
| `SERVER_SYSLOG_PORT` | `514` | CEF syslog collector UDP port |
| `SERVER_HOST` | `0.0.0.0` | Bind host |
| `SERVER_PORT` | `8443` | Bind port |

Agent variables are prefixed with `AGENT_`.

---

## API Reference

Full interactive docs available at `http://localhost:8443/docs`.

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/dashboard` | Live HTML dashboard |
| GET | `/api/v1/dashboard/summary` | JSON summary (events, alerts, top devices) |
| WS  | `/ws/alerts` | WebSocket live alert feed |
| POST | `/api/v1/events` | Ingest a `NormalizedEvent` from an agent |
| GET | `/api/v1/events/{agent_id}` | List events for an agent |
| GET | `/api/v1/alerts` | List all alerts |
| GET | `/api/v1/alerts/{id}` | Get a single alert |
| POST | `/api/v1/anchor` | Submit a signed hash-chain anchor |
| POST | `/api/v1/certs/issue` | Issue an agent mTLS certificate |
| POST | `/api/v1/certs/revoke` | Revoke an agent certificate |
| POST | `/api/v1/certs/trusted-hash` | Register a trusted agent binary hash |
| GET | `/api/v1/certs/trusted-hash/{agent_id}` | Retrieve trusted hash |
| POST | `/api/v1/policy/allowlist` | Add a device to the allowlist |
| GET | `/api/v1/policy/allowlist` | List allowlist entries |
| DELETE | `/api/v1/policy/allowlist/{id}` | Remove an allowlist entry |
| GET | `/api/v1/reports/agent/{id}` | Download CSV / JSON compliance report |

---

## Features

### Detection Engine
- **Six additive risk rules** — `unknown_device` (+40), `new_device` (+25), `mass_storage` (+30), `off_hours` (+20), `high_frequency` (+35), `bluetooth_scan` (+15)
- **ML anomaly detection** — per-agent IsolationForest on 5 hourly features
- **Attack graph** — networkx digraph detects exfil patterns, device enumeration, and lateral movement
- **Cross-agent correlation** — same device across 2+ agents flags lateral movement
- **Honeypot traps** — bait VID:PIDs that instantly alert at score=100 when matched

### Agent
- **Tamper-evident hash chain** — every event extends a SHA-256 chain; chain head signed by server
- **mTLS** — per-agent X.509 certificates issued by built-in CA
- **Agent integrity** — binary SHA-256 verified against server-registered trusted hash
- **Platform monitors** — pyudev (Linux USB), pybluez (Bluetooth), BCC eBPF kprobes, Windows ETW

### Operations
- **Device allowlist** — per-agent or org-wide; suppresses `unknown_device` / `new_device` noise
- **Notification bus** — Email (SMTP), Slack webhook, CEF syslog (SIEM-ready)
- **Live dashboard** — HTML + WebSocket push at `/dashboard`
- **Compliance reports** — signed CSV / JSON with chain integrity verification
- **Security middleware** — API-key enforcement + per-IP rate limiting
- **Alembic migrations** — safe schema evolution without table drops

### Infrastructure
- PostgreSQL with asyncpg (connection pool: 10/20)
- Docker Compose with health-checked Postgres
- GitHub Actions CI: matrix Python 3.11/3.12, CodeQL scan, Docker build
- Tag-triggered GHCR release workflow

---

## Development

```bash
# Install all dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/ -q

# Generate a new migration after model changes
SERVER_DATABASE_URL=sqlite:///./threatdb.db alembic revision --autogenerate -m "describe_change"

# Apply migrations
alembic upgrade head
```

---

## Security Notes

1. Change `SERVER_API_KEY` from the default `changeme` before any production deployment.
2. Enable `SERVER_REQUIRE_MTLS=true` and distribute per-agent certificates via the `/api/v1/certs/issue` endpoint.
3. Rotate the CA and server certificates periodically; revoke compromised agent certs via `/api/v1/certs/revoke`.
4. Run behind a TLS-terminating reverse proxy (nginx/Caddy) in production; the server itself speaks plain HTTP by default.

