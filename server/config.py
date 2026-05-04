"""
server/config.py – Configuration for the ITDN central server.

All settings are read from environment variables so the server can be
configured without touching source code (12-factor style).
"""

import os

# ── Network ───────────────────────────────────────────────────────────────────
SERVER_HOST: str = os.environ.get("ITDN_SERVER_HOST", "0.0.0.0")
SERVER_PORT: int = int(os.environ.get("ITDN_SERVER_PORT", "8443"))
# Path to TLS certificate and private key for the HTTPS listener
TLS_CERT: str = os.environ.get("ITDN_TLS_CERT", "/etc/itdn/server.crt")
TLS_KEY: str = os.environ.get("ITDN_TLS_KEY", "/etc/itdn/server.key")
# CA certificate used to verify agent client certs (mTLS)
CA_CERT: str = os.environ.get("ITDN_CA_CERT", "/etc/itdn/ca.crt")

# ── Persistence ───────────────────────────────────────────────────────────────
DB_PATH: str = os.environ.get("ITDN_DB_PATH", "/var/lib/itdn/itdn.db")
# Full SQLAlchemy database URL.  Defaults to the SQLite path above.
# For PostgreSQL: postgresql+psycopg2://user:password@host:5432/itdn
DATABASE_URL: str = os.environ.get("ITDN_DATABASE_URL", f"sqlite:///{DB_PATH}")

# ── Splunk HEC ────────────────────────────────────────────────────────────────
SPLUNK_HEC_URL: str = os.environ.get(
    "SPLUNK_HEC_URL", "https://splunk.internal:8088/services/collector/event"
)
SPLUNK_HEC_TOKEN: str = os.environ.get("SPLUNK_HEC_TOKEN", "")
SPLUNK_INDEX: str = os.environ.get("SPLUNK_INDEX", "itdn")
# Set to "false" to verify Splunk's TLS cert (recommended in production)
SPLUNK_VERIFY_TLS: bool = os.environ.get("SPLUNK_VERIFY_TLS", "true").lower() == "true"

# ── Anomaly Detection Rules ───────────────────────────────────────────────────
# Hour-of-day (0–23) that defines the start of after-hours (inclusive)
AFTER_HOURS_START: int = int(os.environ.get("ITDN_AFTER_HOURS_START", "22"))
# Hour-of-day (0–23) that defines the end of after-hours (exclusive)
AFTER_HOURS_END: int = int(os.environ.get("ITDN_AFTER_HOURS_END", "6"))
# Transfer volume threshold in bytes/hour that triggers a HIGH alert
VOLUME_THRESHOLD_BYTES: int = int(
    os.environ.get("ITDN_VOLUME_THRESHOLD_BYTES", str(1 * 1024 * 1024 * 1024))  # 1 GB
)
# Number of connect/disconnect cycles within RAPID_CYCLE_WINDOW_SECS that
# triggers a "rapid cycle" alert (tap-and-go exfil pattern)
RAPID_CYCLE_COUNT: int = int(os.environ.get("ITDN_RAPID_CYCLE_COUNT", "5"))
RAPID_CYCLE_WINDOW_SECS: int = int(os.environ.get("ITDN_RAPID_CYCLE_WINDOW_SECS", "300"))

# ── Alert deduplication window ────────────────────────────────────────────────
# Seconds within which duplicate alerts for the same host+device+rule are
# suppressed to avoid alert storms.
ALERT_DEDUP_WINDOW_SECS: int = int(os.environ.get("ITDN_ALERT_DEDUP_SECS", "3600"))

# ── API security ──────────────────────────────────────────────────────────────
# Shared secret for Bearer-token authentication on POST /api/v1/events.
# Leave empty to disable auth (dev / test mode).
API_SECRET_KEY: str = os.environ.get("ITDN_API_KEY", "")

# ── Rate limiting ─────────────────────────────────────────────────────────────
RATE_LIMIT_MAX: int = int(os.environ.get("ITDN_RATE_LIMIT_MAX", "200"))
RATE_LIMIT_WINDOW_SECS: int = int(os.environ.get("ITDN_RATE_LIMIT_WINDOW_SECS", "60"))
