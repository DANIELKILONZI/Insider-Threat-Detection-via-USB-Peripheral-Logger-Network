"""
server/config.py – Configuration for the ITDN central server.

All settings are read from environment variables (or a ``.env`` file when
``python-dotenv`` is installed) via a Pydantic ``BaseSettings`` model.
This gives type coercion, startup-time validation, and surface-level
documentation in one place.

Import the module-level constants directly::

    from server.config import SERVER_HOST, SERVER_PORT, DATABASE_URL
"""

import os

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class _ServerSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Network ───────────────────────────────────────────────────────────────
    ITDN_SERVER_HOST: str = Field(default="0.0.0.0")
    ITDN_SERVER_PORT: int = Field(default=8443)
    ITDN_TLS_CERT: str = Field(default="/etc/itdn/server.crt")
    ITDN_TLS_KEY: str = Field(default="/etc/itdn/server.key")
    ITDN_CA_CERT: str = Field(default="/etc/itdn/ca.crt")

    # ── Persistence ───────────────────────────────────────────────────────────
    ITDN_DB_PATH: str = Field(default="/var/lib/itdn/itdn.db")
    ITDN_DATABASE_URL: str = Field(default="")

    # ── Splunk HEC ────────────────────────────────────────────────────────────
    SPLUNK_HEC_URL: str = Field(
        default="https://splunk.internal:8088/services/collector/event"
    )
    SPLUNK_HEC_TOKEN: str = Field(default="")
    SPLUNK_INDEX: str = Field(default="itdn")
    SPLUNK_VERIFY_TLS: bool = Field(default=True)

    # ── Anomaly Detection Rules ───────────────────────────────────────────────
    ITDN_AFTER_HOURS_START: int = Field(default=22, ge=0, le=23)
    ITDN_AFTER_HOURS_END: int = Field(default=6, ge=0, le=23)
    ITDN_VOLUME_THRESHOLD_BYTES: int = Field(default=1 * 1024 * 1024 * 1024, gt=0)
    ITDN_RAPID_CYCLE_COUNT: int = Field(default=5, gt=0)
    ITDN_RAPID_CYCLE_WINDOW_SECS: int = Field(default=300, gt=0)
    ITDN_ALERT_DEDUP_SECS: int = Field(default=3600, gt=0)

    # ── API security ──────────────────────────────────────────────────────────
    ITDN_API_KEY: str = Field(default="")
    # RBAC: JSON map of "key" -> "role" where role is admin|analyst|readonly.
    # Example: '{"secret123": "admin", "readkey": "readonly"}'
    # When set, ITDN_API_KEY is ignored in favour of this map.
    ITDN_API_KEYS: str = Field(default="")

    # ── Honeypot detection ────────────────────────────────────────────────────
    ITDN_HONEYPOT_VIDS: str = Field(default="")

    # ── Rate limiting ─────────────────────────────────────────────────────────
    ITDN_RATE_LIMIT_MAX: int = Field(default=200, gt=0)
    ITDN_RATE_LIMIT_WINDOW_SECS: int = Field(default=60, gt=0)

    # ── Alert notification channels ───────────────────────────────────────────
    ITDN_SMTP_HOST: str = Field(default="")
    ITDN_SMTP_PORT: int = Field(default=587)
    ITDN_SMTP_USER: str = Field(default="")
    ITDN_SMTP_PASSWORD: str = Field(default="")
    ITDN_SMTP_FROM: str = Field(default="itdn-alerts@localhost")
    ITDN_SMTP_TO: str = Field(default="")       # comma-separated recipient list
    ITDN_SMTP_USE_TLS: bool = Field(default=True)
    ITDN_SLACK_WEBHOOK_URL: str = Field(default="")
    # Minimum severity to emit notifications: LOW | MEDIUM | HIGH | CRITICAL
    ITDN_NOTIFY_MIN_SEVERITY: str = Field(default="HIGH")

    # ── Log retention ─────────────────────────────────────────────────────────
    ITDN_RETENTION_DAYS: int = Field(default=90, gt=0)

    # ── Threat feed ───────────────────────────────────────────────────────────
    # Path to a local newline-delimited file of malicious VID:PID values.
    ITDN_THREAT_FEED_PATH: str = Field(default="")
    # Remote URL to fetch the threat feed from (fetched once on startup).
    ITDN_THREAT_FEED_URL: str = Field(default="")


_s = _ServerSettings()

# ── Public module-level constants ─────────────────────────────────────────────
SERVER_HOST: str = _s.ITDN_SERVER_HOST
SERVER_PORT: int = _s.ITDN_SERVER_PORT
TLS_CERT: str = _s.ITDN_TLS_CERT
TLS_KEY: str = _s.ITDN_TLS_KEY
CA_CERT: str = _s.ITDN_CA_CERT

DB_PATH: str = _s.ITDN_DB_PATH
DATABASE_URL: str = _s.ITDN_DATABASE_URL or f"sqlite:///{_s.ITDN_DB_PATH}"

SPLUNK_HEC_URL: str = _s.SPLUNK_HEC_URL
SPLUNK_HEC_TOKEN: str = _s.SPLUNK_HEC_TOKEN
SPLUNK_INDEX: str = _s.SPLUNK_INDEX
SPLUNK_VERIFY_TLS: bool = _s.SPLUNK_VERIFY_TLS

AFTER_HOURS_START: int = _s.ITDN_AFTER_HOURS_START
AFTER_HOURS_END: int = _s.ITDN_AFTER_HOURS_END
VOLUME_THRESHOLD_BYTES: int = _s.ITDN_VOLUME_THRESHOLD_BYTES
RAPID_CYCLE_COUNT: int = _s.ITDN_RAPID_CYCLE_COUNT
RAPID_CYCLE_WINDOW_SECS: int = _s.ITDN_RAPID_CYCLE_WINDOW_SECS
ALERT_DEDUP_WINDOW_SECS: int = _s.ITDN_ALERT_DEDUP_SECS

API_SECRET_KEY: str = _s.ITDN_API_KEY
API_KEYS: str = _s.ITDN_API_KEYS
RATE_LIMIT_MAX: int = _s.ITDN_RATE_LIMIT_MAX
RATE_LIMIT_WINDOW_SECS: int = _s.ITDN_RATE_LIMIT_WINDOW_SECS

SMTP_HOST: str = _s.ITDN_SMTP_HOST
SMTP_PORT: int = _s.ITDN_SMTP_PORT
SMTP_USER: str = _s.ITDN_SMTP_USER
SMTP_PASSWORD: str = _s.ITDN_SMTP_PASSWORD
SMTP_FROM: str = _s.ITDN_SMTP_FROM
SMTP_TO: str = _s.ITDN_SMTP_TO
SMTP_USE_TLS: bool = _s.ITDN_SMTP_USE_TLS
SLACK_WEBHOOK_URL: str = _s.ITDN_SLACK_WEBHOOK_URL
NOTIFY_MIN_SEVERITY: str = _s.ITDN_NOTIFY_MIN_SEVERITY

RETENTION_DAYS: int = _s.ITDN_RETENTION_DAYS

THREAT_FEED_PATH: str = _s.ITDN_THREAT_FEED_PATH
THREAT_FEED_URL: str = _s.ITDN_THREAT_FEED_URL

HONEYPOT_VIDS: str = _s.ITDN_HONEYPOT_VIDS
