"""
agent/config.py – Configuration for the endpoint agent.

Settings are read from environment variables (or a ``.env`` file when
``python-dotenv`` is installed) via a Pydantic ``BaseSettings`` model.
This gives type coercion and startup-time validation without touching
source code.

Import the module-level constants directly::

    from agent.config import SERVER_URL, HOSTNAME, FLUSH_INTERVAL
"""

import socket

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class _AgentSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Central Server ────────────────────────────────────────────────────────
    ITDN_SERVER_URL: str = Field(default="https://siem.internal:8443")
    ITDN_SERVER_CERT: str = Field(default="/etc/itdn/siem-ca.crt")
    ITDN_AGENT_CERT: str = Field(default="/etc/itdn/agent.crt")
    ITDN_AGENT_KEY: str = Field(default="/etc/itdn/agent.key")

    # ── Agent identity ────────────────────────────────────────────────────────
    ITDN_HOSTNAME: str = Field(default_factory=socket.gethostname)

    # ── Local logging ─────────────────────────────────────────────────────────
    ITDN_LOG_DIR: str = Field(default="/var/log/itdn")

    # ── Event buffering ───────────────────────────────────────────────────────
    ITDN_FLUSH_INTERVAL: int = Field(default=10, gt=0)
    ITDN_MAX_QUEUE_SIZE: int = Field(default=500, gt=0)
    ITDN_RETRY_DB: str = Field(default="")

    # ── Monitoring ────────────────────────────────────────────────────────────
    ITDN_POLL_INTERVAL: float = Field(default=2.0, gt=0)
    ITDN_BT_ENABLED: bool = Field(default=True)

    # ── Audit log encryption ──────────────────────────────────────────────────
    # Optional 32-byte hex key (64 hex chars) for AES-256-GCM encryption of the
    # local audit log.  Leave empty to store plaintext (default / dev mode).
    ITDN_LOG_KEY: str = Field(default="")


import os as _os

_s = _AgentSettings()

# ── Public module-level constants ─────────────────────────────────────────────
SERVER_URL: str = _s.ITDN_SERVER_URL
SERVER_CERT: str = _s.ITDN_SERVER_CERT
AGENT_CERT: str = _s.ITDN_AGENT_CERT
AGENT_KEY: str = _s.ITDN_AGENT_KEY

HOSTNAME: str = _s.ITDN_HOSTNAME

LOCAL_LOG_DIR: str = _s.ITDN_LOG_DIR
LOCAL_LOG_FILE: str = _os.path.join(LOCAL_LOG_DIR, "agent.log")
RETRY_DB: str = _s.ITDN_RETRY_DB or _os.path.join(LOCAL_LOG_DIR, "retry.db")

FLUSH_INTERVAL: int = _s.ITDN_FLUSH_INTERVAL
MAX_QUEUE_SIZE: int = _s.ITDN_MAX_QUEUE_SIZE
POLL_INTERVAL: float = _s.ITDN_POLL_INTERVAL
BT_MONITOR_ENABLED: bool = _s.ITDN_BT_ENABLED

LOG_KEY: str = _s.ITDN_LOG_KEY
