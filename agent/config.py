"""
agent/config.py – Configuration for the endpoint agent.

Settings are read from environment variables with sane defaults so that
the agent can be deployed via a managed configuration system (GPO, Ansible,
etc.) without touching the source code.
"""

import os

# ── Central Server ───────────────────────────────────────────────────────────
SERVER_URL: str = os.environ.get("ITDN_SERVER_URL", "https://siem.internal:8443")
SERVER_CERT: str = os.environ.get("ITDN_SERVER_CERT", "/etc/itdn/siem-ca.crt")
AGENT_CERT: str = os.environ.get("ITDN_AGENT_CERT", "/etc/itdn/agent.crt")
AGENT_KEY: str = os.environ.get("ITDN_AGENT_KEY", "/etc/itdn/agent.key")

# ── Agent identity ────────────────────────────────────────────────────────────
import socket
HOSTNAME: str = os.environ.get("ITDN_HOSTNAME", socket.gethostname())

# ── Local logging ─────────────────────────────────────────────────────────────
LOCAL_LOG_DIR: str = os.environ.get("ITDN_LOG_DIR", "/var/log/itdn")
LOCAL_LOG_FILE: str = os.path.join(LOCAL_LOG_DIR, "agent.log")

# ── Event buffering ───────────────────────────────────────────────────────────
# Events are queued in memory and flushed every FLUSH_INTERVAL seconds.
FLUSH_INTERVAL: int = int(os.environ.get("ITDN_FLUSH_INTERVAL", "10"))
# Maximum number of events held in memory before a forced flush.
MAX_QUEUE_SIZE: int = int(os.environ.get("ITDN_MAX_QUEUE_SIZE", "500"))

# ── Monitoring ────────────────────────────────────────────────────────────────
# Poll interval (seconds) used for platforms that don't support native udev
POLL_INTERVAL: float = float(os.environ.get("ITDN_POLL_INTERVAL", "2.0"))
# Enable Bluetooth monitoring
BT_MONITOR_ENABLED: bool = os.environ.get("ITDN_BT_ENABLED", "true").lower() == "true"
