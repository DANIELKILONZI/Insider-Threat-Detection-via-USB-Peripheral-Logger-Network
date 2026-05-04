"""
server/database.py – Persistence layer for events, alerts, and the
server-side audit chain.

Uses SQLAlchemy Core so both SQLite (default, for single-server deployments)
and PostgreSQL (for 1 000+ endpoint / multi-server deployments) are
supported out of the box.

Switching backends
------------------
Set ``ITDN_DATABASE_URL`` to a PostgreSQL DSN::

    ITDN_DATABASE_URL=postgresql+psycopg2://user:password@host:5432/itdn

When this variable is absent the server falls back to the SQLite file at
``ITDN_DB_PATH`` (default: ``/var/lib/itdn/itdn.db``).

Public interface
----------------
All functions that return rows yield plain ``dict`` objects so callers are
decoupled from the underlying driver's row type.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import sqlalchemy as sa
from sqlalchemy import text

from server.config import DATABASE_URL

_GENESIS_HASH = "0" * 64
_lock = threading.Lock()
_engine: Optional[sa.Engine] = None


# ── Timestamp helpers ─────────────────────────────────────────────────────────

def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _cutoff(window_secs: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=window_secs)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


# ── Engine factory ────────────────────────────────────────────────────────────

def _get_engine() -> sa.Engine:
    global _engine
    if _engine is None:
        kwargs: Dict[str, Any] = {}
        if DATABASE_URL.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            kwargs["poolclass"] = sa.pool.StaticPool
        else:
            # PostgreSQL: explicit connection pooling for multi-agent deployments.
            # pool_size: persistent connections kept open between requests.
            # max_overflow: extra connections allowed above pool_size under load.
            # pool_pre_ping: verify a connection is alive before using it (handles
            #   server-side idle timeouts).
            # pool_recycle: return connections to the pool after 1 h to avoid
            #   stale-connection errors from PostgreSQL's tcp_keepalives.
            kwargs["pool_size"] = 10
            kwargs["max_overflow"] = 20
            kwargs["pool_pre_ping"] = True
            kwargs["pool_recycle"] = 3600
        _engine = sa.create_engine(DATABASE_URL, **kwargs)
    return _engine


# ── Schema definition ─────────────────────────────────────────────────────────

_metadata = sa.MetaData()

_events_tbl = sa.Table(
    "events",
    _metadata,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("received_at", sa.Text, nullable=False),
    sa.Column("hostname", sa.Text, nullable=False),
    sa.Column("event_type", sa.Text, nullable=False),
    sa.Column("device_id", sa.Text, nullable=False),
    sa.Column("serial", sa.Text),
    sa.Column("manufacturer", sa.Text),
    sa.Column("product", sa.Text),
    sa.Column("bus_path", sa.Text),
    sa.Column("transfer_bytes", sa.Integer, default=0),
    sa.Column("raw_json", sa.Text, nullable=False),
)

_alerts_tbl = sa.Table(
    "alerts",
    _metadata,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("created_at", sa.Text, nullable=False),
    sa.Column("hostname", sa.Text, nullable=False),
    sa.Column("device_id", sa.Text, nullable=False),
    sa.Column("rule_name", sa.Text, nullable=False),
    sa.Column("severity", sa.Text, nullable=False),
    sa.Column("description", sa.Text, nullable=False),
    sa.Column("raw_event_json", sa.Text, nullable=False),
    sa.Column("acknowledged", sa.Integer, default=0),
)

_audit_tbl = sa.Table(
    "audit_chain",
    _metadata,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("recorded_at", sa.Text, nullable=False),
    sa.Column("hostname", sa.Text, nullable=False),
    sa.Column("prev_hash", sa.Text, nullable=False),
    sa.Column("event_json", sa.Text, nullable=False),
    sa.Column("record_hash", sa.Text, nullable=False, unique=True),
)

_log_anchors_tbl = sa.Table(
    "log_anchors",
    _metadata,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("agent_id", sa.Text, nullable=False),
    sa.Column("chain_head_hash", sa.Text, nullable=False),
    sa.Column("anchored_at", sa.Text, nullable=False),
    sa.Column("server_signature", sa.Text, nullable=False),
)

_risk_scores_tbl = sa.Table(
    "risk_scores",
    _metadata,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("hostname", sa.Text, nullable=False, unique=True),
    sa.Column("score", sa.Integer, default=0),
    sa.Column("window_start", sa.Text, nullable=False),
    sa.Column("window_end", sa.Text, nullable=False),
    sa.Column("updated_at", sa.Text, nullable=False),
)

_device_baseline_tbl = sa.Table(
    "device_baseline",
    _metadata,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("hostname", sa.Text, nullable=False),
    sa.Column("device_id", sa.Text, nullable=False),
    sa.Column("first_seen", sa.Text, nullable=False),
    sa.Column("last_seen", sa.Text, nullable=False),
    sa.Column("seen_count", sa.Integer, default=1),
)

_agent_integrity_tbl = sa.Table(
    "agent_integrity",
    _metadata,
    sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
    sa.Column("agent_id", sa.Text, nullable=False, unique=True),
    sa.Column("trusted_hash", sa.Text, nullable=False),
    sa.Column("registered_at", sa.Text, nullable=False),
)


def init_db() -> None:
    """Create tables and indexes if they don't exist.  Safe to call every startup."""
    engine = _get_engine()
    _metadata.create_all(engine, checkfirst=True)

    with engine.begin() as conn:
        for idx_sql in [
            "CREATE INDEX IF NOT EXISTS idx_events_hostname    ON events(hostname)",
            "CREATE INDEX IF NOT EXISTS idx_events_device_id   ON events(device_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_received_at ON events(received_at)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_hostname    ON alerts(hostname)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_rule_name   ON alerts(rule_name)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_created_at  ON alerts(created_at)",
        ]:
            try:
                conn.execute(text(idx_sql))
            except Exception:  # pylint: disable=broad-except
                pass  # index may already exist (PostgreSQL raises, SQLite handles IF NOT EXISTS)


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def insert_event(event: Dict[str, Any]) -> int:
    """Persist a raw event dict.  Returns the new row id."""
    with _lock:
        with _get_engine().begin() as conn:
            result = conn.execute(
                _events_tbl.insert().values(
                    received_at=_utcnow(),
                    hostname=event.get("hostname", ""),
                    event_type=event.get("event_type", ""),
                    device_id=event.get("device_id", ""),
                    serial=event.get("serial", ""),
                    manufacturer=event.get("manufacturer", ""),
                    product=event.get("product", ""),
                    bus_path=event.get("bus_path", ""),
                    transfer_bytes=int(event.get("transfer_bytes", 0)),
                    raw_json=json.dumps(event),
                )
            )
    return result.inserted_primary_key[0]


def get_recent_events(hostname: str, window_secs: int) -> List[Dict[str, Any]]:
    """Return events for *hostname* within the last *window_secs* seconds."""
    cutoff = _cutoff(window_secs)
    with _lock:
        with _get_engine().connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT * FROM events "
                    "WHERE hostname = :hostname AND received_at >= :cutoff "
                    "ORDER BY received_at ASC"
                ),
                {"hostname": hostname, "cutoff": cutoff},
            ).mappings().fetchall()
    return [dict(r) for r in rows]


def device_is_new(hostname: str, device_id: str) -> bool:
    """Return True if *device_id* has never been seen on *hostname* before."""
    with _lock:
        with _get_engine().connect() as conn:
            row = conn.execute(
                text(
                    "SELECT 1 FROM events "
                    "WHERE hostname=:hostname AND device_id=:device_id LIMIT 1"
                ),
                {"hostname": hostname, "device_id": device_id},
            ).fetchone()
    return row is None


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def insert_alert(
    hostname: str,
    device_id: str,
    rule_name: str,
    severity: str,
    description: str,
    raw_event: Dict[str, Any],
) -> int:
    """Persist an alert.  Returns the new row id."""
    with _lock:
        with _get_engine().begin() as conn:
            result = conn.execute(
                _alerts_tbl.insert().values(
                    created_at=_utcnow(),
                    hostname=hostname,
                    device_id=device_id,
                    rule_name=rule_name,
                    severity=severity,
                    description=description,
                    raw_event_json=json.dumps(raw_event),
                    acknowledged=0,
                )
            )
    return result.inserted_primary_key[0]


def get_recent_alert(
    hostname: str, device_id: str, rule_name: str, window_secs: int
) -> Optional[Dict[str, Any]]:
    """Return the most recent matching alert within *window_secs*, or None."""
    cutoff = _cutoff(window_secs)
    with _lock:
        with _get_engine().connect() as conn:
            row = conn.execute(
                text(
                    "SELECT * FROM alerts "
                    "WHERE hostname=:hostname AND device_id=:device_id "
                    "  AND rule_name=:rule_name AND created_at >= :cutoff "
                    "ORDER BY created_at DESC LIMIT 1"
                ),
                {
                    "hostname": hostname,
                    "device_id": device_id,
                    "rule_name": rule_name,
                    "cutoff": cutoff,
                },
            ).mappings().fetchone()
    return dict(row) if row else None


def list_alerts(
    hostname: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    conditions = []
    params: Dict[str, Any] = {"limit": limit}
    if hostname:
        conditions.append("hostname = :hostname")
        params["hostname"] = hostname
    if acknowledged is not None:
        conditions.append("acknowledged = :ack")
        params["ack"] = 1 if acknowledged else 0
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    with _lock:
        with _get_engine().connect() as conn:
            rows = conn.execute(
                text(
                    f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT :limit"
                ),
                params,
            ).mappings().fetchall()
    return [dict(r) for r in rows]


def acknowledge_alert(alert_id: int) -> bool:
    """
    Mark the alert with *alert_id* as acknowledged.

    Returns True if the row was found and updated, False if no unacknowledged
    alert with that id exists.
    """
    with _lock:
        with _get_engine().begin() as conn:
            result = conn.execute(
                text(
                    "UPDATE alerts SET acknowledged = 1 "
                    "WHERE id = :id AND acknowledged = 0"
                ),
                {"id": alert_id},
            )
    return result.rowcount > 0


# ---------------------------------------------------------------------------
# Server-side audit chain
# ---------------------------------------------------------------------------

def _tail_server_hash(conn: sa.Connection, hostname: str) -> str:
    """Return the most recent record_hash for *hostname* using the open *conn*."""
    row = conn.execute(
        text(
            "SELECT record_hash FROM audit_chain "
            "WHERE hostname=:hostname ORDER BY id DESC LIMIT 1"
        ),
        {"hostname": hostname},
    ).fetchone()
    return row[0] if row else _GENESIS_HASH


def append_audit_record(hostname: str, event: Dict[str, Any]) -> str:
    """
    Append *event* to the server-side audit chain for *hostname*.
    Returns the new record_hash.
    """
    with _lock:
        with _get_engine().begin() as conn:
            prev_hash = _tail_server_hash(conn, hostname)
            record = {"prev_hash": prev_hash, "event": event}
            serialized = json.dumps(record, sort_keys=True, separators=(",", ":"))
            record_hash = hashlib.sha256(serialized.encode()).hexdigest()
            try:
                conn.execute(
                    _audit_tbl.insert().values(
                        recorded_at=_utcnow(),
                        hostname=hostname,
                        prev_hash=prev_hash,
                        event_json=json.dumps(event),
                        record_hash=record_hash,
                    )
                )
            except sa.exc.IntegrityError:
                pass  # idempotent: hash already recorded
    return record_hash


def get_audit_chain(hostname: str, limit: int = 500) -> List[Dict[str, Any]]:
    with _lock:
        with _get_engine().connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT * FROM audit_chain "
                    "WHERE hostname=:hostname ORDER BY id ASC LIMIT :limit"
                ),
                {"hostname": hostname, "limit": limit},
            ).mappings().fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Timeline (combined events + alerts for incident review)
# ---------------------------------------------------------------------------

def get_timeline(
    hostname: Optional[str] = None,
    device_id: Optional[str] = None,
    since: Optional[str] = None,
    limit: int = 500,
) -> List[Dict[str, Any]]:
    """
    Return a chronological list of events and alerts for a host / device,
    interleaved and sorted by timestamp.

    Each item carries a ``_kind`` field (``"event"`` or ``"alert"``) so
    callers can distinguish the two types.

    Parameters
    ----------
    hostname:   Filter by hostname (optional).
    device_id:  Filter by device_id (optional).
    since:      ISO-8601 datetime string; return only records on or after
                this timestamp (optional).
    limit:      Maximum total rows returned (default 500).
    """
    event_conditions: list[str] = []
    alert_conditions: list[str] = []
    params_e: Dict[str, Any] = {}
    params_a: Dict[str, Any] = {}

    if hostname:
        event_conditions.append("hostname = :hostname")
        alert_conditions.append("hostname = :hostname")
        params_e["hostname"] = hostname
        params_a["hostname"] = hostname

    if device_id:
        event_conditions.append("device_id = :device_id")
        alert_conditions.append("device_id = :device_id")
        params_e["device_id"] = device_id
        params_a["device_id"] = device_id

    if since:
        event_conditions.append("received_at >= :since")
        alert_conditions.append("created_at >= :since")
        params_e["since"] = since
        params_a["since"] = since

    where_e = ("WHERE " + " AND ".join(event_conditions)) if event_conditions else ""
    where_a = ("WHERE " + " AND ".join(alert_conditions)) if alert_conditions else ""

    params_e["limit"] = limit
    params_a["limit"] = limit

    with _lock:
        with _get_engine().connect() as conn:
            event_rows = conn.execute(
                text(
                    f"SELECT id, received_at AS ts, hostname, device_id, "
                    f"event_type, transfer_bytes "
                    f"FROM events {where_e} ORDER BY received_at ASC LIMIT :limit"
                ),
                params_e,
            ).mappings().fetchall()

            alert_rows = conn.execute(
                text(
                    f"SELECT id, created_at AS ts, hostname, device_id, "
                    f"rule_name, severity, description, acknowledged "
                    f"FROM alerts {where_a} ORDER BY created_at ASC LIMIT :limit"
                ),
                params_a,
            ).mappings().fetchall()

    events_out = [{"_kind": "event", **dict(r)} for r in event_rows]
    alerts_out = [{"_kind": "alert", **dict(r)} for r in alert_rows]

    combined = sorted(events_out + alerts_out, key=lambda x: x["ts"])
    return combined[:limit]


# ---------------------------------------------------------------------------
# Remote log anchoring
# ---------------------------------------------------------------------------

def insert_anchor(agent_id: str, chain_head_hash: str) -> str:
    """Sign chain_head_hash with server's RSA private key (or HMAC fallback) and store anchor."""
    from server.config import TLS_KEY, API_SECRET_KEY
    import os, hashlib, hmac

    sig = ""
    # Try RSA signing with TLS key
    if os.path.exists(TLS_KEY):
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            with open(TLS_KEY, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            signature_bytes = private_key.sign(
                chain_head_hash.encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            sig = signature_bytes.hex()
        except Exception:
            sig = ""

    # Fallback: HMAC-SHA256 with API key.
    # HMAC handles arbitrary-length keys natively; no pre-hashing is needed.
    if not sig:
        mac_key = (API_SECRET_KEY or "itdn-default-anchor-key").encode()
        sig = hmac.new(mac_key, chain_head_hash.encode(), hashlib.sha256).hexdigest()

    now = _utcnow()
    with _lock:
        with _get_engine().begin() as conn:
            conn.execute(
                _log_anchors_tbl.insert().values(
                    agent_id=agent_id,
                    chain_head_hash=chain_head_hash,
                    anchored_at=now,
                    server_signature=sig,
                )
            )
    return sig


def get_anchors(agent_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Return anchor records for agent_id."""
    with _lock:
        with _get_engine().connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT * FROM log_anchors WHERE agent_id=:agent_id "
                    "ORDER BY id DESC LIMIT :limit"
                ),
                {"agent_id": agent_id, "limit": limit},
            ).mappings().fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def upsert_risk_score(hostname: str, delta_score: int) -> None:
    """Add delta_score to the 24h rolling cumulative score for hostname."""
    now = _utcnow()
    window_start = _cutoff(86400)
    with _lock:
        with _get_engine().begin() as conn:
            row = conn.execute(
                text("SELECT id, score FROM risk_scores WHERE hostname=:hostname"),
                {"hostname": hostname},
            ).fetchone()
            if row:
                new_score = (row[1] or 0) + delta_score
                conn.execute(
                    text(
                        "UPDATE risk_scores SET score=:score, window_end=:we, updated_at=:ua "
                        "WHERE hostname=:hostname"
                    ),
                    {"score": new_score, "we": now, "ua": now, "hostname": hostname},
                )
            else:
                conn.execute(
                    _risk_scores_tbl.insert().values(
                        hostname=hostname,
                        score=delta_score,
                        window_start=window_start,
                        window_end=now,
                        updated_at=now,
                    )
                )


def get_risk_score(hostname: str) -> int:
    """Return the current cumulative risk score for hostname."""
    with _lock:
        with _get_engine().connect() as conn:
            row = conn.execute(
                text("SELECT score FROM risk_scores WHERE hostname=:hostname"),
                {"hostname": hostname},
            ).fetchone()
    return row[0] if row else 0


# ---------------------------------------------------------------------------
# Device baseline
# ---------------------------------------------------------------------------

def update_device_baseline(hostname: str, device_id: str) -> None:
    """Upsert baseline record: insert on first sight, update last_seen + seen_count after."""
    now = _utcnow()
    with _lock:
        with _get_engine().begin() as conn:
            row = conn.execute(
                text(
                    "SELECT id, seen_count FROM device_baseline "
                    "WHERE hostname=:hostname AND device_id=:device_id"
                ),
                {"hostname": hostname, "device_id": device_id},
            ).fetchone()
            if row:
                conn.execute(
                    text(
                        "UPDATE device_baseline SET last_seen=:ls, seen_count=:sc "
                        "WHERE id=:id"
                    ),
                    {"ls": now, "sc": (row[1] or 0) + 1, "id": row[0]},
                )
            else:
                conn.execute(
                    _device_baseline_tbl.insert().values(
                        hostname=hostname,
                        device_id=device_id,
                        first_seen=now,
                        last_seen=now,
                        seen_count=1,
                    )
                )


def get_device_baseline(hostname: str) -> List[Dict[str, Any]]:
    """Return all baseline device records for hostname."""
    with _lock:
        with _get_engine().connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT * FROM device_baseline WHERE hostname=:hostname "
                    "ORDER BY first_seen ASC"
                ),
                {"hostname": hostname},
            ).mappings().fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Cross-agent device correlation
# ---------------------------------------------------------------------------

def get_recent_events_by_device(device_id: str, window_secs: int) -> List[Dict[str, Any]]:
    """Return recent events for a device_id across all hosts."""
    cutoff = _cutoff(window_secs)
    with _lock:
        with _get_engine().connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT * FROM events "
                    "WHERE device_id=:device_id AND received_at >= :cutoff "
                    "ORDER BY received_at ASC"
                ),
                {"device_id": device_id, "cutoff": cutoff},
            ).mappings().fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Agent integrity
# ---------------------------------------------------------------------------

def register_agent_hash(agent_id: str, agent_hash: str) -> None:
    """Register or update the trusted hash for agent_id."""
    now = _utcnow()
    with _lock:
        with _get_engine().begin() as conn:
            row = conn.execute(
                text("SELECT id FROM agent_integrity WHERE agent_id=:agent_id"),
                {"agent_id": agent_id},
            ).fetchone()
            if row:
                conn.execute(
                    text(
                        "UPDATE agent_integrity SET trusted_hash=:hash, registered_at=:ra "
                        "WHERE agent_id=:agent_id"
                    ),
                    {"hash": agent_hash, "ra": now, "agent_id": agent_id},
                )
            else:
                conn.execute(
                    _agent_integrity_tbl.insert().values(
                        agent_id=agent_id,
                        trusted_hash=agent_hash,
                        registered_at=now,
                    )
                )


def check_agent_hash(agent_id: str, agent_hash: str) -> tuple:
    """Check if agent_hash matches the stored trusted hash. Returns (trusted, stored_hash)."""
    with _lock:
        with _get_engine().connect() as conn:
            row = conn.execute(
                text("SELECT trusted_hash FROM agent_integrity WHERE agent_id=:agent_id"),
                {"agent_id": agent_id},
            ).fetchone()
    if not row:
        return False, ""
    stored = row[0]
    return stored == agent_hash, stored
