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
    conditions_e: list[str] = []
    conditions_a: list[str] = []
    params_e: Dict[str, Any] = {}
    params_a: Dict[str, Any] = {}

    if hostname:
        conditions_e.append("hostname = :hostname")
        conditions_a.append("hostname = :hostname")
        params_e["hostname"] = hostname
        params_a["hostname"] = hostname

    if device_id:
        conditions_e.append("device_id = :device_id")
        conditions_a.append("device_id = :device_id")
        params_e["device_id"] = device_id
        params_a["device_id"] = device_id

    if since:
        conditions_e.append("received_at >= :since")
        conditions_a.append("created_at >= :since")
        params_e["since"] = since
        params_a["since"] = since

    where_e = ("WHERE " + " AND ".join(conditions_e)) if conditions_e else ""
    where_a = ("WHERE " + " AND ".join(conditions_a)) if conditions_a else ""

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
