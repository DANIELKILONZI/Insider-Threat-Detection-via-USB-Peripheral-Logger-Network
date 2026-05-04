"""
server/database.py – SQLite persistence layer for events, alerts, and the
server-side audit chain.

Schema overview
---------------
events  – one row per device event received from agents
alerts  – one row per fired alert (deduplication handled by alert_manager)
audit   – server-side hash-chain mirror of agent audit records

The SQLite file is fine for < 50 M rows.  For large-scale deployments swap
the connection factory for psycopg2/SQLAlchemy targeting PostgreSQL; the rest
of the module stays unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from server.config import DB_PATH

_GENESIS_HASH = "0" * 64
_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Create tables if they don't exist yet.  Safe to call on every startup."""
    with _lock:
        conn = _connect()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at   TEXT    NOT NULL,
                hostname      TEXT    NOT NULL,
                event_type    TEXT    NOT NULL,
                device_id     TEXT    NOT NULL,
                serial        TEXT,
                manufacturer  TEXT,
                product       TEXT,
                bus_path      TEXT,
                transfer_bytes INTEGER DEFAULT 0,
                raw_json      TEXT    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_hostname   ON events(hostname);
            CREATE INDEX IF NOT EXISTS idx_events_device_id  ON events(device_id);
            CREATE INDEX IF NOT EXISTS idx_events_received_at ON events(received_at);

            CREATE TABLE IF NOT EXISTS alerts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at    TEXT    NOT NULL,
                hostname      TEXT    NOT NULL,
                device_id     TEXT    NOT NULL,
                rule_name     TEXT    NOT NULL,
                severity      TEXT    NOT NULL,
                description   TEXT    NOT NULL,
                raw_event_json TEXT   NOT NULL,
                acknowledged  INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_hostname  ON alerts(hostname);
            CREATE INDEX IF NOT EXISTS idx_alerts_rule_name ON alerts(rule_name);
            CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);

            CREATE TABLE IF NOT EXISTS audit_chain (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at   TEXT    NOT NULL,
                hostname      TEXT    NOT NULL,
                prev_hash     TEXT    NOT NULL,
                event_json    TEXT    NOT NULL,
                record_hash   TEXT    NOT NULL UNIQUE
            );
            """
        )
        conn.commit()
        conn.close()


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

def insert_event(event: Dict[str, Any]) -> int:
    """Persist a raw event dict.  Returns the new row id."""
    with _lock:
        conn = _connect()
        cur = conn.execute(
            """
            INSERT INTO events
                (received_at, hostname, event_type, device_id, serial,
                 manufacturer, product, bus_path, transfer_bytes, raw_json)
            VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.get("hostname", ""),
                event.get("event_type", ""),
                event.get("device_id", ""),
                event.get("serial", ""),
                event.get("manufacturer", ""),
                event.get("product", ""),
                event.get("bus_path", ""),
                int(event.get("transfer_bytes", 0)),
                json.dumps(event),
            ),
        )
        conn.commit()
        row_id = cur.lastrowid
        conn.close()
        return row_id


def get_recent_events(hostname: str, window_secs: int) -> List[sqlite3.Row]:
    """Return events for *hostname* within the last *window_secs* seconds."""
    with _lock:
        conn = _connect()
        rows = conn.execute(
            """
            SELECT * FROM events
            WHERE hostname = ?
              AND received_at >= datetime('now', ? || ' seconds')
            ORDER BY received_at ASC
            """,
            (hostname, f"-{window_secs}"),
        ).fetchall()
        conn.close()
    return rows


def device_is_new(hostname: str, device_id: str) -> bool:
    """Return True if *device_id* has never been seen on *hostname* before."""
    with _lock:
        conn = _connect()
        row = conn.execute(
            "SELECT 1 FROM events WHERE hostname=? AND device_id=? LIMIT 1",
            (hostname, device_id),
        ).fetchone()
        conn.close()
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
        conn = _connect()
        cur = conn.execute(
            """
            INSERT INTO alerts
                (created_at, hostname, device_id, rule_name, severity,
                 description, raw_event_json)
            VALUES (datetime('now'), ?, ?, ?, ?, ?, ?)
            """,
            (
                hostname,
                device_id,
                rule_name,
                severity,
                description,
                json.dumps(raw_event),
            ),
        )
        conn.commit()
        row_id = cur.lastrowid
        conn.close()
        return row_id


def get_recent_alert(
    hostname: str, device_id: str, rule_name: str, window_secs: int
) -> Optional[sqlite3.Row]:
    """Return the most recent matching alert within *window_secs*, or None."""
    with _lock:
        conn = _connect()
        row = conn.execute(
            """
            SELECT * FROM alerts
            WHERE hostname=? AND device_id=? AND rule_name=?
              AND created_at >= datetime('now', ? || ' seconds')
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (hostname, device_id, rule_name, f"-{window_secs}"),
        ).fetchone()
        conn.close()
    return row


def list_alerts(
    hostname: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    limit: int = 200,
) -> List[sqlite3.Row]:
    conditions = []
    params: List[Any] = []
    if hostname:
        conditions.append("hostname = ?")
        params.append(hostname)
    if acknowledged is not None:
        conditions.append("acknowledged = ?")
        params.append(1 if acknowledged else 0)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)
    with _lock:
        conn = _connect()
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY created_at DESC LIMIT ?",
            params,
        ).fetchall()
        conn.close()
    return rows


# ---------------------------------------------------------------------------
# Server-side audit chain
# ---------------------------------------------------------------------------

def _tail_server_hash(hostname: str) -> str:
    with _lock:
        conn = _connect()
        row = conn.execute(
            "SELECT record_hash FROM audit_chain WHERE hostname=? ORDER BY id DESC LIMIT 1",
            (hostname,),
        ).fetchone()
        conn.close()
    return row["record_hash"] if row else _GENESIS_HASH


def append_audit_record(hostname: str, event: Dict[str, Any]) -> str:
    """
    Append *event* to the server-side audit chain for *hostname*.
    Returns the new record_hash.
    """
    prev_hash = _tail_server_hash(hostname)
    record = {"prev_hash": prev_hash, "event": event}
    serialized = json.dumps(record, sort_keys=True, separators=(",", ":"))
    record_hash = hashlib.sha256(serialized.encode()).hexdigest()

    with _lock:
        conn = _connect()
        conn.execute(
            """
            INSERT OR IGNORE INTO audit_chain
                (recorded_at, hostname, prev_hash, event_json, record_hash)
            VALUES (datetime('now'), ?, ?, ?, ?)
            """,
            (hostname, prev_hash, json.dumps(event), record_hash),
        )
        conn.commit()
        conn.close()
    return record_hash


def get_audit_chain(hostname: str, limit: int = 500) -> List[sqlite3.Row]:
    with _lock:
        conn = _connect()
        rows = conn.execute(
            """
            SELECT * FROM audit_chain
            WHERE hostname=?
            ORDER BY id ASC
            LIMIT ?
            """,
            (hostname, limit),
        ).fetchall()
        conn.close()
    return rows
