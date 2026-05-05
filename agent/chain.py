"""SQLite-backed tamper-evident hash chain for local event storage."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import List, Optional

from shared.schema import NormalizedEvent


class EventChain:
    """Append-only chain of NormalizedEvents stored in SQLite."""

    def __init__(self, db_path: str = "chain.db") -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS events (
                        seq       INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id  TEXT NOT NULL UNIQUE,
                        agent_id  TEXT NOT NULL,
                        actor     TEXT NOT NULL,
                        device_id TEXT NOT NULL,
                        action    TEXT NOT NULL,
                        source_type TEXT NOT NULL,
                        raw_json  TEXT NOT NULL,
                        confidence REAL NOT NULL,
                        timestamp TEXT NOT NULL,
                        prev_hash TEXT,
                        event_hash TEXT NOT NULL
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def get_chain_head(self) -> Optional[str]:
        """Return the event_hash of the most recent event."""
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                return row["event_hash"] if row else None
            finally:
                conn.close()

    def add_event(self, event: NormalizedEvent) -> str:
        """Append event to chain; sets prev_hash and recomputes event_hash."""
        with self._lock:
            conn = self._connect()
            try:
                head_row = conn.execute(
                    "SELECT event_hash FROM events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                prev_hash = head_row["event_hash"] if head_row else None

                # Rebuild event with chain link
                linked = NormalizedEvent(
                    event_id=event.event_id,
                    agent_id=event.agent_id,
                    actor=event.actor,
                    device_id=event.device_id,
                    action=event.action,
                    source_type=event.source_type,
                    raw=event.raw,
                    confidence=event.confidence,
                    timestamp=event.timestamp,
                    prev_hash=prev_hash,
                )

                conn.execute(
                    """
                    INSERT INTO events
                        (event_id, agent_id, actor, device_id, action, source_type,
                         raw_json, confidence, timestamp, prev_hash, event_hash)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        linked.event_id,
                        linked.agent_id,
                        linked.actor,
                        linked.device_id,
                        linked.action,
                        linked.source_type,
                        json.dumps(linked.raw),
                        linked.confidence,
                        linked.timestamp.isoformat(),
                        linked.prev_hash,
                        linked.event_hash,
                    ),
                )
                conn.commit()
                return linked.event_hash
            finally:
                conn.close()

    def verify_chain(self) -> bool:
        """Walk the chain; return True if all hashes are consistent."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM events ORDER BY seq ASC"
                ).fetchall()
                for i, row in enumerate(rows):
                    expected_prev = rows[i - 1]["event_hash"] if i > 0 else None
                    if row["prev_hash"] != expected_prev:
                        return False
                    payload = (
                        f"{row['event_id']}"
                        f"{row['agent_id']}"
                        f"{row['device_id']}"
                        f"{row['action']}"
                        f"{row['timestamp']}"
                        f"{row['prev_hash'] or ''}"
                    )
                    computed = hashlib.sha256(payload.encode()).hexdigest()
                    if computed != row["event_hash"]:
                        return False
                return True
            finally:
                conn.close()

    def get_events(self, limit: int = 100) -> List[NormalizedEvent]:
        """Return most recent *limit* events."""
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM events ORDER BY seq DESC LIMIT ?", (limit,)
                ).fetchall()
                events = []
                for row in rows:
                    events.append(
                        NormalizedEvent(
                            event_id=row["event_id"],
                            agent_id=row["agent_id"],
                            actor=row["actor"],
                            device_id=row["device_id"],
                            action=row["action"],
                            source_type=row["source_type"],
                            raw=json.loads(row["raw_json"]),
                            confidence=row["confidence"],
                            timestamp=datetime.fromisoformat(row["timestamp"]),
                            prev_hash=row["prev_hash"],
                            event_hash=row["event_hash"],
                        )
                    )
                return events
            finally:
                conn.close()
