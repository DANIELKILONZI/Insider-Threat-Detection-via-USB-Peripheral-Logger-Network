"""
agent/retry_queue.py – SQLite-backed persistent retry queue for agent events.

Events written to this queue survive agent restarts and extended network
outages.  The caller dequeues a batch, attempts delivery, then either
commits (success) or puts the batch back (failure).

The backing SQLite file is created automatically at ``ITDN_RETRY_DB``
(default: ``<ITDN_LOG_DIR>/retry.db``).

Thread safety
-------------
All operations acquire a module-level lock and use a single shared
``sqlite3.Connection`` with ``check_same_thread=False``.

Usage::

    from agent.retry_queue import PersistentQueue
    q = PersistentQueue()
    q.put(event_dict)
    batch = q.peek(50)
    if deliver(batch):
        q.commit(len(batch))
    # else: events remain at the front for the next retry
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

EventDict = Dict[str, Any]


def _db_path() -> str:
    log_dir = os.environ.get("ITDN_LOG_DIR", "/var/log/itdn")
    return os.environ.get("ITDN_RETRY_DB", os.path.join(log_dir, "retry.db"))


class PersistentQueue:
    """Append-only SQLite queue with cursor-based consumption."""

    def __init__(self) -> None:
        path = _db_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._init_schema()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS retry_queue (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload   TEXT    NOT NULL
                )
                """
            )
            self._conn.commit()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def put(self, event: EventDict) -> None:
        """Append *event* to the end of the queue."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO retry_queue (payload) VALUES (?)",
                (json.dumps(event),),
            )
            self._conn.commit()

    def peek(self, limit: int = 100) -> List[EventDict]:
        """
        Return up to *limit* events from the front of the queue **without**
        removing them.  Call :meth:`commit` after successful delivery.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, payload FROM retry_queue ORDER BY id ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [json.loads(row[1]) for row in rows]

    def commit(self, count: int) -> None:
        """Remove the *count* oldest events from the queue (after delivery)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id FROM retry_queue ORDER BY id ASC LIMIT ?",
                (count,),
            ).fetchall()
            if rows:
                ids = [r[0] for r in rows]
                self._conn.execute(
                    f"DELETE FROM retry_queue WHERE id IN ({','.join('?' * len(ids))})",
                    ids,
                )
                self._conn.commit()

    def size(self) -> int:
        """Return the number of pending events."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM retry_queue"
            ).fetchone()
        return row[0] if row else 0

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            self._conn.close()
