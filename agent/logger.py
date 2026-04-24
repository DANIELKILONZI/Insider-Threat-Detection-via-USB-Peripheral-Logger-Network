"""
agent/logger.py – Local tamper-evident event logger.

Writes JSON-Lines to a local log file and maintains a running SHA-256
hash chain so that any post-hoc tampering is detectable.  The chain root
hash is printed to stdout on clean shutdown so it can be stored out-of-band.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from typing import Any, Dict

from agent.config import LOCAL_LOG_DIR, LOCAL_LOG_FILE

logger = logging.getLogger(__name__)

_GENESIS_HASH = "0" * 64  # initial chain anchor


class LocalAuditLogger:
    """
    Thread-safe JSON-Lines logger with SHA-256 hash chaining.

    Each record written to disk includes:
        - The event payload
        - The SHA-256 hash of the *previous* record (``prev_hash``)
        - The SHA-256 hash of *this* record (``record_hash``)

    Replaying the log and recomputing hashes allows any gaps or
    modifications to be detected.
    """

    def __init__(self) -> None:
        os.makedirs(LOCAL_LOG_DIR, exist_ok=True)
        self._lock = threading.Lock()
        self._prev_hash: str = _GENESIS_HASH
        self._load_tail_hash()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_tail_hash(self) -> None:
        """Read the last record_hash from an existing log file to continue the chain."""
        if not os.path.exists(LOCAL_LOG_FILE):
            return
        try:
            last_line = b""
            with open(LOCAL_LOG_FILE, "rb") as fh:
                for line in fh:
                    if line.strip():
                        last_line = line
            if last_line:
                record = json.loads(last_line)
                self._prev_hash = record.get("record_hash", _GENESIS_HASH)
        except Exception:  # pylint: disable=broad-except
            logger.warning("Could not read tail hash from existing log; starting fresh chain")
            self._prev_hash = _GENESIS_HASH

    @staticmethod
    def _hash_record(record: Dict[str, Any]) -> str:
        serialized = json.dumps(record, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, event: Dict[str, Any]) -> str:
        """
        Append *event* to the local log with hash-chain metadata.

        Returns the ``record_hash`` of the written record.
        """
        with self._lock:
            record: Dict[str, Any] = {
                "prev_hash": self._prev_hash,
                "event": event,
            }
            record_hash = self._hash_record(record)
            record["record_hash"] = record_hash

            try:
                with open(LOCAL_LOG_FILE, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record) + "\n")
            except OSError as exc:
                logger.error("Failed to write local audit log: %s", exc)
                raise

            self._prev_hash = record_hash
            return record_hash

    @property
    def chain_head(self) -> str:
        """SHA-256 hash of the most recently written record."""
        with self._lock:
            return self._prev_hash
