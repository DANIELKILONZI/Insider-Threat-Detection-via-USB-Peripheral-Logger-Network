"""
agent/logger.py – Local tamper-evident event logger.

Writes JSON-Lines to a local log file and maintains a running SHA-256
hash chain so that any post-hoc tampering is detectable.  The chain root
hash is printed to stdout on clean shutdown so it can be stored out-of-band.

When ``ITDN_LOG_KEY`` is set to a 64-hex-character AES-256 key, each record
is encrypted with AES-256-GCM before being written to disk (see
``agent/crypto.py``).  Chain integrity is computed on the plaintext so it
is preserved regardless of whether encryption is enabled.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from typing import Any, Dict

from agent.config import LOCAL_LOG_DIR, LOCAL_LOG_FILE
from agent.crypto import decrypt_record, encrypt_record, is_encryption_enabled

logger = logging.getLogger(__name__)

_GENESIS_HASH = "0" * 64  # initial chain anchor


class LocalAuditLogger:
    """
    Thread-safe JSON-Lines logger with SHA-256 hash chaining.

    Each record written to disk includes:
        - The event payload
        - The SHA-256 hash of the *previous* record (``prev_hash``)
        - The SHA-256 hash of *this* record (``record_hash``)

    When ``ITDN_LOG_KEY`` is configured the record is AES-256-GCM encrypted
    before being appended; the hashes are still computed on plaintext so
    the chain can be verified after decryption.

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
                record = decrypt_record(last_line.decode("utf-8"))
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
                if is_encryption_enabled():
                    line = encrypt_record(record)
                else:
                    line = json.dumps(record)

                with open(LOCAL_LOG_FILE, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
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
