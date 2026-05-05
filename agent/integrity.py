"""Agent binary integrity check — verifies SHA-256 hash against server-stored value."""
from __future__ import annotations

import hashlib
import logging
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def compute_binary_hash(path: Optional[str] = None) -> str:
    """Return SHA-256 hex digest of the agent entry-point script."""
    target = Path(path) if path else Path(sys.argv[0]).resolve()
    h = hashlib.sha256()
    try:
        with open(target, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        logger.error("compute_binary_hash: cannot read %s: %s", target, exc)
        return ""


def verify_integrity(trusted_hash: str, path: Optional[str] = None) -> bool:
    """Compare local binary hash to trusted_hash. Returns True if they match."""
    actual = compute_binary_hash(path)
    if not actual:
        return False
    match = actual == trusted_hash
    if not match:
        logger.critical(
            "INTEGRITY MISMATCH: binary hash does not match server-stored trusted hash"
        )
    return match
