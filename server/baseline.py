"""
server/baseline.py – Device baseline profiling for ITDN.
"""

from __future__ import annotations

import logging
from typing import Any, List

logger = logging.getLogger(__name__)


class BaselineProfiler:
    """Tracks known devices per hostname for anomaly detection."""

    def __init__(self, db: Any) -> None:
        self._db = db

    def is_known(self, hostname: str, device_id: str) -> bool:
        """Return True if device_id has been seen on hostname before."""
        baseline = self._db.get_device_baseline(hostname)
        return any(b["device_id"] == device_id for b in baseline)

    def update(self, hostname: str, device_id: str) -> None:
        """Record that device_id was seen on hostname."""
        self._db.update_device_baseline(hostname, device_id)
