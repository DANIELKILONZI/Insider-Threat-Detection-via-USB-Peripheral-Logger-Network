"""
server/honeypot.py – Honeypot device profile detection for ITDN.
"""

from __future__ import annotations

import logging
from typing import List

logger = logging.getLogger(__name__)


class HoneypotConfig:
    """Configurable list of honeypot USB vendor:product ID pairs."""

    def __init__(self) -> None:
        from server.config import HONEYPOT_VIDS
        self.HONEYPOT_VIDS: List[str] = [
            v.strip() for v in HONEYPOT_VIDS.split(",") if v.strip()
        ] if HONEYPOT_VIDS else []


_honeypot_config = HoneypotConfig()


def is_honeypot_device(device_id: str) -> bool:
    """Return True if device_id matches any configured honeypot vid:pid."""
    return device_id in _honeypot_config.HONEYPOT_VIDS
