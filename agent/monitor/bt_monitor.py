"""Bluetooth device monitor using pybluez (Linux). Stubs for other platforms."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Iterator

from shared.schema import NormalizedEvent

logger = logging.getLogger(__name__)


class BTMonitor:
    """Periodically scans for Bluetooth devices and yields NormalizedEvents."""

    def __init__(
        self,
        agent_id: str,
        actor: str = "system",
        scan_duration: int = 8,
        sleep_between: int = 30,
    ) -> None:
        self.agent_id = agent_id
        self.actor = actor
        self.scan_duration = scan_duration
        self.sleep_between = sleep_between

    def monitor(self) -> Iterator[NormalizedEvent]:
        """Yields scan events. Raises ImportError if bluetooth not available."""
        try:
            import bluetooth  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "pybluez2 is required for Bluetooth monitoring. "
                "Install with: pip install pybluez2"
            ) from exc

        while True:
            try:
                devices = bluetooth.discover_devices(
                    duration=self.scan_duration,
                    lookup_names=True,
                    flush_cache=True,
                )
                for addr, name in devices:
                    yield NormalizedEvent(
                        agent_id=self.agent_id,
                        actor=self.actor,
                        device_id=addr,
                        action="scan",
                        source_type="bluetooth",
                        raw={
                            "mac": addr,
                            "name": name or "",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                        confidence=0.85,
                    )
            except Exception as exc:
                logger.warning("BT scan error: %s", exc)
            time.sleep(self.sleep_between)
