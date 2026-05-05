"""Notification bus — fan-out alerts to all registered sinks."""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from server.notifications.base import NotificationSink

logger = logging.getLogger(__name__)


class NotificationBus:
    """Holds a list of sinks and dispatches alert dicts to all of them."""

    def __init__(self) -> None:
        self._sinks: List[NotificationSink] = []

    def register(self, sink: NotificationSink) -> None:
        """Register a new notification sink."""
        self._sinks.append(sink)
        logger.info("Registered notification sink: %s", type(sink).__name__)

    async def dispatch(self, alert: Dict[str, Any]) -> None:
        """Fan out *alert* to every registered sink (errors are logged, not raised)."""
        for sink in self._sinks:
            try:
                await sink.send(alert)
            except Exception:
                logger.exception(
                    "Sink %s raised an error dispatching alert %s",
                    type(sink).__name__,
                    alert.get("id"),
                )

    def __len__(self) -> int:
        return len(self._sinks)


# Module-level singleton — configure sinks at startup via server/main.py
_bus = NotificationBus()


def get_bus() -> NotificationBus:
    """Return the global notification bus (FastAPI dependency / direct usage)."""
    return _bus
