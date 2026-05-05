"""Abstract base for notification sinks."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class NotificationSink(ABC):
    """A single notification channel (email, Slack, syslog, …)."""

    @abstractmethod
    async def send(self, alert: Dict[str, Any]) -> None:
        """Dispatch *alert* dict to the underlying channel.

        The dict always has at least the keys:
            id, agent_id, rule, score, device_id, timestamp, details_json
        """
