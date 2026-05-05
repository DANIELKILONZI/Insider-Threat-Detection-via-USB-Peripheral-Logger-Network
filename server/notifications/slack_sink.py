"""Slack webhook notification sink."""
from __future__ import annotations

import json
import logging
from typing import Any, Dict

import httpx

from server.notifications.base import NotificationSink

logger = logging.getLogger(__name__)


class SlackSink(NotificationSink):
    """Post alert summaries to a Slack Incoming Webhook URL."""

    def __init__(self, webhook_url: str, timeout: float = 10.0) -> None:
        self.webhook_url = webhook_url
        self.timeout = timeout

    async def send(self, alert: Dict[str, Any]) -> None:
        text = (
            f":rotating_light: *Insider Threat Alert*\n"
            f"*Rule*: `{alert.get('rule', 'N/A')}`  "
            f"*Score*: `{alert.get('score', 0):.0f}`\n"
            f"*Agent*: `{alert.get('agent_id', 'N/A')}`  "
            f"*Device*: `{alert.get('device_id', 'N/A')}`\n"
            f"*Time*: {alert.get('timestamp', 'N/A')}"
        )
        payload = {"text": text}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    self.webhook_url,
                    content=json.dumps(payload),
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
            logger.info("Slack alert sent (HTTP %s)", resp.status_code)
        except Exception:
            logger.exception("Failed to send Slack alert")
