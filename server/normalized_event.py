"""
server/normalized_event.py – Normalized event schema for ITDN.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from pydantic import BaseModel, Field


class NormalizedEvent(BaseModel):
    """Canonical representation of a USB/BT peripheral event."""

    actor: str = Field(description="Reporting hostname")
    device_id: str
    action: Literal["connected", "disconnected", "data_transfer"]
    source_type: Literal["usb", "bluetooth"]
    raw: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    timestamp: str
    agent_id: str


def normalize_event(event: Dict[str, Any]) -> NormalizedEvent:
    """Wrap a raw USB/BT event dict into a NormalizedEvent."""
    event_type = event.get("event_type", "connected")
    if event_type == "connected":
        action = "connected"
    elif event_type == "disconnected":
        action = "disconnected"
    else:
        action = "data_transfer"

    source_type: Literal["usb", "bluetooth"] = (
        "bluetooth" if event.get("source_type") == "bluetooth" else "usb"
    )

    timestamp = event.get("timestamp") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    hostname = event.get("hostname", "unknown")

    return NormalizedEvent(
        actor=hostname,
        device_id=event.get("device_id", ""),
        action=action,
        source_type=source_type,
        raw=event,
        confidence=float(event.get("confidence", 1.0)),
        timestamp=timestamp,
        agent_id=hostname,
    )
