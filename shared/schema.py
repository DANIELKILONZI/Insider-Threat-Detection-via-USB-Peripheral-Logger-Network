"""Shared normalized event schema used by both agent and server."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator


class NormalizedEvent(BaseModel):
    """Tamper-evident, normalized event envelope emitted by USB/BT monitors."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    agent_id: str
    actor: str  # username or process name
    device_id: str  # "VID:PID" for USB, MAC address for BT
    action: str  # connect | disconnect | data_transfer | scan
    source_type: str  # usb | bluetooth
    raw: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    prev_hash: Optional[str] = None
    event_hash: str = Field(default="")

    @model_validator(mode="after")
    def compute_hash(self) -> "NormalizedEvent":
        if not self.event_hash:
            self.event_hash = self._compute_hash()
        return self

    def _compute_hash(self) -> str:
        payload = (
            f"{self.event_id}"
            f"{self.agent_id}"
            f"{self.device_id}"
            f"{self.action}"
            f"{self.timestamp.isoformat()}"
            f"{self.prev_hash or ''}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def recompute_hash(self) -> str:
        """Recompute and return hash without mutating the object."""
        return self._compute_hash()

    model_config = {"json_encoders": {datetime: lambda v: v.isoformat()}}
