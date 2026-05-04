"""
server/schema.py – Pydantic v2 models for validating inbound API payloads.

Validates every event in a POST /api/v1/events batch before it is
persisted or evaluated by the rules engine.

Valid event_type values: "connected", "disconnected", "data_transfer"
All string fields are stripped of leading/trailing whitespace.
transfer_bytes must be ≥ 0.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class DeviceEvent(BaseModel):
    """Schema for a single device event sent by an endpoint agent."""

    event_type: Literal["connected", "disconnected", "data_transfer"]
    device_id: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=256)
    serial: Optional[str] = ""
    manufacturer: Optional[str] = ""
    product: Optional[str] = ""
    bus_path: Optional[str] = ""
    timestamp: Optional[str] = ""
    transfer_bytes: int = Field(default=0, ge=0)

    model_config = {"extra": "allow"}  # allow agent-specific extra fields

    @field_validator("device_id", "hostname", mode="before")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip() if isinstance(v, str) else v

    @field_validator("serial", "manufacturer", "product", "bus_path", "timestamp", mode="before")
    @classmethod
    def coerce_none_to_empty(cls, v: object) -> str:
        if v is None:
            return ""
        return str(v).strip()


class EventBatch(BaseModel):
    """Schema for the POST /api/v1/events request body."""

    events: List[DeviceEvent] = Field(min_length=0)
