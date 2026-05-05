"""Baseline profiler — tracks per-agent known devices and usage hours."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from server.models import BaselineDevice


class BaselineProfiler:
    def __init__(
        self,
        off_hours_start: int = 18,
        off_hours_end: int = 8,
    ) -> None:
        self.off_hours_start = off_hours_start
        self.off_hours_end = off_hours_end

    async def record_device(
        self,
        agent_id: str,
        device_id: str,
        timestamp: datetime,
        db: AsyncSession,
    ) -> None:
        """Insert or update baseline record for agent+device."""
        result = await db.execute(
            select(BaselineDevice).where(
                BaselineDevice.agent_id == agent_id,
                BaselineDevice.device_id == device_id,
            )
        )
        row = result.scalars().first()
        if row:
            row.seen_count += 1
            row.last_seen = timestamp
        else:
            db.add(
                BaselineDevice(
                    agent_id=agent_id,
                    device_id=device_id,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    seen_count=1,
                )
            )
        await db.flush()

    async def is_known_device(
        self, agent_id: str, device_id: str, db: AsyncSession
    ) -> bool:
        """True if device has been seen by this agent before (seen_count > 1)."""
        result = await db.execute(
            select(BaselineDevice).where(
                BaselineDevice.agent_id == agent_id,
                BaselineDevice.device_id == device_id,
            )
        )
        row = result.scalars().first()
        return row is not None and row.seen_count > 1

    def is_off_hours(self, ts: datetime) -> bool:
        """True if timestamp falls outside normal business hours (8am–6pm)."""
        hour = ts.hour
        if self.off_hours_start > self.off_hours_end:
            return hour >= self.off_hours_start or hour < self.off_hours_end
        return self.off_hours_start <= hour < self.off_hours_end

    async def get_profile(self, agent_id: str, db: AsyncSession) -> dict:
        """Return the known device set and usage stats for an agent."""
        result = await db.execute(
            select(BaselineDevice).where(BaselineDevice.agent_id == agent_id)
        )
        rows = result.scalars().all()
        devices = [
            {
                "device_id": r.device_id,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
                "seen_count": r.seen_count,
            }
            for r in rows
        ]
        return {"agent_id": agent_id, "devices": devices, "device_count": len(devices)}
