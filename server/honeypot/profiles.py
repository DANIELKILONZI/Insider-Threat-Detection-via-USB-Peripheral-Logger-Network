"""Honeypot device profile manager.

Bait VID:PIDs are registered. Any real device matching them fires a
high-confidence alert (attacker cloned a trusted device).
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models import Alert, HoneypotProfile

logger = logging.getLogger(__name__)

# Built-in bait profiles — known "trusted" identifiers used as traps
DEFAULT_PROFILES = [
    {"vid": "dead", "pid": "beef", "name": "Bait: Dead Beef"},
    {"vid": "cafe", "pid": "babe", "name": "Bait: Cafe Babe"},
    {"vid": "1234", "pid": "abcd", "name": "Bait: Generic Corporate Token"},
]


class HoneypotManager:
    async def seed_defaults(self, db: AsyncSession) -> None:
        """Insert default bait profiles if not already present."""
        for p in DEFAULT_PROFILES:
            result = await db.execute(
                select(HoneypotProfile).where(
                    HoneypotProfile.vid == p["vid"],
                    HoneypotProfile.pid == p["pid"],
                )
            )
            if not result.scalars().first():
                db.add(HoneypotProfile(vid=p["vid"], pid=p["pid"], name=p["name"]))
        await db.flush()

    async def is_honeypot_device(self, device_id: str, db: AsyncSession) -> bool:
        """Return True if device_id matches any active honeypot profile."""
        parts = device_id.lower().split(":")
        if len(parts) < 2:
            return False
        vid, pid = parts[0], parts[1]
        result = await db.execute(
            select(HoneypotProfile).where(
                HoneypotProfile.vid == vid,
                HoneypotProfile.pid == pid,
                HoneypotProfile.active.is_(True),
            )
        )
        return result.scalars().first() is not None

    async def add_profile(
        self, vid: str, pid: str, name: str, db: AsyncSession
    ) -> HoneypotProfile:
        profile = HoneypotProfile(vid=vid.lower(), pid=pid.lower(), name=name)
        db.add(profile)
        await db.flush()
        return profile

    async def check(
        self, device_id: str, agent_id: str, db: AsyncSession
    ) -> Optional[Alert]:
        """Check device_id; return high-confidence Alert if honeypot match."""
        if await self.is_honeypot_device(device_id, db):
            logger.warning(
                "HONEYPOT HIT: agent=%s device=%s", agent_id, device_id
            )
            return Alert(
                agent_id=agent_id,
                rule="honeypot_match",
                score=100.0,
                device_id=device_id,
                timestamp=datetime.now(timezone.utc),
                details_json=json.dumps(
                    {
                        "device_id": device_id,
                        "confidence": 1.0,
                        "description": "Device matches honeypot bait profile — possible cloned device",
                    }
                ),
            )
        return None
