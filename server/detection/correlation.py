"""Cross-agent correlation — detects shared devices and lateral movement."""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import List

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models import Event, HoneypotProfile

logger = logging.getLogger(__name__)


class CrossAgentCorrelator:
    async def find_shared_devices(self, db: AsyncSession) -> List[dict]:
        """Return devices seen by 2+ distinct agents — lateral movement signal."""
        result = await db.execute(
            select(
                Event.device_id,
                func.count(func.distinct(Event.agent_id)).label("agent_count"),
            )
            .group_by(Event.device_id)
            .having(func.count(func.distinct(Event.agent_id)) > 1)
        )
        rows = result.all()
        out = []
        for row in rows:
            # Get agent list
            agents_result = await db.execute(
                select(func.distinct(Event.agent_id)).where(
                    Event.device_id == row.device_id
                )
            )
            agents = [a[0] for a in agents_result.all()]
            out.append(
                {
                    "device_id": row.device_id,
                    "agent_count": row.agent_count,
                    "agents": agents,
                    "signal": "lateral_movement",
                }
            )
        return out

    async def find_device_clones(self, db: AsyncSession) -> List[dict]:
        """Return events where device_id matches a honeypot VID:PID — clone attack."""
        result = await db.execute(
            select(HoneypotProfile).where(HoneypotProfile.active.is_(True))
        )
        profiles = result.scalars().all()

        clones = []
        for profile in profiles:
            vid_pid = f"{profile.vid}:{profile.pid}"
            ev_result = await db.execute(
                select(Event).where(Event.device_id == vid_pid)
            )
            matches = ev_result.scalars().all()
            for ev in matches:
                clones.append(
                    {
                        "device_id": vid_pid,
                        "honeypot_name": profile.name,
                        "agent_id": ev.agent_id,
                        "event_id": ev.event_id,
                        "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                        "signal": "honeypot_clone",
                    }
                )
        return clones

    async def correlate_timewindow(
        self, device_id: str, window_seconds: int, db: AsyncSession
    ) -> List[dict]:
        """Return events for a device across all agents within a time window."""
        from datetime import datetime, timezone

        result = await db.execute(
            select(Event)
            .where(Event.device_id == device_id)
            .order_by(Event.timestamp.asc())
        )
        events = result.scalars().all()

        # Sliding window: any two events within window_seconds from different agents
        correlated = []
        for i, ev_a in enumerate(events):
            if ev_a.timestamp is None:
                continue
            for ev_b in events[i + 1 :]:
                if ev_b.timestamp is None:
                    continue
                if ev_a.agent_id == ev_b.agent_id:
                    continue
                delta = abs(
                    (ev_b.timestamp - ev_a.timestamp).total_seconds()
                )
                if delta <= window_seconds:
                    correlated.append(
                        {
                            "device_id": device_id,
                            "agent_a": ev_a.agent_id,
                            "agent_b": ev_b.agent_id,
                            "delta_seconds": delta,
                            "signal": "cross_agent_correlation",
                        }
                    )
        return correlated
