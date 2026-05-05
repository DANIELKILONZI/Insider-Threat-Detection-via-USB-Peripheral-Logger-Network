"""Rule-based risk scoring engine with rolling-window cumulative score."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import config
from server.models import Alert, AllowlistedDevice, BaselineDevice, Event
from shared.schema import NormalizedEvent

logger = logging.getLogger(__name__)

# USB mass-storage VID:PID prefixes (class 08xx or well-known devices)
MASS_STORAGE_PIDS = {"0781", "0951", "058f", "1307", "0bda"}  # SanDisk, Kingston, etc.

# Points per rule
RULES = {
    "unknown_device": 40,
    "off_hours": 20,
    "mass_storage": 30,
    "new_device": 25,
    "bluetooth_scan": 15,
    "high_frequency": 35,
}


class RiskEngine:
    def __init__(
        self,
        threshold: Optional[float] = None,
        rolling_window_seconds: Optional[int] = None,
        off_hours_start: int = 18,
        off_hours_end: int = 8,
    ) -> None:
        self.threshold = threshold if threshold is not None else config.risk_threshold
        self.rolling_window = (
            rolling_window_seconds
            if rolling_window_seconds is not None
            else config.rolling_window_seconds
        )
        self.off_hours_start = off_hours_start
        self.off_hours_end = off_hours_end

    # ------------------------------------------------------------------
    def _is_off_hours(self, ts: datetime) -> bool:
        hour = ts.hour
        if self.off_hours_start > self.off_hours_end:
            return hour >= self.off_hours_start or hour < self.off_hours_end
        return self.off_hours_start <= hour < self.off_hours_end

    def _is_mass_storage(self, device_id: str) -> bool:
        parts = device_id.lower().split(":")
        if len(parts) >= 2:
            return parts[0] in MASS_STORAGE_PIDS or parts[1] in MASS_STORAGE_PIDS
        return False

    # ------------------------------------------------------------------
    async def _is_allowlisted(self, agent_id: str, device_id: str, db: AsyncSession) -> bool:
        """Return True if device_id is on the per-agent or org-wide allowlist."""
        result = await db.execute(
            select(AllowlistedDevice).where(
                (AllowlistedDevice.device_id == device_id)
                & (
                    (AllowlistedDevice.agent_id == agent_id)
                    | (AllowlistedDevice.agent_id == "*")
                )
            )
        )
        return result.scalars().first() is not None

    # ------------------------------------------------------------------
    async def score_event(
        self, event: NormalizedEvent, db: AsyncSession
    ) -> Tuple[float, Optional[Alert]]:
        fired: list[str] = []
        score = 0.0

        # BT scan
        if event.source_type == "bluetooth" and event.action == "scan":
            score += RULES["bluetooth_scan"]
            fired.append("bluetooth_scan")

        # Off-hours
        if self._is_off_hours(event.timestamp):
            score += RULES["off_hours"]
            fired.append("off_hours")

        # Mass storage
        if self._is_mass_storage(event.device_id):
            score += RULES["mass_storage"]
            fired.append("mass_storage")

        # new_device: first time this agent has ever seen this device (no baseline row)
        # unknown_device: device seen before but less than 3 times (not established as normal)
        # Skip both rules when the device is on the allowlist.
        allowlisted = await self._is_allowlisted(event.agent_id, event.device_id, db)

        result = await db.execute(
            select(BaselineDevice).where(
                BaselineDevice.agent_id == event.agent_id,
                BaselineDevice.device_id == event.device_id,
            )
        )
        baseline_row = result.scalars().first()
        is_first_ever = baseline_row is None
        is_not_established = baseline_row is None or baseline_row.seen_count < 3

        if is_first_ever and not allowlisted:
            score += RULES["new_device"]
            fired.append("new_device")

        if is_not_established and not allowlisted:
            score += RULES["unknown_device"]
            fired.append("unknown_device")

        # High frequency: >10 events in last 60 s
        from datetime import timedelta

        window_start = event.timestamp - timedelta(seconds=60)
        count_result = await db.execute(
            select(func.count(Event.id)).where(
                Event.agent_id == event.agent_id,
                Event.timestamp >= window_start,
            )
        )
        event_count = count_result.scalar() or 0
        if event_count > 10:
            score += RULES["high_frequency"]
            fired.append("high_frequency")

        # Cumulative rolling window
        from datetime import timedelta as td

        window_start_roll = event.timestamp - td(seconds=self.rolling_window)
        past_result = await db.execute(
            select(func.sum(Alert.score)).where(
                Alert.agent_id == event.agent_id,
                Alert.timestamp >= window_start_roll,
            )
        )
        cumulative = (past_result.scalar() or 0.0) + score

        alert = None
        if cumulative >= self.threshold and fired:
            alert = Alert(
                agent_id=event.agent_id,
                rule=", ".join(fired),
                score=cumulative,
                device_id=event.device_id,
                timestamp=event.timestamp,
                details_json=json.dumps(
                    {
                        "event_id": event.event_id,
                        "rules_fired": fired,
                        "event_score": score,
                        "cumulative": cumulative,
                    }
                ),
            )

        return score, alert
