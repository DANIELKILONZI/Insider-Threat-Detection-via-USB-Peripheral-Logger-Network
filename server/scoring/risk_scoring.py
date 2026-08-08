"""
server/scoring/risk_scoring.py – Cumulative risk scoring engine for ITDN.
"""

from __future__ import annotations

import logging
from typing import Any, List

logger = logging.getLogger(__name__)

RULE_WEIGHTS = {
    "unknown_device": 40,
    "after_hours_device": 20,
    "high_volume_transfer": 50,
    "rapid_cycle": 30,
    "honeypot_device": 100,
}


class RiskScorer:
    """Scores events by fired alert rules and accumulates a 24h rolling score."""

    def __init__(self, db: Any) -> None:
        self._db = db

    def score_event(self, hostname: str, fired_alerts: List[Any]) -> int:
        """
        Compute delta score from fired_alerts, persist via db.upsert_risk_score,
        and return the updated cumulative score.
        """
        delta = sum(
            RULE_WEIGHTS.get(alert.rule_name, 10)
            for alert in fired_alerts
        )
        if delta > 0:
            self._db.upsert_risk_score(hostname, delta)
        return self._db.get_risk_score(hostname)
