"""
server/rules.py – Anomaly detection rules engine.

Each rule is a plain function with signature::

    rule_xxx(event: EventDict, db) -> Optional[Alert]

where *db* is the ``server.database`` module (injected so tests can mock it).

An ``Alert`` namedtuple is returned when the rule fires, or ``None`` when it
does not.

Rules implemented
-----------------
1. after_hours_device    – USB/BT device connected outside business hours
2. unknown_device        – device ID never seen before on this host
3. high_volume_transfer  – cumulative bytes transferred in last hour > threshold
4. rapid_cycle           – ≥ N connect/disconnect events within a short window
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Dict, List, NamedTuple, Optional

from server.rule_config import get_config

logger = logging.getLogger(__name__)

EventDict = Dict[str, Any]


class Alert(NamedTuple):
    rule_name: str
    severity: str      # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    description: str


# ---------------------------------------------------------------------------
# Individual rules
# ---------------------------------------------------------------------------

def rule_after_hours_device(event: EventDict, db: Any) -> Optional[Alert]:
    """Fire when a device is *connected* outside of business hours."""
    if event.get("event_type") != "connected":
        return None

    cfg = get_config()
    after_hours_start: int = cfg["after_hours_start"]
    after_hours_end: int = cfg["after_hours_end"]

    # Parse the event timestamp; fall back to current UTC time
    ts_str = event.get("timestamp", "")
    try:
        ts = datetime.datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        ts = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    hour = ts.hour
    # After-hours is after_hours_start .. midnight .. after_hours_end
    if after_hours_start <= hour or hour < after_hours_end:
        return Alert(
            rule_name="after_hours_device",
            severity="HIGH",
            description=(
                f"Device {event.get('device_id')} connected at {ts_str} "
                f"on host {event.get('hostname')} – outside business hours "
                f"({after_hours_start:02d}:00–{after_hours_end:02d}:00)."
            ),
        )
    return None


def rule_unknown_device(event: EventDict, db: Any) -> Optional[Alert]:
    """Fire when a device ID has never been seen on this host before."""
    if event.get("event_type") != "connected":
        return None

    hostname = event.get("hostname", "")
    device_id = event.get("device_id", "")
    if db.device_is_new(hostname, device_id):
        return Alert(
            rule_name="unknown_device",
            severity="MEDIUM",
            description=(
                f"Previously unseen device {device_id} "
                f"(serial={event.get('serial', 'N/A')}) "
                f"connected to host {hostname}."
            ),
        )
    return None


def rule_high_volume_transfer(event: EventDict, db: Any) -> Optional[Alert]:
    """
    Fire when the cumulative transfer_bytes for a host in the last hour
    exceeds the configured volume threshold.
    """
    if int(event.get("transfer_bytes", 0)) == 0:
        return None

    hostname = event.get("hostname", "")
    rows = db.get_recent_events(hostname, window_secs=3600)
    total_bytes = sum(int(r["transfer_bytes"]) for r in rows)
    total_bytes += int(event.get("transfer_bytes", 0))

    volume_threshold = get_config()["volume_threshold_bytes"]
    if total_bytes >= volume_threshold:
        gb = total_bytes / (1024 ** 3)
        return Alert(
            rule_name="high_volume_transfer",
            severity="CRITICAL",
            description=(
                f"Host {hostname} transferred {gb:.2f} GB via USB/BT "
                f"in the last hour (threshold: "
                f"{volume_threshold/(1024**3):.0f} GB)."
            ),
        )
    return None


def rule_rapid_cycle(event: EventDict, db: Any) -> Optional[Alert]:
    """
    Fire when a host generates ≥ rapid_cycle_count USB events within
    rapid_cycle_window_secs (indicates rapid plug/unplug – common during
    data exfiltration across multiple devices).
    """
    cfg = get_config()
    rapid_cycle_count: int = cfg["rapid_cycle_count"]
    rapid_cycle_window: int = cfg["rapid_cycle_window_secs"]

    hostname = event.get("hostname", "")
    rows = db.get_recent_events(hostname, window_secs=rapid_cycle_window)
    # Count only connect/disconnect events for the same device family
    cycle_events = [
        r for r in rows if r["event_type"] in ("connected", "disconnected")
    ]
    count = len(cycle_events) + 1  # +1 for the current event

    if count >= rapid_cycle_count:
        return Alert(
            rule_name="rapid_cycle",
            severity="HIGH",
            description=(
                f"Host {hostname} had {count} connect/disconnect events "
                f"within {rapid_cycle_window}s "
                f"(threshold: {rapid_cycle_count}). "
                f"Possible rapid-cycle exfiltration."
            ),
        )
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_RULES = [
    rule_after_hours_device,
    rule_unknown_device,
    rule_high_volume_transfer,
    rule_rapid_cycle,
]


def evaluate(event: EventDict, db: Any) -> List[Alert]:
    """
    Run all rules against *event*.

    Returns a (possibly empty) list of ``Alert`` objects for every rule
    that fired.
    """
    alerts: List[Alert] = []
    for rule_fn in _RULES:
        try:
            result = rule_fn(event, db)
            if result is not None:
                alerts.append(result)
                logger.info(
                    "Rule '%s' fired [%s]: %s",
                    result.rule_name,
                    result.severity,
                    result.description,
                )
        except Exception:  # pylint: disable=broad-except
            logger.exception("Rule %s raised an exception", rule_fn.__name__)
    return alerts
