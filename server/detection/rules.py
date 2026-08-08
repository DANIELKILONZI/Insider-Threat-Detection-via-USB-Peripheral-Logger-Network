"""
server/detection/rules.py – Anomaly detection rules engine.

Each rule is a plain function with signature::

    rule_xxx(event: EventDict, db) -> Optional[Alert]

where *db* is the ``server.database`` module (injected so tests can mock it).

An ``Alert`` namedtuple is returned when the rule fires, or ``None`` when it
does not.

Rules implemented
-----------------
1. after_hours_device      – USB/BT device connected outside business hours
                             (timezone-aware: uses per-host UTC offset when known)
2. unknown_device          – device ID never seen before on this host
3. high_volume_transfer    – cumulative bytes transferred in last hour > threshold
4. rapid_cycle             – ≥ N connect/disconnect events within a short window
5. cross_agent_device      – same device seen on multiple hosts within an hour
6. honeypot_device         – device matches a configured honeypot VID:PID
7. known_malicious_device  – device VID:PID found in the threat feed (CRITICAL)
8. user_unknown_device     – device never seen before by this specific user (UBA)
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Dict, List, NamedTuple, Optional

from server.detection.rule_config import get_config
from server.metrics import METRICS

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
    """Fire when a device is *connected* outside of business hours.

    When a per-host UTC offset has been recorded via the timezone inference
    subsystem, the event timestamp is adjusted to local time before the
    after-hours window is evaluated.  This prevents false positives for
    agents in non-UTC timezones.
    """
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

    # Apply per-host timezone offset when available
    hostname = event.get("hostname", "")
    try:
        offset = db.get_host_timezone(hostname)
        if offset is not None:
            ts = ts + datetime.timedelta(hours=offset)
    except Exception:  # pylint: disable=broad-except
        pass  # db may not have the function in tests

    hour = ts.hour
    # After-hours is after_hours_start .. midnight .. after_hours_end
    if after_hours_start <= hour or hour < after_hours_end:
        return Alert(
            rule_name="after_hours_device",
            severity="HIGH",
            description=(
                f"Device {event.get('device_id')} connected at {ts_str} "
                f"on host {hostname} – outside business hours "
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


def rule_cross_agent_device(event: EventDict, db: Any) -> Optional[Alert]:
    """Fire when the same device_id appears on a different host within the last hour."""
    device_id = event.get("device_id", "")
    hostname = event.get("hostname", "")
    if not device_id or not hostname:
        return None
    recent = db.get_recent_events_by_device(device_id, window_secs=3600)
    other_hosts = {r["hostname"] for r in recent if r["hostname"] != hostname}
    if other_hosts:
        return Alert(
            rule_name="cross_agent_device",
            severity="CRITICAL",
            description=(
                f"Device {device_id} seen on multiple hosts within 1 hour "
                f"(also on: {', '.join(sorted(other_hosts))}) – possible lateral movement."
            ),
        )
    return None


def rule_honeypot_device(event: EventDict, db: Any) -> Optional[Alert]:
    """Fire when a known honeypot device is connected."""
    from server.detection.honeypot import is_honeypot_device
    device_id = event.get("device_id", "")
    if device_id and is_honeypot_device(device_id):
        return Alert(
            rule_name="honeypot_device",
            severity="CRITICAL",
            description=(
                f"Honeypot device triggered: {device_id} connected to "
                f"{event.get('hostname', 'unknown')} – possible device cloning attack."
            ),
        )
    return None


def rule_known_malicious_device(event: EventDict, db: Any) -> Optional[Alert]:
    """Fire CRITICAL when the device VID:PID appears in the threat feed."""
    if event.get("event_type") != "connected":
        return None
    from server.detection.threat_feed import is_known_malicious
    device_id = event.get("device_id", "")
    if device_id and is_known_malicious(device_id):
        return Alert(
            rule_name="known_malicious_device",
            severity="CRITICAL",
            description=(
                f"Known-malicious device {device_id} connected to "
                f"{event.get('hostname', 'unknown')} – matches threat feed entry."
            ),
        )
    return None


def rule_user_unknown_device(event: EventDict, db: Any) -> Optional[Alert]:
    """Fire when the current user has never been seen using this device before (UBA).

    The event must include a non-empty ``user`` field for this rule to fire.
    """
    if event.get("event_type") != "connected":
        return None
    username = event.get("user", "")
    if not username:
        return None
    hostname = event.get("hostname", "")
    device_id = event.get("device_id", "")
    try:
        if db.user_device_is_new(username, hostname, device_id):
            return Alert(
                rule_name="user_unknown_device",
                severity="HIGH",
                description=(
                    f"User '{username}' has never previously used device {device_id} "
                    f"on host {hostname} – possible credential-sharing or theft."
                ),
            )
    except Exception:  # pylint: disable=broad-except
        pass  # db may not have UBA methods in older deployments
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_RULES = [
    rule_after_hours_device,
    rule_unknown_device,
    rule_high_volume_transfer,
    rule_rapid_cycle,
    rule_cross_agent_device,
    rule_honeypot_device,
    rule_known_malicious_device,
    rule_user_unknown_device,
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
                METRICS.inc_rule_fire(result.rule_name)
                logger.info(
                    "Rule '%s' fired [%s]: %s",
                    result.rule_name,
                    result.severity,
                    result.description,
                )
        except Exception:  # pylint: disable=broad-except
            logger.exception("Rule %s raised an exception", rule_fn.__name__)
    return alerts
