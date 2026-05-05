"""
server/alert_manager.py – Deduplicate, persist, and forward alerts.

The manager sits between the rules engine and the database/Splunk forwarder.
It suppresses duplicate alerts for the same host+device+rule within the
configured deduplication window to avoid alert fatigue.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

import server.database as db
import server.es_forwarder as es
import server.splunk_forwarder as splunk
from server.config import ALERT_DEDUP_WINDOW_SECS
from server.metrics import METRICS
from server.notifiers import notify
from server.rules import Alert

logger = logging.getLogger(__name__)

EventDict = Dict[str, Any]


def process_alerts(event: EventDict, alerts: list[Alert]) -> None:
    """
    For each *alert* in *alerts*:
    1. Check whether an identical alert was already fired within the dedup window.
    2. If not, persist it and forward it to Splunk.
    """
    hostname = event.get("hostname", "")
    device_id = event.get("device_id", "")

    for alert in alerts:
        existing = db.get_recent_alert(
            hostname, device_id, alert.rule_name, ALERT_DEDUP_WINDOW_SECS
        )
        if existing:
            logger.debug(
                "Suppressing duplicate alert '%s' for %s on %s (within dedup window)",
                alert.rule_name,
                device_id,
                hostname,
            )
            continue

        alert_id = db.insert_alert(
            hostname=hostname,
            device_id=device_id,
            rule_name=alert.rule_name,
            severity=alert.severity,
            description=alert.description,
            raw_event=event,
        )
        METRICS.inc_alerts_fired(alert.severity, alert.rule_name)
        logger.warning(
            "[ALERT id=%d] [%s] %s: %s",
            alert_id,
            alert.severity,
            alert.rule_name,
            alert.description,
        )

        alert_payload = {
            "alert_id": alert_id,
            "hostname": hostname,
            "device_id": device_id,
            "rule_name": alert.rule_name,
            "severity": alert.severity,
            "description": alert.description,
            "event": event,
        }
        splunk.forward_alert(alert_payload)
        es.forward_alert(alert_payload)
        notify(alert_payload)
