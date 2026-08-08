"""
server/notifications/splunk_forwarder.py – Push events and alerts to Splunk via HEC.

The Splunk HTTP Event Collector (HEC) endpoint accepts JSON payloads over
HTTPS.  This module sends each event/alert as a separate HEC record so they
appear in the configured index and can be correlated by Splunk ES correlation
searches.

Usage::

    from server.notifications.splunk_forwarder import forward_event, forward_alert
    forward_event(event_dict)
    forward_alert(alert_dict)
"""

from __future__ import annotations

import json
import logging
import ssl
import urllib.request
from typing import Any, Dict

from server.config import SPLUNK_HEC_TOKEN, SPLUNK_HEC_URL, SPLUNK_INDEX, SPLUNK_VERIFY_TLS

logger = logging.getLogger(__name__)


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not SPLUNK_VERIFY_TLS:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _send(sourcetype: str, payload: Dict[str, Any]) -> bool:
    """
    POST a single HEC record to Splunk.  Returns True on success.

    Silently returns False (and logs a warning) when SPLUNK_HEC_TOKEN is not
    configured so that the rest of the pipeline keeps working in dev mode.
    """
    if not SPLUNK_HEC_TOKEN:
        logger.debug("Splunk HEC token not configured – skipping forwarding")
        return False

    hec_record = {
        "index": SPLUNK_INDEX,
        "sourcetype": sourcetype,
        "source": "itdn",
        "event": payload,
    }
    body = json.dumps(hec_record).encode("utf-8")
    req = urllib.request.Request(
        SPLUNK_HEC_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=_ssl_context(), timeout=10) as resp:
            if resp.status == 200:
                return True
            logger.warning("Splunk HEC returned HTTP %d", resp.status)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("Splunk HEC forwarding failed: %s", exc)
    return False


def forward_event(event: Dict[str, Any]) -> bool:
    """Forward a raw device event to Splunk."""
    return _send("itdn:device_event", event)


def forward_alert(alert: Dict[str, Any]) -> bool:
    """Forward a fired alert to Splunk."""
    return _send("itdn:alert", alert)
