"""
server/notifications/notifiers.py – Out-of-band alert notification channels.

Supports two notification sinks:

1. **SMTP email** – sends an email to one or more SOC recipients when an
   alert fires.  Requires ITDN_SMTP_HOST (and optionally ITDN_SMTP_USER /
   ITDN_SMTP_PASSWORD for authenticated relays).

2. **Slack / Teams webhook** – POSTs a JSON payload to a pre-configured
   incoming-webhook URL.  The same URL format works for both Slack and
   Microsoft Teams (Teams also accepts Slack-compatible webhooks).

Both sinks are no-ops when the corresponding environment variables are not
configured, so no code changes are needed between dev and production.

Severity filter
---------------
Set ``ITDN_NOTIFY_MIN_SEVERITY`` (default: ``HIGH``) to suppress low-noise
notifications for minor alerts.  Only alerts at or above this severity level
will be dispatched to notification channels.

Severity ladder: LOW < MEDIUM < HIGH < CRITICAL
"""

from __future__ import annotations

import logging
import smtplib
import urllib.error
import urllib.request
from email.mime.text import MIMEText
from typing import Any, Dict

from server.config import (
    NOTIFY_MIN_SEVERITY,
    SLACK_WEBHOOK_URL,
    SMTP_FROM,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_TO,
    SMTP_USE_TLS,
    SMTP_USER,
)

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

AlertPayload = Dict[str, Any]


def _severity_passes(severity: str) -> bool:
    """Return True if *severity* meets the minimum notification threshold."""
    try:
        return _SEVERITY_ORDER.index(severity.upper()) >= _SEVERITY_ORDER.index(
            NOTIFY_MIN_SEVERITY.upper()
        )
    except ValueError:
        return True  # unknown severity always passes


# ---------------------------------------------------------------------------
# SMTP email
# ---------------------------------------------------------------------------

def send_email_alert(alert: AlertPayload) -> None:
    """Send an email notification for *alert* if SMTP is configured."""
    if not SMTP_HOST or not SMTP_TO:
        return
    if not _severity_passes(alert.get("severity", "LOW")):
        return

    recipients = [r.strip() for r in SMTP_TO.split(",") if r.strip()]
    if not recipients:
        return

    subject = (
        f"[ITDN {alert.get('severity', 'ALERT')}] "
        f"{alert.get('rule_name', 'alert')} on {alert.get('hostname', 'unknown')}"
    )
    body_lines = [
        f"Alert ID  : {alert.get('alert_id', 'N/A')}",
        f"Severity  : {alert.get('severity', 'N/A')}",
        f"Rule      : {alert.get('rule_name', 'N/A')}",
        f"Host      : {alert.get('hostname', 'N/A')}",
        f"Device    : {alert.get('device_id', 'N/A')}",
        "",
        alert.get("description", ""),
    ]
    body = "\n".join(body_lines)

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(recipients)

    try:
        if SMTP_USE_TLS:
            smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
            smtp.starttls()
        else:
            smtp = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
        if SMTP_USER and SMTP_PASSWORD:
            smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.sendmail(SMTP_FROM, recipients, msg.as_string())
        smtp.quit()
        logger.info("Email alert sent for alert_id=%s", alert.get("alert_id"))
    except Exception:  # pylint: disable=broad-except
        logger.exception("Failed to send email alert for alert_id=%s", alert.get("alert_id"))


# ---------------------------------------------------------------------------
# Slack / Teams webhook
# ---------------------------------------------------------------------------

def send_slack_alert(alert: AlertPayload) -> None:
    """POST an alert notification to the configured Slack/Teams webhook URL."""
    if not SLACK_WEBHOOK_URL:
        return
    if not _severity_passes(alert.get("severity", "LOW")):
        return

    import json

    severity = alert.get("severity", "ALERT")
    _colour_map = {
        "LOW": "#36a64f",
        "MEDIUM": "#ff9f00",
        "HIGH": "#e01e5a",
        "CRITICAL": "#4d0000",
    }
    colour = _colour_map.get(severity.upper(), "#888888")

    # Slack-compatible payload (also works with Teams via Slack-compat mode)
    payload = {
        "attachments": [
            {
                "color": colour,
                "title": (
                    f"[{severity}] {alert.get('rule_name', 'alert')} "
                    f"on {alert.get('hostname', 'unknown')}"
                ),
                "text": alert.get("description", ""),
                "fields": [
                    {"title": "Alert ID", "value": str(alert.get("alert_id", "N/A")), "short": True},
                    {"title": "Device", "value": str(alert.get("device_id", "N/A")), "short": True},
                ],
                "footer": "ITDN Insider Threat Detection",
            }
        ]
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            logger.info(
                "Slack alert posted for alert_id=%s (status=%d)",
                alert.get("alert_id"),
                resp.status,
            )
    except urllib.error.URLError:
        logger.exception("Failed to post Slack alert for alert_id=%s", alert.get("alert_id"))


# ---------------------------------------------------------------------------
# Unified dispatch
# ---------------------------------------------------------------------------

def notify(alert: AlertPayload) -> None:
    """Dispatch *alert* to all configured notification channels."""
    send_email_alert(alert)
    send_slack_alert(alert)
