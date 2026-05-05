"""Syslog (CEF) notification sink.

Emits a CEF-formatted syslog UDP datagram on every alert so that SIEM
systems (Splunk, QRadar, ArcSight …) can ingest events directly.

CEF header format:
  CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extensions
"""
from __future__ import annotations

import logging
import socket
from datetime import datetime, timezone
from typing import Any, Dict

from server.notifications.base import NotificationSink

logger = logging.getLogger(__name__)

# Map score ranges to CEF severity (0-10)
def _cef_severity(score: float) -> int:
    if score >= 100:
        return 10
    if score >= 80:
        return 8
    if score >= 60:
        return 6
    if score >= 40:
        return 4
    return 2


class SyslogSink(NotificationSink):
    """Send CEF-formatted UDP syslog datagrams to a SIEM collector.

    Args:
        host: Syslog collector host (default: localhost)
        port: UDP port (default: 514)
        facility: Syslog facility number 0–23 (default: 1 = user)
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 514,
        facility: int = 1,
    ) -> None:
        self.host = host
        self.port = port
        self.facility = facility
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _build_cef(self, alert: Dict[str, Any]) -> str:
        severity = _cef_severity(float(alert.get("score", 0)))
        rule = alert.get("rule", "unknown").replace("|", "-")
        agent_id = alert.get("agent_id", "N/A")
        device_id = alert.get("device_id", "N/A")
        ts = alert.get("timestamp", datetime.now(timezone.utc).isoformat())
        alert_id = alert.get("id", "0")

        # CEF header
        header = (
            f"CEF:0|InsiderThreat|USB-Logger|1.0"
            f"|{rule}|{rule}|{severity}"
        )
        # CEF extensions
        ext = (
            f"rt={ts} "
            f"dvchost={agent_id} "
            f"deviceExternalId={alert_id} "
            f"cs1={device_id} "
            f"cs1Label=device_id "
            f"msg={alert.get('details_json', '{}')}"
        )
        return f"{header}|{ext}"

    async def send(self, alert: Dict[str, Any]) -> None:
        cef = self._build_cef(alert)
        # Prepend syslog priority byte (facility * 8 + severity)
        priority = self.facility * 8 + min(_cef_severity(float(alert.get("score", 0))), 7)
        message = f"<{priority}>{cef}"
        try:
            self._sock.sendto(message.encode("utf-8"), (self.host, self.port))
            logger.debug("CEF syslog sent to %s:%s", self.host, self.port)
        except Exception:
            logger.exception("Failed to send CEF syslog alert")
