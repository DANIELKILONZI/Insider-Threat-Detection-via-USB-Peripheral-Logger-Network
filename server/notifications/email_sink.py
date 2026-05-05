"""Email (SMTP) notification sink."""
from __future__ import annotations

import logging
import smtplib
from email.mime.text import MIMEText
from typing import Any, Dict, List

from server.notifications.base import NotificationSink

logger = logging.getLogger(__name__)


class EmailSink(NotificationSink):
    """Send alert summaries via SMTP.

    Environment / constructor params:
        smtp_host   – SMTP server hostname (default: localhost)
        smtp_port   – SMTP port (default: 587)
        smtp_user   – login username (optional)
        smtp_pass   – login password (optional)
        from_addr   – sender address
        to_addrs    – list of recipient addresses
        use_tls     – STARTTLS (default: True)
    """

    def __init__(
        self,
        from_addr: str,
        to_addrs: List[str],
        smtp_host: str = "localhost",
        smtp_port: int = 587,
        smtp_user: str = "",
        smtp_pass: str = "",
        use_tls: bool = True,
    ) -> None:
        self.from_addr = from_addr
        self.to_addrs = to_addrs
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_pass = smtp_pass
        self.use_tls = use_tls

    async def send(self, alert: Dict[str, Any]) -> None:
        subject = (
            f"[ALERT] {alert.get('rule', 'unknown')} "
            f"— agent {alert.get('agent_id', '?')} "
            f"score {alert.get('score', 0):.0f}"
        )
        body = (
            f"Alert ID   : {alert.get('id', 'N/A')}\n"
            f"Agent      : {alert.get('agent_id', 'N/A')}\n"
            f"Rule       : {alert.get('rule', 'N/A')}\n"
            f"Score      : {alert.get('score', 0):.1f}\n"
            f"Device     : {alert.get('device_id', 'N/A')}\n"
            f"Timestamp  : {alert.get('timestamp', 'N/A')}\n"
            f"Details    : {alert.get('details_json', '{}')}\n"
        )
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as conn:
                if self.use_tls:
                    conn.starttls()
                if self.smtp_user:
                    conn.login(self.smtp_user, self.smtp_pass)
                conn.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            logger.info("Email alert sent to %s", self.to_addrs)
        except Exception:
            logger.exception("Failed to send email alert")
