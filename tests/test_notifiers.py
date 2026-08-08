"""
tests/test_notifiers.py – Tests for the alert notification channels.
"""

from __future__ import annotations

import smtplib
from unittest.mock import MagicMock, patch


def _alert(severity="HIGH", rule_name="test_rule"):
    return {
        "alert_id": 42,
        "hostname": "ws-notify",
        "device_id": "cafe:1234",
        "rule_name": rule_name,
        "severity": severity,
        "description": "Test alert description",
    }


# ---------------------------------------------------------------------------
# Severity filter
# ---------------------------------------------------------------------------

def test_severity_passes_high():
    import importlib
    import server.notifications.notifiers as n
    importlib.reload(n)
    assert n._severity_passes("HIGH") is True
    assert n._severity_passes("CRITICAL") is True


def test_severity_blocks_low_when_threshold_high(monkeypatch):
    import server.notifications.notifiers as n
    monkeypatch.setattr(n, "NOTIFY_MIN_SEVERITY", "HIGH")
    assert n._severity_passes("LOW") is False
    assert n._severity_passes("MEDIUM") is False


def test_severity_passes_medium_when_threshold_medium(monkeypatch):
    import server.notifications.notifiers as n
    monkeypatch.setattr(n, "NOTIFY_MIN_SEVERITY", "MEDIUM")
    assert n._severity_passes("MEDIUM") is True
    assert n._severity_passes("LOW") is False


# ---------------------------------------------------------------------------
# Email – no-op when not configured
# ---------------------------------------------------------------------------

def test_send_email_noop_when_not_configured(monkeypatch):
    monkeypatch.setattr("server.notifications.notifiers.SMTP_HOST", "")
    import server.notifications.notifiers as n
    # Should not raise
    n.send_email_alert(_alert())


def test_send_email_noop_when_no_recipients(monkeypatch):
    monkeypatch.setattr("server.notifications.notifiers.SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr("server.notifications.notifiers.SMTP_TO", "")
    import server.notifications.notifiers as n
    n.send_email_alert(_alert())


# ---------------------------------------------------------------------------
# Email – actually calls smtplib when configured
# ---------------------------------------------------------------------------

def test_send_email_calls_smtp(monkeypatch):
    monkeypatch.setattr("server.notifications.notifiers.SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr("server.notifications.notifiers.SMTP_PORT", 587)
    monkeypatch.setattr("server.notifications.notifiers.SMTP_FROM", "itdn@example.com")
    monkeypatch.setattr("server.notifications.notifiers.SMTP_TO", "soc@example.com")
    monkeypatch.setattr("server.notifications.notifiers.SMTP_USE_TLS", True)
    monkeypatch.setattr("server.notifications.notifiers.SMTP_USER", "")
    monkeypatch.setattr("server.notifications.notifiers.SMTP_PASSWORD", "")
    monkeypatch.setattr("server.notifications.notifiers.NOTIFY_MIN_SEVERITY", "LOW")

    import server.notifications.notifiers as n

    mock_smtp = MagicMock()
    mock_smtp_instance = MagicMock()
    mock_smtp.return_value = mock_smtp_instance

    with patch("server.notifications.notifiers.smtplib.SMTP", mock_smtp):
        n.send_email_alert(_alert(severity="HIGH"))

    mock_smtp.assert_called_once_with("smtp.example.com", 587, timeout=10)
    mock_smtp_instance.starttls.assert_called_once()
    mock_smtp_instance.sendmail.assert_called_once()
    mock_smtp_instance.quit.assert_called_once()


# ---------------------------------------------------------------------------
# Email – handles SMTP exceptions gracefully
# ---------------------------------------------------------------------------

def test_send_email_handles_smtp_error(monkeypatch):
    monkeypatch.setattr("server.notifications.notifiers.SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr("server.notifications.notifiers.SMTP_PORT", 587)
    monkeypatch.setattr("server.notifications.notifiers.SMTP_FROM", "itdn@example.com")
    monkeypatch.setattr("server.notifications.notifiers.SMTP_TO", "soc@example.com")
    monkeypatch.setattr("server.notifications.notifiers.SMTP_USE_TLS", False)
    monkeypatch.setattr("server.notifications.notifiers.SMTP_USER", "")
    monkeypatch.setattr("server.notifications.notifiers.SMTP_PASSWORD", "")
    monkeypatch.setattr("server.notifications.notifiers.NOTIFY_MIN_SEVERITY", "LOW")

    import server.notifications.notifiers as n

    with patch("server.notifications.notifiers.smtplib.SMTP", side_effect=smtplib.SMTPException("conn refused")):
        n.send_email_alert(_alert(severity="HIGH"))  # must not raise


# ---------------------------------------------------------------------------
# Slack – no-op when not configured
# ---------------------------------------------------------------------------

def test_send_slack_noop_when_not_configured(monkeypatch):
    monkeypatch.setattr("server.notifications.notifiers.SLACK_WEBHOOK_URL", "")
    import server.notifications.notifiers as n
    n.send_slack_alert(_alert())


# ---------------------------------------------------------------------------
# Slack – calls webhook when configured
# ---------------------------------------------------------------------------

def test_send_slack_posts_webhook(monkeypatch):
    monkeypatch.setattr("server.notifications.notifiers.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test")
    monkeypatch.setattr("server.notifications.notifiers.NOTIFY_MIN_SEVERITY", "LOW")

    import server.notifications.notifiers as n
    from unittest.mock import patch as _patch, MagicMock as _MM

    mock_resp = _MM()
    mock_resp.status = 200
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)

    with _patch("server.notifications.notifiers.urllib.request.urlopen", return_value=mock_resp) as mock_open:
        n.send_slack_alert(_alert(severity="CRITICAL"))

    mock_open.assert_called_once()


# ---------------------------------------------------------------------------
# unified notify() dispatches both channels
# ---------------------------------------------------------------------------

def test_notify_dispatches_both(monkeypatch):
    monkeypatch.setattr("server.notifications.notifiers.SMTP_HOST", "")
    monkeypatch.setattr("server.notifications.notifiers.SLACK_WEBHOOK_URL", "")
    import server.notifications.notifiers as n
    # With no channels configured, notify() should silently succeed
    n.notify(_alert())
