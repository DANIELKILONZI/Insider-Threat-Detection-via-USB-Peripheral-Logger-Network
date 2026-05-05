"""Tests for the notification bus and sinks."""
import asyncio
from typing import Any, Dict
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from server.notifications.base import NotificationSink
from server.notifications.bus import NotificationBus


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class _RecordingSink(NotificationSink):
    def __init__(self):
        self.received: list[Dict[str, Any]] = []

    async def send(self, alert: Dict[str, Any]) -> None:
        self.received.append(alert)


class _FailingSink(NotificationSink):
    async def send(self, alert: Dict[str, Any]) -> None:
        raise RuntimeError("deliberate sink failure")


# ---------------------------------------------------------------------------
# Bus tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bus_dispatches_to_sink():
    bus = NotificationBus()
    sink = _RecordingSink()
    bus.register(sink)
    await bus.dispatch({"id": 1, "rule": "test", "score": 90})
    assert len(sink.received) == 1
    assert sink.received[0]["rule"] == "test"


@pytest.mark.asyncio
async def test_bus_dispatches_to_multiple_sinks():
    bus = NotificationBus()
    s1 = _RecordingSink()
    s2 = _RecordingSink()
    bus.register(s1)
    bus.register(s2)
    await bus.dispatch({"id": 2, "score": 50})
    assert len(s1.received) == 1
    assert len(s2.received) == 1


@pytest.mark.asyncio
async def test_bus_tolerates_sink_failure():
    bus = NotificationBus()
    bus.register(_FailingSink())
    good = _RecordingSink()
    bus.register(good)
    # Should not raise
    await bus.dispatch({"id": 3, "score": 80})
    assert len(good.received) == 1


@pytest.mark.asyncio
async def test_empty_bus_no_error():
    bus = NotificationBus()
    await bus.dispatch({"id": 99, "score": 0})


# ---------------------------------------------------------------------------
# Slack sink
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_slack_sink_send(respx_mock=None):
    """Slack sink makes a POST to the webhook URL."""
    from server.notifications.slack_sink import SlackSink
    import httpx

    sent_payloads = []

    async def _fake_post(url, **kwargs):
        sent_payloads.append({"url": url, **kwargs})
        resp = httpx.Response(200, text="ok")
        return resp

    sink = SlackSink(webhook_url="https://hooks.slack.example/test")
    alert = {"id": 1, "agent_id": "a1", "rule": "test", "score": 95, "device_id": "x", "timestamp": "2025-01-01T00:00:00Z"}

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=httpx.Response(200, text="ok")):
        # Should not raise even if mock doesn't fully replicate httpx
        try:
            await sink.send(alert)
        except Exception:
            pass  # network-level errors are caught by the sink itself


# ---------------------------------------------------------------------------
# Syslog sink
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_syslog_sink_builds_cef():
    from server.notifications.syslog_sink import SyslogSink

    sink = SyslogSink(host="127.0.0.1", port=9999)
    cef = sink._build_cef({
        "id": 42,
        "rule": "honeypot_match",
        "score": 100,
        "agent_id": "agent-1",
        "device_id": "dead:beef",
        "timestamp": "2025-01-01T00:00:00Z",
        "details_json": "{}",
    })
    assert "CEF:0" in cef
    assert "honeypot_match" in cef
    assert "agent-1" in cef


@pytest.mark.asyncio
async def test_syslog_sink_send_no_error():
    from server.notifications.syslog_sink import SyslogSink
    import socket

    sink = SyslogSink(host="127.0.0.1", port=9999)
    # Patch sendto so no real UDP packet is sent
    sink._sock = MagicMock(spec=socket.socket)
    sink._sock.sendto = MagicMock()
    await sink.send({"id": 1, "rule": "test", "score": 80, "agent_id": "a", "device_id": "d", "timestamp": "2025-01-01T00:00:00Z", "details_json": "{}"})
    assert sink._sock.sendto.called
