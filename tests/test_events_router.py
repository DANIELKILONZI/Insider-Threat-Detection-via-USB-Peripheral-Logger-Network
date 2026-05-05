"""Integration tests for the events router."""
import json
from datetime import datetime, timezone

import pytest
from httpx import AsyncClient, ASGITransport

from server.main import app


@pytest.mark.asyncio
async def test_health_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_post_event(db_session):
    from server.routers.events import create_event
    from shared.schema import NormalizedEvent

    ev = NormalizedEvent(
        agent_id="router-agent",
        actor="user",
        device_id="abcd:1234",
        action="connect",
        source_type="usb",
    )
    result = await create_event(ev, db_session)
    assert result["event_id"] == ev.event_id


@pytest.mark.asyncio
async def test_list_events_empty(db_session):
    from server.routers.events import list_events

    result = await list_events("nonexistent-agent", db=db_session)
    assert result == []


@pytest.mark.asyncio
async def test_post_event_triggers_honeypot_alert(db_session):
    from server.honeypot.profiles import HoneypotManager
    from server.routers.events import create_event
    from shared.schema import NormalizedEvent

    # Seed honeypot
    mgr = HoneypotManager()
    await mgr.add_profile("dead", "beef", "Bait", db_session)

    ev = NormalizedEvent(
        agent_id="hp-agent",
        actor="attacker",
        device_id="dead:beef",
        action="connect",
        source_type="usb",
    )
    result = await create_event(ev, db_session)
    assert result["alert"] is not None
    assert result["alert"]["rule"] == "honeypot_match"
