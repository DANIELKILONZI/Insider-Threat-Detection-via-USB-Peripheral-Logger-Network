"""Tests for cross-agent correlation."""
from datetime import datetime, timezone, timedelta

import pytest

from server.detection.correlation import CrossAgentCorrelator
from server.models import Event, HoneypotProfile


def _ev(agent_id, device_id, action="connect", hour=10):
    return Event(
        event_id=f"{agent_id}-{device_id}-{action}",
        agent_id=agent_id,
        actor="user",
        device_id=device_id,
        action=action,
        source_type="usb",
        confidence=1.0,
        raw_json="{}",
        event_hash="a" * 64,
        timestamp=datetime(2024, 1, 1, hour, 0, 0, tzinfo=timezone.utc),
    )


@pytest.mark.asyncio
async def test_find_shared_devices(db_session):
    corr = CrossAgentCorrelator()
    db_session.add(_ev("agent-1", "shared:device"))
    db_session.add(_ev("agent-2", "shared:device"))
    db_session.add(_ev("agent-1", "unique:device"))
    await db_session.flush()

    shared = await corr.find_shared_devices(db_session)
    device_ids = [s["device_id"] for s in shared]
    assert "shared:device" in device_ids
    assert "unique:device" not in device_ids


@pytest.mark.asyncio
async def test_no_shared_devices(db_session):
    corr = CrossAgentCorrelator()
    db_session.add(_ev("a1", "only-a1"))
    db_session.add(_ev("a2", "only-a2"))
    await db_session.flush()

    shared = await corr.find_shared_devices(db_session)
    assert shared == []


@pytest.mark.asyncio
async def test_find_device_clones(db_session):
    corr = CrossAgentCorrelator()
    # Add honeypot profile
    db_session.add(HoneypotProfile(vid="dead", pid="beef", name="Bait", active=True))
    # Add event matching honeypot
    db_session.add(_ev("agent-3", "dead:beef"))
    await db_session.flush()

    clones = await corr.find_device_clones(db_session)
    assert len(clones) >= 1
    assert clones[0]["signal"] == "honeypot_clone"


@pytest.mark.asyncio
async def test_correlate_timewindow(db_session):
    corr = CrossAgentCorrelator()
    ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    ev1 = Event(
        event_id="e1",
        agent_id="ag1",
        actor="u",
        device_id="correlate:me",
        action="connect",
        source_type="usb",
        confidence=1.0,
        raw_json="{}",
        event_hash="b" * 64,
        timestamp=ts,
    )
    ev2 = Event(
        event_id="e2",
        agent_id="ag2",
        actor="u",
        device_id="correlate:me",
        action="connect",
        source_type="usb",
        confidence=1.0,
        raw_json="{}",
        event_hash="c" * 64,
        timestamp=ts + timedelta(seconds=30),
    )
    db_session.add(ev1)
    db_session.add(ev2)
    await db_session.flush()

    results = await corr.correlate_timewindow("correlate:me", 60, db_session)
    assert len(results) >= 1
    assert results[0]["signal"] == "cross_agent_correlation"
