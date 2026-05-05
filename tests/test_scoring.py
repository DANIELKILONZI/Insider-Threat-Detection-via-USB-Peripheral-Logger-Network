"""Tests for the risk scoring engine."""
from datetime import datetime, timezone

import pytest

from server.scoring.risk_engine import RiskEngine
from shared.schema import NormalizedEvent


@pytest.mark.asyncio
async def test_bt_scan_scores(db_session):
    engine = RiskEngine(threshold=9999)
    ev = NormalizedEvent(
        agent_id="a1",
        actor="u",
        device_id="aa:bb:cc:dd:ee:ff",
        action="scan",
        source_type="bluetooth",
    )
    score, alert = await engine.score_event(ev, db_session)
    assert score >= 15  # bluetooth_scan rule
    assert alert is None  # threshold too high


@pytest.mark.asyncio
async def test_off_hours_scores(db_session):
    engine = RiskEngine(threshold=9999)
    ev = NormalizedEvent(
        agent_id="a2",
        actor="u",
        device_id="0001:0001",
        action="connect",
        source_type="usb",
        # 2am = off-hours
        timestamp=datetime(2024, 1, 1, 2, 0, 0, tzinfo=timezone.utc),
    )
    score, alert = await engine.score_event(ev, db_session)
    assert score >= 20  # off_hours rule


@pytest.mark.asyncio
async def test_mass_storage_scores(db_session):
    engine = RiskEngine(threshold=9999)
    ev = NormalizedEvent(
        agent_id="a3",
        actor="u",
        device_id="0781:5567",  # SanDisk mass storage
        action="connect",
        source_type="usb",
    )
    score, alert = await engine.score_event(ev, db_session)
    assert score >= 30  # mass_storage rule


@pytest.mark.asyncio
async def test_new_device_scores(db_session):
    engine = RiskEngine(threshold=9999)
    ev = NormalizedEvent(
        agent_id="new-agent",
        actor="u",
        device_id="ffff:ffff",
        action="connect",
        source_type="usb",
    )
    score, _ = await engine.score_event(ev, db_session)
    assert score >= 25  # new_device rule


@pytest.mark.asyncio
async def test_alert_fires_on_threshold(db_session):
    engine = RiskEngine(threshold=10.0)
    ev = NormalizedEvent(
        agent_id="thresh-agent",
        actor="u",
        device_id="0781:5567",
        action="connect",
        source_type="usb",
    )
    score, alert = await engine.score_event(ev, db_session)
    assert alert is not None
    assert alert.agent_id == "thresh-agent"
    assert alert.score >= 10.0


@pytest.mark.asyncio
async def test_no_alert_below_threshold(db_session):
    engine = RiskEngine(threshold=9999.0)
    ev = NormalizedEvent(
        agent_id="safe-agent",
        actor="u",
        device_id="aa:bb:cc:dd:ee:ff",
        action="scan",
        source_type="bluetooth",
        timestamp=datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc),
    )
    score, alert = await engine.score_event(ev, db_session)
    assert alert is None
