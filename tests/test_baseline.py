"""Tests for baseline profiler."""
from datetime import datetime, timezone

import pytest

from server.scoring.baseline import BaselineProfiler
from shared.schema import NormalizedEvent


@pytest.mark.asyncio
async def test_record_and_is_known(db_session):
    bp = BaselineProfiler()
    ts = datetime.now(timezone.utc)
    # First record — not known yet
    await bp.record_device("agent-1", "1234:abcd", ts, db_session)
    assert not await bp.is_known_device("agent-1", "1234:abcd", db_session)

    # Second record — now known
    await bp.record_device("agent-1", "1234:abcd", ts, db_session)
    assert await bp.is_known_device("agent-1", "1234:abcd", db_session)


@pytest.mark.asyncio
async def test_unknown_device(db_session):
    bp = BaselineProfiler()
    assert not await bp.is_known_device("agent-x", "ffff:ffff", db_session)


@pytest.mark.asyncio
async def test_get_profile(db_session):
    bp = BaselineProfiler()
    ts = datetime.now(timezone.utc)
    await bp.record_device("prof-agent", "1111:2222", ts, db_session)
    await bp.record_device("prof-agent", "3333:4444", ts, db_session)
    profile = await bp.get_profile("prof-agent", db_session)
    assert profile["agent_id"] == "prof-agent"
    assert profile["device_count"] == 2
    assert len(profile["devices"]) == 2


def test_off_hours():
    bp = BaselineProfiler(off_hours_start=18, off_hours_end=8)
    # 2am — off-hours
    ts_night = datetime(2024, 1, 1, 2, 0, 0, tzinfo=timezone.utc)
    assert bp.is_off_hours(ts_night)

    # 10am — working hours
    ts_day = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    assert not bp.is_off_hours(ts_day)

    # 7pm — off-hours
    ts_eve = datetime(2024, 1, 1, 19, 0, 0, tzinfo=timezone.utc)
    assert bp.is_off_hours(ts_eve)


@pytest.mark.asyncio
async def test_seen_count_increments(db_session):
    bp = BaselineProfiler()
    ts = datetime.now(timezone.utc)
    for _ in range(4):
        await bp.record_device("cnt-agent", "aaaa:bbbb", ts, db_session)
    from sqlalchemy import select
    from server.models import BaselineDevice

    result = await db_session.execute(
        select(BaselineDevice).where(
            BaselineDevice.agent_id == "cnt-agent",
            BaselineDevice.device_id == "aaaa:bbbb",
        )
    )
    row = result.scalars().first()
    assert row.seen_count == 4
