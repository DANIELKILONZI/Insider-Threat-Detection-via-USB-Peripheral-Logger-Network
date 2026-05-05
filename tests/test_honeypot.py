"""Tests for honeypot device profiles."""
from datetime import datetime, timezone

import pytest

from server.honeypot.profiles import DEFAULT_PROFILES, HoneypotManager
from server.models import HoneypotProfile


@pytest.mark.asyncio
async def test_seed_defaults(db_session):
    mgr = HoneypotManager()
    await mgr.seed_defaults(db_session)
    await db_session.flush()

    for p in DEFAULT_PROFILES:
        assert await mgr.is_honeypot_device(f"{p['vid']}:{p['pid']}", db_session)


@pytest.mark.asyncio
async def test_not_honeypot_device(db_session):
    mgr = HoneypotManager()
    assert not await mgr.is_honeypot_device("1234:5678", db_session)


@pytest.mark.asyncio
async def test_add_custom_profile(db_session):
    mgr = HoneypotManager()
    await mgr.add_profile("aabb", "ccdd", "Custom Bait", db_session)
    assert await mgr.is_honeypot_device("aabb:ccdd", db_session)


@pytest.mark.asyncio
async def test_check_returns_alert_for_honeypot(db_session):
    mgr = HoneypotManager()
    await mgr.add_profile("dead", "beef", "Bait", db_session)
    alert = await mgr.check("dead:beef", "agent-h", db_session)
    assert alert is not None
    assert alert.rule == "honeypot_match"
    assert alert.score == 100.0
    assert alert.agent_id == "agent-h"


@pytest.mark.asyncio
async def test_check_returns_none_for_normal(db_session):
    mgr = HoneypotManager()
    alert = await mgr.check("ffff:0001", "agent-n", db_session)
    assert alert is None


@pytest.mark.asyncio
async def test_inactive_profile_not_matched(db_session):
    mgr = HoneypotManager()
    db_session.add(HoneypotProfile(vid="1111", pid="2222", name="Inactive", active=False))
    await db_session.flush()
    assert not await mgr.is_honeypot_device("1111:2222", db_session)
