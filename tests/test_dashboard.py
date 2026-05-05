"""Tests for dashboard summary endpoint and WebSocket manager."""
import pytest
from httpx import AsyncClient, ASGITransport

from server.main import app


@pytest.mark.asyncio
async def test_dashboard_summary_empty(db_session):
    from server.routers.dashboard import dashboard_summary

    summary = await dashboard_summary(db=db_session)
    assert summary["total_events"] == 0
    assert summary["total_alerts"] == 0
    assert summary["active_agents_24h"] == 0
    assert isinstance(summary["top_risky_devices"], list)
    assert isinstance(summary["recent_alerts"], list)


@pytest.mark.asyncio
async def test_dashboard_summary_with_data(db_session, sample_event):
    from server.routers.dashboard import dashboard_summary
    from server.models import Event, Alert

    ev = sample_event(agent_id="dash-agent")
    row = Event(
        event_id=ev.event_id,
        agent_id=ev.agent_id,
        actor=ev.actor,
        device_id=ev.device_id,
        action=ev.action,
        source_type=ev.source_type,
        confidence=ev.confidence,
        raw_json="{}",
        event_hash=ev.event_hash,
        prev_hash=ev.prev_hash,
        timestamp=ev.timestamp,
    )
    db_session.add(row)
    db_session.add(Alert(
        agent_id=ev.agent_id,
        rule="test",
        score=90.0,
        device_id=ev.device_id,
        timestamp=ev.timestamp,
        details_json="{}",
    ))
    await db_session.commit()

    summary = await dashboard_summary(db=db_session)
    assert summary["total_events"] == 1
    assert summary["total_alerts"] == 1
    assert len(summary["top_risky_devices"]) == 1


@pytest.mark.asyncio
async def test_ws_manager_broadcast():
    from server.routers.dashboard import _ConnectionManager

    mgr = _ConnectionManager()
    # No connections — broadcast should not raise
    await mgr.broadcast({"type": "alert", "rule": "test"})
    assert len(mgr._connections) == 0
