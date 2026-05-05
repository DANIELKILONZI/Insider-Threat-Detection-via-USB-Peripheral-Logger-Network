"""Tests for audit trail / compliance report endpoint."""
import pytest

from server.models import Alert, Event
from server.routers.reports import agent_report


# Helper to populate DB
async def _seed(db_session, sample_event):
    ev = sample_event(agent_id="report-agent", device_id="0781:5567")
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
    al = Alert(
        agent_id=ev.agent_id,
        rule="test_rule",
        score=90.0,
        device_id=ev.device_id,
        timestamp=ev.timestamp,
        details_json="{}",
    )
    db_session.add(al)
    await db_session.commit()
    return ev


@pytest.mark.asyncio
async def test_report_csv_returns_content(db_session, sample_event):
    await _seed(db_session, sample_event)

    response = await agent_report("report-agent", db=db_session)
    # StreamingResponse
    content = b""
    async for chunk in response.body_iterator:
        content += chunk.encode() if isinstance(chunk, str) else chunk

    assert b"report-agent" in content
    assert b"EVENTS" in content
    assert b"ALERTS" in content
    assert b"chain_integrity" in content


@pytest.mark.asyncio
async def test_report_json_format(db_session, sample_event):
    import json

    await _seed(db_session, sample_event)

    response = await agent_report("report-agent", fmt="json", db=db_session)
    body = response.body
    data = json.loads(body)
    assert data["meta"]["agent_id"] == "report-agent"
    assert len(data["events"]) >= 1
    assert len(data["alerts"]) >= 1


@pytest.mark.asyncio
async def test_report_empty_agent(db_session):
    response = await agent_report("no-such-agent", db=db_session)
    content = b""
    async for chunk in response.body_iterator:
        content += chunk.encode() if isinstance(chunk, str) else chunk
    assert b"event_count" in content or b"no-such-agent" in content


@pytest.mark.asyncio
async def test_report_invalid_since_raises(db_session):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        await agent_report("agent-x", since="not-a-date", db=db_session)
    assert exc_info.value.status_code == 422


@pytest.mark.asyncio
async def test_report_chain_integrity_ok(db_session, sample_event):
    """Chain integrity passes for an unmodified chain."""
    await _seed(db_session, sample_event)
    response = await agent_report("report-agent", fmt="json", db=db_session)
    import json

    data = json.loads(response.body)
    assert data["meta"]["chain_integrity"] == "OK"
