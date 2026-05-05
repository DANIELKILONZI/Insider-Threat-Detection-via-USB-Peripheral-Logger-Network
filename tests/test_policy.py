"""Tests for the device allowlist policy endpoints and risk engine integration."""
import pytest

from server.routers.policy import add_allowlist_entry, list_allowlist, remove_allowlist_entry
from server.routers.policy import AllowlistEntry


# ---------------------------------------------------------------------------
# Policy router tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_add_and_list_allowlist_entry(db_session):
    entry = AllowlistEntry(agent_id="agent-1", device_id="0781:5567", note="IT approved")
    result = await add_allowlist_entry(entry, db=db_session)
    assert result["device_id"] == "0781:5567"
    assert result["agent_id"] == "agent-1"

    rows = await list_allowlist(db=db_session)
    assert any(r["device_id"] == "0781:5567" for r in rows)


@pytest.mark.asyncio
async def test_list_allowlist_filtered_by_agent(db_session):
    e1 = AllowlistEntry(agent_id="agentX", device_id="aaaa:1111")
    e2 = AllowlistEntry(agent_id="agentY", device_id="bbbb:2222")
    await add_allowlist_entry(e1, db=db_session)
    await add_allowlist_entry(e2, db=db_session)

    rows = await list_allowlist(agent_id="agentX", db=db_session)
    device_ids = {r["device_id"] for r in rows}
    assert "aaaa:1111" in device_ids
    # agentY's device should NOT appear
    assert "bbbb:2222" not in device_ids


@pytest.mark.asyncio
async def test_orgwide_allowlist_returned_for_all_agents(db_session):
    org_entry = AllowlistEntry(agent_id="*", device_id="cccc:3333", note="org-wide")
    await add_allowlist_entry(org_entry, db=db_session)

    rows = await list_allowlist(agent_id="anyAgent", db=db_session)
    assert any(r["device_id"] == "cccc:3333" for r in rows)


@pytest.mark.asyncio
async def test_remove_allowlist_entry(db_session):
    entry = AllowlistEntry(agent_id="agent-del", device_id="dddd:4444")
    result = await add_allowlist_entry(entry, db=db_session)
    entry_id = result["id"]

    await remove_allowlist_entry(entry_id, db=db_session)
    rows = await list_allowlist(db=db_session)
    assert not any(r["device_id"] == "dddd:4444" for r in rows)


@pytest.mark.asyncio
async def test_remove_nonexistent_returns_404(db_session):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        await remove_allowlist_entry(99999, db=db_session)
    assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# Risk engine integration: allowlisted device skips unknown/new rules
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_allowlisted_device_skips_unknown_device_rules(db_session, sample_event):
    from server.scoring.risk_engine import RiskEngine
    from server.routers.policy import AllowlistEntry, add_allowlist_entry

    device_id = "0781:5567"
    # Allowlist the device for all agents
    await add_allowlist_entry(AllowlistEntry(agent_id="*", device_id=device_id), db=db_session)

    engine = RiskEngine(threshold=1000)  # high threshold so no alert fires
    event = sample_event(device_id=device_id)
    score, alert = await engine.score_event(event, db_session)

    # unknown_device (+40) and new_device (+25) should NOT be in score
    assert score < 65, f"Expected allowlisted device to skip unknown/new rules, got score={score}"


@pytest.mark.asyncio
async def test_non_allowlisted_device_still_scores(db_session, sample_event):
    from server.scoring.risk_engine import RiskEngine

    engine = RiskEngine(threshold=1000)
    event = sample_event(device_id="9999:9999")
    score, alert = await engine.score_event(event, db_session)
    # unknown_device (40) + new_device (25) = 65 minimum
    assert score >= 65
