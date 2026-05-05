"""Tests for the anchor endpoint."""
import pytest

from server.models import Anchor


@pytest.mark.asyncio
async def test_anchor_stored(db_session):
    from server.routers.anchor import AnchorRequest, create_anchor

    req = AnchorRequest(
        agent_id="agent-1",
        chain_head_hash="a" * 64,
        timestamp="2024-01-01T00:00:00+00:00",
    )
    result = await create_anchor(req, db_session)
    assert "anchor_id" in result
    assert "signature" in result
    assert len(result["signature"]) > 10


@pytest.mark.asyncio
async def test_anchor_get_latest(db_session):
    from server.routers.anchor import AnchorRequest, create_anchor, get_anchor

    req = AnchorRequest(
        agent_id="agent-anchor-test",
        chain_head_hash="b" * 64,
        timestamp="2024-06-01T00:00:00+00:00",
    )
    await create_anchor(req, db_session)
    result = await get_anchor("agent-anchor-test", db_session)
    assert result["chain_head_hash"] == "b" * 64
    assert result["agent_id"] == "agent-anchor-test"


@pytest.mark.asyncio
async def test_anchor_not_found_raises(db_session):
    from fastapi import HTTPException

    from server.routers.anchor import get_anchor

    with pytest.raises(HTTPException) as exc_info:
        await get_anchor("no-such-agent", db_session)
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_anchor_signature_is_base64(db_session):
    import base64

    from server.routers.anchor import AnchorRequest, create_anchor

    req = AnchorRequest(
        agent_id="agent-b64",
        chain_head_hash="c" * 64,
        timestamp="2024-01-01T00:00:00+00:00",
    )
    result = await create_anchor(req, db_session)
    # Should be valid base64
    decoded = base64.b64decode(result["signature"])
    assert len(decoded) > 0
