"""Tests for SecurityMiddleware (API-key + rate limiting)."""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

from server.middleware import SecurityMiddleware


def _make_app(api_key: str = "", rate_limit: int = 0, window: int = 60) -> FastAPI:
    app = FastAPI()
    app.add_middleware(
        SecurityMiddleware,
        api_key=api_key,
        rate_limit_requests=rate_limit,
        rate_limit_window=window,
    )

    @app.get("/protected")
    def protected():
        return {"ok": True}

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


# ---------------------------------------------------------------------------
# API-key tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_api_key_required_missing():
    app = _make_app(api_key="secret")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/protected")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_api_key_required_wrong():
    app = _make_app(api_key="secret")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/protected", headers={"X-API-Key": "wrong"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_api_key_correct():
    app = _make_app(api_key="secret")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/protected", headers={"X-API-Key": "secret"})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_health_skips_auth():
    app = _make_app(api_key="secret")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/health")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_no_api_key_required_when_empty():
    app = _make_app(api_key="")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get("/protected")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Rate limiting tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rate_limit_exceeded():
    app = _make_app(rate_limit=3, window=60)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        for _ in range(3):
            r = await c.get("/protected")
            assert r.status_code == 200
        # 4th request should be throttled
        r = await c.get("/protected")
    assert r.status_code == 429


@pytest.mark.asyncio
async def test_rate_limit_not_applied_to_health():
    app = _make_app(rate_limit=2, window=60)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        for _ in range(5):
            r = await c.get("/health")
    assert r.status_code == 200  # health is always public


@pytest.mark.asyncio
async def test_rate_limit_disabled_when_zero():
    app = _make_app(rate_limit=0, window=60)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        for _ in range(10):
            r = await c.get("/protected")
    assert r.status_code == 200
