"""Shared test fixtures."""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

# Use in-memory SQLite for tests
os.environ.setdefault("SERVER_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from server.database import Base
from shared.schema import NormalizedEvent

TEST_AGENT_ID = "test-agent-001"


# ------------------------------------------------------------------ DB session
@pytest_asyncio.fixture
async def db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


# ------------------------------------------------------------------ Sample event
@pytest.fixture
def sample_event():
    def _make(
        agent_id: str = TEST_AGENT_ID,
        device_id: str = "0781:5567",
        action: str = "connect",
        source_type: str = "usb",
        actor: str = "testuser",
        confidence: float = 1.0,
        timestamp: datetime | None = None,
    ) -> NormalizedEvent:
        return NormalizedEvent(
            agent_id=agent_id,
            actor=actor,
            device_id=device_id,
            action=action,
            source_type=source_type,
            confidence=confidence,
            timestamp=timestamp or datetime.now(timezone.utc),
        )

    return _make


# ------------------------------------------------------------------ CA fixture
@pytest.fixture
def ca(tmp_path):
    from server.ca.cert_authority import CertificateAuthority

    ca_cert = str(tmp_path / "ca.crt")
    ca_key = str(tmp_path / "ca.key")
    return CertificateAuthority(ca_cert_path=ca_cert, ca_key_path=ca_key)
