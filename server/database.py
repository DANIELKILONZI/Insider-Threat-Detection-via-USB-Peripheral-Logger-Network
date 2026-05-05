"""SQLAlchemy async database setup.

Production: asyncpg (PostgreSQL)
Testing:    aiosqlite (SQLite)

DATABASE_URL examples:
  postgresql+asyncpg://user:pass@localhost/threatdb
  sqlite+aiosqlite:///./threatdb.db
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from server.config import config

Base = declarative_base()

_is_sqlite = config.database_url.startswith("sqlite")

if _is_sqlite:
    engine = create_async_engine(
        config.database_url,
        connect_args={"check_same_thread": False},
        echo=False,
    )
else:
    engine = create_async_engine(
        config.database_url,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=3600,
        echo=False,
    )

AsyncSessionLocal = sessionmaker(  # type: ignore[call-overload]
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db() -> None:
    """Create all tables."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    """FastAPI dependency — yields an AsyncSession."""
    async with AsyncSessionLocal() as session:
        yield session
