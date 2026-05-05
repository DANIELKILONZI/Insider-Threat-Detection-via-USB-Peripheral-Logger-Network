import os
import sys
import pathlib
from logging.config import fileConfig

from sqlalchemy import create_engine, pool
from sqlalchemy.orm import declarative_base

from alembic import context

# ---------------------------------------------------------------------------
# Alembic config
# ---------------------------------------------------------------------------
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ---------------------------------------------------------------------------
# Resolve DB URL (sync driver, no async prefix)
# ---------------------------------------------------------------------------
_db_url = os.environ.get("SERVER_DATABASE_URL", config.get_main_option("sqlalchemy.url"))
_db_url = _db_url.replace("postgresql+asyncpg://", "postgresql://")
_db_url = _db_url.replace("sqlite+aiosqlite://", "sqlite://")
config.set_main_option("sqlalchemy.url", _db_url)

# ---------------------------------------------------------------------------
# Import ORM models without triggering the async engine in server/database.py
# ---------------------------------------------------------------------------
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

# Create a standalone sync-only Base that we inject as server.database.Base
# before any model imports happen. This avoids creating the async engine.
_Base = declarative_base()

# Stub out the parts of server.database that models actually use
import types  # noqa: E402

_fake_db = types.ModuleType("server.database")
_fake_db.Base = _Base  # type: ignore[attr-defined]
sys.modules["server.database"] = _fake_db

# Now it's safe to import models — they will map to _Base.metadata
import server.models  # noqa: E402, F401

target_metadata = _Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    connectable = create_engine(
        config.get_main_option("sqlalchemy.url"),
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
