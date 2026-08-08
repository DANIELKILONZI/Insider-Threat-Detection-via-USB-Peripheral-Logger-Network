"""Alembic migration environment for ITDN.

The schema is defined with SQLAlchemy **Core** in :mod:`server.database`
(the module-level ``metadata`` object), so ``target_metadata`` points straight
at it — there are no ORM models to import and no async engine to work around.

The database URL is resolved from :data:`server.config.DATABASE_URL`
(``ITDN_DATABASE_URL``, falling back to SQLite at ``ITDN_DB_PATH``) so that
migrations and the running server can never disagree about which database they
are talking to.  For a one-off run against a different database, pass::

    alembic -x db_url=postgresql+psycopg2://user:pw@host/itdn upgrade head
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from server.config import DATABASE_URL
from server.database import metadata

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# -x db_url=... wins, then the server's own configured URL.  The sqlalchemy.url
# key in alembic.ini is deliberately left empty and never used directly.
_db_url = context.get_x_argument(as_dictionary=True).get("db_url") or DATABASE_URL
config.set_main_option("sqlalchemy.url", _db_url)

target_metadata = metadata


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting (``alembic upgrade head --sql``)."""
    context.configure(
        url=_db_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live connection."""
    connectable = create_engine(_db_url, poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            # SQLite cannot ALTER most column properties in place; batch mode
            # rewrites the table instead.  No-op on PostgreSQL.
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
