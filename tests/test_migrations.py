"""
tests/test_migrations.py – Guards that the Alembic migration history and the
SQLAlchemy Core metadata in ``server.database`` never drift apart.

ITDN can provision its database two ways: ``init_db()`` (``metadata.create_all``,
used by tests and single-server installs) and ``alembic upgrade head`` (used by
managed deployments).  If those two produce different schemas, a bug reproduces
on one deployment style and not the other.  These tests fail the moment someone
adds a table or index to ``server.database`` without a matching migration.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest
import sqlalchemy as sa

alembic_command = pytest.importorskip("alembic.command")
from alembic.autogenerate import compare_metadata  # noqa: E402
from alembic.config import Config  # noqa: E402
from alembic.migration import MigrationContext  # noqa: E402
from alembic.script import ScriptDirectory  # noqa: E402

from server.database import metadata  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
ALEMBIC_INI = REPO_ROOT / "alembic.ini"


def _config_for(url: str) -> Config:
    """Alembic config pinned to ``url`` via the same -x hook the CLI uses."""
    cfg = Config(str(ALEMBIC_INI))
    cfg.cmd_opts = argparse.Namespace(x=[f"db_url={url}"])
    return cfg


def _schema_of(url: str) -> dict[str, str]:
    """Map every table/index name to its normalised CREATE statement."""
    engine = sa.create_engine(url)
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                sa.text(
                    "SELECT name, sql FROM sqlite_master "
                    "WHERE name NOT LIKE 'sqlite_%' AND name != 'alembic_version'"
                )
            ).fetchall()
    finally:
        engine.dispose()
    return {name: " ".join((sql or "").split()) for name, sql in rows}


def test_migration_matches_create_all(tmp_path):
    """`alembic upgrade head` and `metadata.create_all` yield the same schema."""
    migrated_url = f"sqlite:///{tmp_path / 'migrated.db'}"
    created_url = f"sqlite:///{tmp_path / 'created.db'}"

    alembic_command.upgrade(_config_for(migrated_url), "head")

    engine = sa.create_engine(created_url)
    try:
        metadata.create_all(engine)
    finally:
        engine.dispose()

    assert _schema_of(migrated_url) == _schema_of(created_url)


def test_no_pending_model_changes(tmp_path):
    """A migrated database is already in sync with the metadata — no drift."""
    url = f"sqlite:///{tmp_path / 'migrated.db'}"
    alembic_command.upgrade(_config_for(url), "head")

    engine = sa.create_engine(url)
    try:
        with engine.connect() as conn:
            diff = compare_metadata(MigrationContext.configure(conn), metadata)
    finally:
        engine.dispose()

    assert diff == [], f"Uncommitted schema changes need a migration: {diff}"


def test_downgrade_to_base_is_clean(tmp_path):
    """Every migration's downgrade() reverses its upgrade()."""
    url = f"sqlite:///{tmp_path / 'roundtrip.db'}"
    cfg = _config_for(url)

    alembic_command.upgrade(cfg, "head")
    assert _schema_of(url), "upgrade produced no tables"

    alembic_command.downgrade(cfg, "base")
    assert _schema_of(url) == {}, "downgrade left tables behind"


def test_single_head_revision():
    """The history has exactly one head — catches un-merged migration branches."""
    heads = ScriptDirectory.from_config(Config(str(ALEMBIC_INI))).get_heads()
    assert len(heads) == 1, f"expected a single head, found {heads}"


def test_init_db_stamps_head(tmp_path, monkeypatch):
    """A create_all-provisioned DB is stamped, so `upgrade head` is a no-op on it."""
    import importlib

    monkeypatch.setenv("ITDN_DB_PATH", str(tmp_path / "stamped.db"))
    monkeypatch.setenv("ITDN_DATABASE_URL", "")

    import server.config as cfg_mod
    importlib.reload(cfg_mod)
    import server.database as db_mod
    importlib.reload(db_mod)

    db_mod.init_db()

    expected_head = ScriptDirectory.from_config(
        Config(str(ALEMBIC_INI))
    ).get_current_head()

    engine = sa.create_engine(f"sqlite:///{tmp_path / 'stamped.db'}")
    try:
        with engine.connect() as conn:
            current = MigrationContext.configure(conn).get_current_revision()
    finally:
        engine.dispose()

    assert current == expected_head

    # Leave the module set back to the ambient test configuration.
    importlib.reload(cfg_mod)
    importlib.reload(db_mod)
