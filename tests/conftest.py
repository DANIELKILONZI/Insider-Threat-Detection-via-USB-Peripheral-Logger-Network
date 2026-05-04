"""
tests/conftest.py – Shared pytest fixtures.

Provides:
  ``full_client``           – Flask test client with isolated SQLite DB and all
                              server modules reloaded.
  ``reset_rule_config``     – autouse fixture that resets runtime thresholds to
                              defaults before and after every test, preventing
                              state leakage from config-patching tests.
"""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture(autouse=True)
def reset_rule_config():
    """Reset rule_config thresholds to defaults before and after every test."""
    import server.rule_config as rc
    rc.reset_to_defaults()
    yield
    rc.reset_to_defaults()


@pytest.fixture()
def full_client(tmp_path, monkeypatch):
    """
    Flask test client with a per-test SQLite database and all server
    modules reloaded so env-var changes are picked up cleanly.
    """
    monkeypatch.setenv("ITDN_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("SPLUNK_HEC_TOKEN", "")  # disable Splunk forwarding
    monkeypatch.setenv("ITDN_API_KEY", "")       # disable auth by default

    import server.config as cfg
    importlib.reload(cfg)

    import server.database as database
    importlib.reload(database)

    import server.rule_config as rc
    importlib.reload(rc)

    import server.rules as rules_mod
    importlib.reload(rules_mod)

    import server.auth as auth_mod
    importlib.reload(auth_mod)

    import server.app as app_mod
    importlib.reload(app_mod)

    _app = app_mod.create_app()
    _app.config["TESTING"] = True
    with _app.test_client() as c:
        yield c
