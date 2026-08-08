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
import os

import pytest

# Anchoring fails closed when the server holds no signing key, so the suite
# supplies a real one.  Tests therefore exercise the genuine HMAC signing and
# verification path rather than the ITDN_ALLOW_UNSIGNED_ANCHORS dev fallback;
# tests/test_anchor_signing.py covers the refusal and dev-mode branches
# explicitly.  Set at import time so it is present before any module reload.
os.environ.setdefault("ITDN_ANCHOR_KEY", "test-anchor-signing-key-not-a-real-secret")


@pytest.fixture(autouse=True)
def reset_rule_config():
    """Reset rule_config thresholds to defaults before and after every test."""
    import server.detection.rule_config as rc
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

    import server.detection.rule_config as rc
    importlib.reload(rc)

    import server.detection.rules as rules_mod
    importlib.reload(rules_mod)

    import server.auth as auth_mod
    importlib.reload(auth_mod)

    import server.app as app_mod
    importlib.reload(app_mod)

    _app = app_mod.create_app()
    _app.config["TESTING"] = True
    with _app.test_client() as c:
        yield c
