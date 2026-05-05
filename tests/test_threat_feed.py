"""
tests/test_threat_feed.py – Tests for the USB VID:PID threat feed.
"""

from __future__ import annotations

import os
import tempfile

import pytest


def _reset_feed():
    """Reset the threat feed module state between tests."""
    import importlib
    import server.threat_feed as tf
    tf._known_malicious = set()
    tf._loaded = False


# ---------------------------------------------------------------------------
# Basic lookup
# ---------------------------------------------------------------------------

def test_empty_feed_not_malicious():
    _reset_feed()
    import server.threat_feed as tf
    # No feed configured → nothing is malicious
    assert tf.is_known_malicious("0781:5567") is False


def test_add_entry_makes_malicious():
    _reset_feed()
    import server.threat_feed as tf
    tf.add_entry("0781:5567")
    assert tf.is_known_malicious("0781:5567") is True


def test_case_normalisation():
    _reset_feed()
    import server.threat_feed as tf
    tf.add_entry("DEAD:BEEF")
    assert tf.is_known_malicious("dead:beef") is True
    assert tf.is_known_malicious("DEAD:BEEF") is True


def test_unknown_device_not_malicious():
    _reset_feed()
    import server.threat_feed as tf
    tf.add_entry("0781:5567")
    assert tf.is_known_malicious("9999:0001") is False


# ---------------------------------------------------------------------------
# Local file loading
# ---------------------------------------------------------------------------

def test_load_local_file(monkeypatch, tmp_path):
    feed_file = tmp_path / "feed.txt"
    feed_file.write_text("# comment\n0781:5567\nDEAD:BEEF\n\n")

    monkeypatch.setattr("server.threat_feed.THREAT_FEED_PATH", str(feed_file))
    monkeypatch.setattr("server.threat_feed.THREAT_FEED_URL", "")

    _reset_feed()
    import server.threat_feed as tf
    count = tf.reload()
    assert count == 2
    assert tf.is_known_malicious("0781:5567") is True
    assert tf.is_known_malicious("dead:beef") is True


def test_local_file_comments_stripped(monkeypatch, tmp_path):
    feed_file = tmp_path / "feed.txt"
    feed_file.write_text("# BadUSB list\n# header\naaaa:bbbb\n")
    monkeypatch.setattr("server.threat_feed.THREAT_FEED_PATH", str(feed_file))
    monkeypatch.setattr("server.threat_feed.THREAT_FEED_URL", "")

    _reset_feed()
    import server.threat_feed as tf
    tf.reload()
    assert tf.is_known_malicious("aaaa:bbbb") is True


def test_missing_file_does_not_crash(monkeypatch):
    monkeypatch.setattr("server.threat_feed.THREAT_FEED_PATH", "/nonexistent/path/feed.txt")
    monkeypatch.setattr("server.threat_feed.THREAT_FEED_URL", "")

    _reset_feed()
    import server.threat_feed as tf
    count = tf.reload()
    assert count == 0


# ---------------------------------------------------------------------------
# Rule integration
# ---------------------------------------------------------------------------

def test_rule_known_malicious_device_fires():
    import importlib
    import server.rules as rules_mod
    importlib.reload(rules_mod)
    import server.threat_feed as tf

    _reset_feed()
    tf.add_entry("dead:c0de")

    class _MockDB:
        def get_host_timezone(self, h): return None
        def device_is_new(self, h, d): return False
        def get_recent_events(self, h, **kw): return []
        def get_recent_events_by_device(self, d, **kw): return []

    event = {
        "event_type": "connected",
        "device_id": "dead:c0de",
        "hostname": "ws-threat",
        "timestamp": "2024-06-15T10:00:00Z",
        "transfer_bytes": 0,
    }
    alerts = rules_mod.evaluate(event, _MockDB())
    rule_names = [a.rule_name for a in alerts]
    assert "known_malicious_device" in rule_names
    critical = [a for a in alerts if a.rule_name == "known_malicious_device"]
    assert critical[0].severity == "CRITICAL"


def test_rule_known_malicious_device_does_not_fire_for_clean_device():
    import importlib
    import server.rules as rules_mod
    importlib.reload(rules_mod)
    import server.threat_feed as tf

    _reset_feed()
    tf.add_entry("dead:c0de")

    class _MockDB:
        def get_host_timezone(self, h): return None
        def device_is_new(self, h, d): return False
        def get_recent_events(self, h, **kw): return []
        def get_recent_events_by_device(self, d, **kw): return []

    event = {
        "event_type": "connected",
        "device_id": "cafe:1234",
        "hostname": "ws-clean",
        "timestamp": "2024-06-15T10:00:00Z",
        "transfer_bytes": 0,
    }
    alerts = rules_mod.evaluate(event, _MockDB())
    assert not any(a.rule_name == "known_malicious_device" for a in alerts)
