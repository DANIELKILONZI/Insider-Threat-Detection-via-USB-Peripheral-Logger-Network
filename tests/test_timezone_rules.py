"""
tests/test_timezone_rules.py – Tests for timezone-aware after-hours rule.
"""

from __future__ import annotations

import importlib

import pytest


# ---------------------------------------------------------------------------
# Mock DB helpers
# ---------------------------------------------------------------------------

class _MockDB:
    def __init__(self, tz_offset=None):
        self._tz = tz_offset

    def get_host_timezone(self, hostname):
        return self._tz

    def device_is_new(self, h, d): return False
    def get_recent_events(self, h, **kw): return []
    def get_recent_events_by_device(self, d, **kw): return []
    def user_device_is_new(self, u, h, d): return False


def _make_event(ts, hostname="ws-tz"):
    return {
        "event_type": "connected",
        "device_id": "cafe:1234",
        "hostname": hostname,
        "timestamp": ts,
        "transfer_bytes": 0,
    }


def _get_rules():
    import server.rules as rules_mod
    importlib.reload(rules_mod)
    return rules_mod


# ---------------------------------------------------------------------------
# After-hours detection without timezone offset (UTC baseline)
# ---------------------------------------------------------------------------

def test_after_hours_no_offset_utc_23h_fires():
    rules_mod = _get_rules()
    event = _make_event("2024-06-15T23:00:00Z")
    alert = rules_mod.rule_after_hours_device(event, _MockDB(tz_offset=None))
    assert alert is not None
    assert alert.rule_name == "after_hours_device"


def test_after_hours_no_offset_utc_10h_no_fire():
    rules_mod = _get_rules()
    event = _make_event("2024-06-15T10:00:00Z")
    alert = rules_mod.rule_after_hours_device(event, _MockDB(tz_offset=None))
    assert alert is None


# ---------------------------------------------------------------------------
# Timezone-aware: event at UTC 23:00 but host is UTC+2 → local time 01:00
# (still after-hours, so the alert should STILL fire)
# ---------------------------------------------------------------------------

def test_after_hours_with_offset_still_fires():
    rules_mod = _get_rules()
    event = _make_event("2024-06-15T23:00:00Z")
    # UTC+2 → local 01:00, which is still after-hours (before 06:00)
    alert = rules_mod.rule_after_hours_device(event, _MockDB(tz_offset=2.0))
    assert alert is not None


# ---------------------------------------------------------------------------
# Timezone-aware: event at UTC 22:30 but host is UTC+1 → local time 23:30
# (after-hours – should fire)
# ---------------------------------------------------------------------------

def test_after_hours_utc_offset_positive_fires():
    rules_mod = _get_rules()
    event = _make_event("2024-06-15T22:30:00Z")
    alert = rules_mod.rule_after_hours_device(event, _MockDB(tz_offset=1.0))
    assert alert is not None


# ---------------------------------------------------------------------------
# Timezone-aware: event at UTC 07:00, host UTC-9 → local time 22:00
# (UTC 07:00 is business hours, but local 22:00 is after-hours → should fire)
# ---------------------------------------------------------------------------

def test_after_hours_utc_offset_negative_fires():
    rules_mod = _get_rules()
    event = _make_event("2024-06-15T07:00:00Z")
    alert = rules_mod.rule_after_hours_device(event, _MockDB(tz_offset=-9.0))
    assert alert is not None


# ---------------------------------------------------------------------------
# Timezone-aware: event at UTC 21:00, host UTC+3 → local 00:00 midnight
# (local midnight is still after-hours because hour=0 < end=6)
# ---------------------------------------------------------------------------

def test_after_hours_midnight_local_fires():
    rules_mod = _get_rules()
    event = _make_event("2024-06-15T21:00:00Z")
    alert = rules_mod.rule_after_hours_device(event, _MockDB(tz_offset=3.0))
    assert alert is not None


# ---------------------------------------------------------------------------
# Timezone DB persistence
# ---------------------------------------------------------------------------

def test_update_and_get_host_timezone(full_client):
    import server.database as database
    database.update_host_timezone("tz-host", 5.5)
    offset = database.get_host_timezone("tz-host")
    assert offset == 5.5


def test_update_host_timezone_updates_existing(full_client):
    import server.database as database
    database.update_host_timezone("tz-host2", 0.0)
    database.update_host_timezone("tz-host2", -5.0)
    offset = database.get_host_timezone("tz-host2")
    assert offset == -5.0


def test_get_host_timezone_unknown_returns_none(full_client):
    import server.database as database
    offset = database.get_host_timezone("no-such-host-tz")
    assert offset is None
