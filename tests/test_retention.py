"""
tests/test_retention.py – Tests for the log retention / purge feature.
"""

from __future__ import annotations

import importlib
from datetime import datetime, timedelta, timezone

import pytest


def _old_ts(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# purge_old_records DB function
# ---------------------------------------------------------------------------

def test_purge_removes_old_events(full_client):
    import server.database as database

    event = {
        "event_type": "connected",
        "device_id": "cafe:1234",
        "hostname": "purge-host",
        "serial": "",
        "manufacturer": "",
        "product": "",
        "bus_path": "",
        "transfer_bytes": 0,
    }
    database.insert_event(event)

    # Manually back-date the event to simulate an old record
    import sqlalchemy as sa
    from sqlalchemy import text
    with database._lock:
        with database._get_engine().begin() as conn:
            conn.execute(
                text("UPDATE events SET received_at = :ts WHERE hostname = :h"),
                {"ts": _old_ts(100), "h": "purge-host"},
            )

    counts = database.purge_old_records(retention_days=90)
    assert counts["events"] >= 1


def test_purge_keeps_recent_events(full_client):
    import server.database as database

    event = {
        "event_type": "connected",
        "device_id": "new:device",
        "hostname": "keep-host",
        "serial": "",
        "manufacturer": "",
        "product": "",
        "bus_path": "",
        "transfer_bytes": 0,
    }
    database.insert_event(event)

    before = len(database.get_recent_events("keep-host", window_secs=86400 * 7))
    counts = database.purge_old_records(retention_days=90)
    after = len(database.get_recent_events("keep-host", window_secs=86400 * 7))
    assert after == before  # recent event untouched
    assert counts["events"] == 0  # nothing deleted


def test_purge_endpoint(full_client):
    import json
    resp = full_client.post(
        "/api/v1/maintenance/purge",
        data=json.dumps({"retention_days": 3650}),
        content_type="application/json",
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    assert "deleted" in body
    assert "events" in body["deleted"]
