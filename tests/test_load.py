"""
tests/test_load.py – Throughput benchmarks for the ITDN event ingestion pipeline.

Uses pytest-benchmark to measure the number of events the server can process
per second under two scenarios:

1. Single-event ingestion  – one call to db.insert_event / rules.evaluate per test.
2. Batch ingestion (100)   – measures the /api/v1/events endpoint with a 100-event
                             payload to expose HTTP overhead and per-batch costs.

Run with:
    python -m pytest tests/test_load.py -v --benchmark-sort=mean

To generate a JSON report:
    python -m pytest tests/test_load.py --benchmark-json=benchmark.json
"""

from __future__ import annotations

import json
import importlib

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(**kwargs):
    defaults = {
        "event_type": "connected",
        "device_id": "cafe:1234",
        "hostname": "bench-host",
        "serial": "BEN001",
        "manufacturer": "Bench Corp",
        "product": "BenchDrive",
        "timestamp": "2024-06-15T10:00:00Z",
        "transfer_bytes": 0,
    }
    defaults.update(kwargs)
    return defaults


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def bench_db(tmp_path_factory, monkeypatch_module):
    """Module-scoped isolated SQLite database for benchmark tests."""
    db_path = tmp_path_factory.mktemp("bench") / "bench.db"
    monkeypatch_module.setenv("ITDN_DB_PATH", str(db_path))
    monkeypatch_module.setenv("SPLUNK_HEC_TOKEN", "")
    monkeypatch_module.setenv("ITDN_API_KEY", "")

    import server.config as cfg
    importlib.reload(cfg)
    import server.database as database
    importlib.reload(database)
    database.init_db()
    return database


@pytest.fixture(scope="module")
def bench_client(tmp_path_factory, monkeypatch_module):
    """Module-scoped Flask test client for HTTP-level benchmarks."""
    db_path = tmp_path_factory.mktemp("bench_http") / "bench.db"
    monkeypatch_module.setenv("ITDN_DB_PATH", str(db_path))
    monkeypatch_module.setenv("SPLUNK_HEC_TOKEN", "")
    monkeypatch_module.setenv("ITDN_API_KEY", "")

    import server.config as cfg
    importlib.reload(cfg)
    import server.database as database
    importlib.reload(database)
    import server.app as app_mod
    importlib.reload(app_mod)

    _app = app_mod.create_app()
    _app.config["TESTING"] = True
    with _app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# pytest does not have a built-in module-scoped monkeypatch; provide one.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def monkeypatch_module():
    """Module-scoped monkeypatch."""
    import _pytest.monkeypatch
    mp = _pytest.monkeypatch.MonkeyPatch()
    yield mp
    mp.undo()


# ---------------------------------------------------------------------------
# Benchmark: raw DB insert (no HTTP)
# ---------------------------------------------------------------------------

@pytest.mark.benchmark(group="db-insert")
def test_single_event_db_insert(benchmark, bench_db):
    """Measure raw DB event insertion throughput (no rules, no HTTP)."""
    event = _make_event()
    benchmark(bench_db.insert_event, event)


# ---------------------------------------------------------------------------
# Benchmark: rules evaluation
# ---------------------------------------------------------------------------

@pytest.mark.benchmark(group="rules")
def test_rules_evaluate(benchmark, bench_db):
    """Measure rules engine evaluation throughput."""
    import importlib
    import server.detection.rules as rules_mod
    importlib.reload(rules_mod)

    event = _make_event()
    benchmark(rules_mod.evaluate, event, bench_db)


# ---------------------------------------------------------------------------
# Benchmark: HTTP endpoint – single event
# ---------------------------------------------------------------------------

@pytest.mark.benchmark(group="http")
def test_http_single_event(benchmark, bench_client):
    """Measure HTTP throughput for a single-event POST to /api/v1/events."""
    payload = json.dumps({"events": [_make_event()]}).encode()

    def _post():
        resp = bench_client.post(
            "/api/v1/events",
            data=payload,
            content_type="application/json",
        )
        assert resp.status_code == 200

    benchmark(_post)


# ---------------------------------------------------------------------------
# Benchmark: HTTP endpoint – batch of 100 events
# ---------------------------------------------------------------------------

@pytest.mark.benchmark(group="http-batch")
def test_http_batch_100_events(benchmark, bench_client):
    """Measure HTTP throughput for a 100-event POST to /api/v1/events."""
    events = [_make_event(device_id=f"dead:{i:04x}") for i in range(100)]
    payload = json.dumps({"events": events}).encode()

    def _post():
        resp = bench_client.post(
            "/api/v1/events",
            data=payload,
            content_type="application/json",
        )
        assert resp.status_code == 200

    benchmark(_post)
