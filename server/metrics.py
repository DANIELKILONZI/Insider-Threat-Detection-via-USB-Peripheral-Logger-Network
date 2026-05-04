"""
server/metrics.py – In-process Prometheus-style metrics counters.

Exposes simple thread-safe counters and a gauge that ``GET /metrics``
serialises as the Prometheus text exposition format (no external library
required).

Metrics exported
----------------
``itdn_events_ingested_total``   Counter – raw device events received.
``itdn_alerts_fired_total``      Counter – alerts that passed deduplication
                                  and were persisted (labelled by severity and
                                  rule_name).
``itdn_alerts_active``           Gauge   – unacknowledged alerts currently in
                                  the database (refreshed on each scrape via a
                                  callback).
``itdn_rule_fires_total``        Counter – rules that fired (labelled by
                                  rule_name), regardless of deduplication.

Usage
-----
Import the singletons and call the increment/observe helpers::

    from server.metrics import METRICS
    METRICS.inc_events_ingested()
    METRICS.inc_alerts_fired("HIGH", "after_hours_device")
    METRICS.inc_rule_fire("after_hours_device")

Register an active-alert callback once at startup::

    METRICS.set_active_alert_callback(lambda: db.count_active_alerts())

Expose the metrics over HTTP by adding the ``/metrics`` route to Flask
(done in ``server/app.py``).
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, Optional


class _Metrics:
    """Thread-safe in-process metrics registry."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events_ingested: int = 0
        # (severity, rule_name) → count
        self._alerts_fired: Dict[tuple, int] = {}
        # rule_name → count
        self._rule_fires: Dict[str, int] = {}
        self._active_alert_cb: Optional[Callable[[], int]] = None

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def inc_events_ingested(self, count: int = 1) -> None:
        with self._lock:
            self._events_ingested += count

    def inc_alerts_fired(self, severity: str, rule_name: str) -> None:
        key = (severity.upper(), rule_name)
        with self._lock:
            self._alerts_fired[key] = self._alerts_fired.get(key, 0) + 1

    def inc_rule_fire(self, rule_name: str) -> None:
        with self._lock:
            self._rule_fires[rule_name] = self._rule_fires.get(rule_name, 0) + 1

    def set_active_alert_callback(self, cb: Callable[[], int]) -> None:
        """Register a zero-argument callable that returns the current active-alert count."""
        with self._lock:
            self._active_alert_cb = cb

    # ------------------------------------------------------------------
    # Prometheus text format
    # ------------------------------------------------------------------

    def render(self) -> str:
        """
        Serialise all metrics in the `Prometheus text exposition format
        <https://prometheus.io/docs/instrumenting/exposition_formats/>`_.
        """
        with self._lock:
            events = self._events_ingested
            alerts_fired = dict(self._alerts_fired)
            rule_fires = dict(self._rule_fires)
            cb = self._active_alert_cb

        lines: list[str] = []

        # ── itdn_events_ingested_total ─────────────────────────────────
        lines.append("# HELP itdn_events_ingested_total Total device events received")
        lines.append("# TYPE itdn_events_ingested_total counter")
        lines.append(f"itdn_events_ingested_total {events}")

        # ── itdn_alerts_fired_total ────────────────────────────────────
        lines.append(
            "# HELP itdn_alerts_fired_total "
            "Alerts persisted after deduplication, by severity and rule"
        )
        lines.append("# TYPE itdn_alerts_fired_total counter")
        for (severity, rule), count in sorted(alerts_fired.items()):
            labels = f'severity="{severity}",rule_name="{rule}"'
            lines.append(f"itdn_alerts_fired_total{{{labels}}} {count}")

        # ── itdn_rule_fires_total ──────────────────────────────────────
        lines.append(
            "# HELP itdn_rule_fires_total "
            "Times each rule fired (before deduplication)"
        )
        lines.append("# TYPE itdn_rule_fires_total counter")
        for rule, count in sorted(rule_fires.items()):
            lines.append(f'itdn_rule_fires_total{{rule_name="{rule}"}} {count}')

        # ── itdn_alerts_active ─────────────────────────────────────────
        lines.append(
            "# HELP itdn_alerts_active Current number of unacknowledged alerts"
        )
        lines.append("# TYPE itdn_alerts_active gauge")
        active = cb() if cb else 0
        lines.append(f"itdn_alerts_active {active}")

        return "\n".join(lines) + "\n"


#: Singleton instance used throughout the server.
METRICS = _Metrics()
