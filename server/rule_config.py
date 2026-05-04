"""
server/rule_config.py – Runtime-adjustable anomaly detection thresholds.

At startup the store is initialised from environment variables (via
``server.config``).  SOC operators can then adjust thresholds live through
``PATCH /api/v1/config`` without redeploying the service.

The store is process-local and in-memory; it resets to the env-var defaults
on service restart.  For persistence across restarts set the env vars in your
Docker / systemd configuration.

Usage::

    from server.rule_config import get_config, update_config

    cfg = get_config()
    new_cfg, errors = update_config({"rapid_cycle_count": 3})
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Tuple

from server.config import (
    AFTER_HOURS_END,
    AFTER_HOURS_START,
    ALERT_DEDUP_WINDOW_SECS,
    RAPID_CYCLE_COUNT,
    RAPID_CYCLE_WINDOW_SECS,
    VOLUME_THRESHOLD_BYTES,
)

_lock = threading.RLock()

_runtime: Dict[str, int] = {
    "after_hours_start": AFTER_HOURS_START,
    "after_hours_end": AFTER_HOURS_END,
    "volume_threshold_bytes": VOLUME_THRESHOLD_BYTES,
    "rapid_cycle_count": RAPID_CYCLE_COUNT,
    "rapid_cycle_window_secs": RAPID_CYCLE_WINDOW_SECS,
    "alert_dedup_window_secs": ALERT_DEDUP_WINDOW_SECS,
}

# Keys that accept any positive integer
_POSITIVE_INT_KEYS = frozenset(_runtime.keys())
# Additional range constraints
_RANGE_CONSTRAINTS: Dict[str, Tuple[int, int]] = {
    "after_hours_start": (0, 23),
    "after_hours_end": (0, 23),
}


def get_config() -> Dict[str, Any]:
    """Return a snapshot of the current runtime configuration."""
    with _lock:
        return dict(_runtime)


def reset_to_defaults() -> None:
    """Restore all thresholds to the values loaded from environment variables.

    Intended for use in tests to prevent state leakage between test cases.
    """
    with _lock:
        _runtime.update(
            {
                "after_hours_start": AFTER_HOURS_START,
                "after_hours_end": AFTER_HOURS_END,
                "volume_threshold_bytes": VOLUME_THRESHOLD_BYTES,
                "rapid_cycle_count": RAPID_CYCLE_COUNT,
                "rapid_cycle_window_secs": RAPID_CYCLE_WINDOW_SECS,
                "alert_dedup_window_secs": ALERT_DEDUP_WINDOW_SECS,
            }
        )


def update_config(updates: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """
    Apply *updates* to the runtime configuration.

    Only known keys with valid positive-integer values are accepted.

    Returns ``(new_config, errors)`` where *errors* is a list of
    human-readable error messages for any rejected keys.
    """
    errors: List[str] = []
    validated: Dict[str, int] = {}

    for key, value in updates.items():
        if key not in _POSITIVE_INT_KEYS:
            errors.append(f"Unknown configuration key: {key!r}")
            continue

        if not isinstance(value, int) or isinstance(value, bool):
            errors.append(f"{key!r} must be an integer, got {type(value).__name__!r}")
            continue

        lo, hi = _RANGE_CONSTRAINTS.get(key, (1, 2**31 - 1))
        if not (lo <= value <= hi):
            errors.append(f"{key!r} must be in range [{lo}, {hi}], got {value}")
            continue

        validated[key] = value

    with _lock:
        _runtime.update(validated)

    return get_config(), errors
