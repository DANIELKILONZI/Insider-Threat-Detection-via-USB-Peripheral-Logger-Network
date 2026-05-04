"""
server/auth.py – API key authentication and per-IP rate limiting.

Authentication
--------------
When ITDN_API_KEY is set, every inbound request must carry:
    Authorization: Bearer <key>

Requests without the correct key are rejected with HTTP 401.

If ITDN_API_KEY is empty (the default), authentication is disabled so that
development / test environments work without configuration.

Rate Limiting
-------------
A simple in-memory sliding-window limiter restricts each client IP to
ITDN_RATE_LIMIT_MAX requests within ITDN_RATE_LIMIT_WINDOW seconds.

Exceeding the limit returns HTTP 429.  The window and max are configurable
via environment variables.

Usage::

    from server.auth import require_api_key, rate_limit

    @app.route("/api/v1/events", methods=["POST"])
    @require_api_key
    @rate_limit
    def ingest_events(): …
"""

from __future__ import annotations

import functools
import threading
import time
from collections import defaultdict
from typing import Callable

from flask import jsonify, request

from server.config import API_SECRET_KEY, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_SECS

# Per-IP sliding window: maps IP → list of request timestamps (monotonic)
_ip_timestamps: dict[str, list[float]] = defaultdict(list)
_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Authentication decorator
# ---------------------------------------------------------------------------

def require_api_key(fn: Callable) -> Callable:
    """Reject requests that don't carry the correct Bearer token.

    No-op when ``ITDN_API_KEY`` is empty (dev / test mode).
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if API_SECRET_KEY:
            auth_header = request.headers.get("Authorization", "")
            if auth_header != f"Bearer {API_SECRET_KEY}":
                return jsonify({"error": "Unauthorized – invalid or missing API key"}), 401
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Rate-limiting decorator
# ---------------------------------------------------------------------------

def rate_limit(fn: Callable) -> Callable:
    """Sliding-window per-IP rate limiter.

    Allows up to ``RATE_LIMIT_MAX`` requests per ``RATE_LIMIT_WINDOW_SECS``
    seconds from the same remote IP.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr or "unknown"
        now = time.monotonic()
        cutoff = now - RATE_LIMIT_WINDOW_SECS

        with _lock:
            times = _ip_timestamps[ip]
            # Evict stale entries
            _ip_timestamps[ip] = [t for t in times if t > cutoff]
            if len(_ip_timestamps[ip]) >= RATE_LIMIT_MAX:
                return (
                    jsonify(
                        {
                            "error": (
                                f"Rate limit exceeded – max {RATE_LIMIT_MAX} requests "
                                f"per {RATE_LIMIT_WINDOW_SECS}s"
                            )
                        }
                    ),
                    429,
                )
            _ip_timestamps[ip].append(now)

        return fn(*args, **kwargs)
    return wrapper
