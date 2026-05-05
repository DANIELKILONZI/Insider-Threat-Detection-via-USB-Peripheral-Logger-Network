"""
server/auth.py – API key authentication, RBAC, and per-IP rate limiting.

Authentication & RBAC
---------------------
Two modes are supported:

1. **Single shared key** (``ITDN_API_KEY`` is set):
   Every inbound request must carry ``Authorization: Bearer <key>``.
   All authenticated callers share the implicit role ``"admin"``.

2. **Role-keyed map** (``ITDN_API_KEYS`` is a JSON dict):
   ``ITDN_API_KEYS = '{"adminkey": "admin", "analystkey": "analyst", "readkey": "readonly"}'``
   Each key maps to one of three roles:

   * ``admin``    – full access (ingest, config PATCH, ack, integrity ops)
   * ``analyst``  – can read all endpoints + ack alerts; cannot change config
   * ``readonly`` – read-only access (GET endpoints only)

   When ``ITDN_API_KEYS`` is set it takes precedence over ``ITDN_API_KEY``.

Requests without a valid key (when auth is configured) return HTTP 401.
Requests with insufficient role return HTTP 403.

If both ``ITDN_API_KEY`` and ``ITDN_API_KEYS`` are empty, authentication is
disabled so that dev / test environments work without configuration.

Rate Limiting
-------------
A simple in-memory sliding-window limiter restricts each client IP to
ITDN_RATE_LIMIT_MAX requests within ITDN_RATE_LIMIT_WINDOW seconds.

Exceeding the limit returns HTTP 429.

Usage::

    from server.auth import require_api_key, require_role, rate_limit

    @app.route("/api/v1/events", methods=["POST"])
    @require_api_key
    @rate_limit
    def ingest_events(): …

    @app.route("/api/v1/config", methods=["PATCH"])
    @require_role("admin")
    def patch_config(): …
"""

from __future__ import annotations

import functools
import json
import threading
import time
from collections import defaultdict
from typing import Callable, Optional

from flask import jsonify, request

from server.config import API_SECRET_KEY, API_KEYS, RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_SECS

# Per-IP sliding window: maps IP → list of request timestamps (monotonic)
_ip_timestamps: dict[str, list[float]] = defaultdict(list)
_lock = threading.Lock()

# Role precedence ordering (higher index = more permissive)
_ROLE_ORDER = ["readonly", "analyst", "admin"]


def _parse_api_keys() -> dict[str, str]:
    """Parse ITDN_API_KEYS JSON string into a {key: role} dict."""
    if not API_KEYS:
        return {}
    try:
        mapping = json.loads(API_KEYS)
        if not isinstance(mapping, dict):
            return {}
        return {str(k): str(v) for k, v in mapping.items()}
    except (json.JSONDecodeError, Exception):
        return {}


def _get_caller_role() -> Optional[str]:
    """
    Extract and validate the caller's Bearer token.

    Returns the caller's role string ("admin", "analyst", "readonly"),
    or ``None`` when the token is missing / invalid.

    When auth is disabled (no keys configured) returns ``"admin"`` so
    all decorators pass through without rejecting requests.
    """
    keys_map = _parse_api_keys()

    # Mode 1: role-keyed map takes precedence
    if keys_map:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        token = auth_header[len("Bearer "):]
        return keys_map.get(token)  # None if not found

    # Mode 2: single shared key
    if API_SECRET_KEY:
        auth_header = request.headers.get("Authorization", "")
        if auth_header == f"Bearer {API_SECRET_KEY}":
            return "admin"
        return None

    # No auth configured – allow everything as admin
    return "admin"


# ---------------------------------------------------------------------------
# Authentication decorator
# ---------------------------------------------------------------------------

def require_api_key(fn: Callable) -> Callable:
    """Reject requests that don't carry a recognised Bearer token.

    No-op when neither ``ITDN_API_KEY`` nor ``ITDN_API_KEYS`` is set.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        role = _get_caller_role()
        if role is None:
            return jsonify({"error": "Unauthorized – invalid or missing API key"}), 401
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Role-based access control decorator
# ---------------------------------------------------------------------------

def require_role(minimum_role: str) -> Callable:
    """Return a decorator that requires the caller to hold at least *minimum_role*.

    Roles (from least to most permissive): readonly → analyst → admin.

    A 401 is returned when the token is absent/invalid; 403 when the token
    is valid but the role is insufficient.
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            role = _get_caller_role()
            if role is None:
                return jsonify({"error": "Unauthorized – invalid or missing API key"}), 401
            try:
                caller_level = _ROLE_ORDER.index(role)
                required_level = _ROLE_ORDER.index(minimum_role)
            except ValueError:
                return jsonify({"error": "Forbidden – unrecognised role"}), 403
            if caller_level < required_level:
                return jsonify(
                    {
                        "error": (
                            f"Forbidden – role '{role}' insufficient; "
                            f"'{minimum_role}' or higher required"
                        )
                    }
                ), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


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
