"""Security middleware for the FastAPI application.

1. API-key enforcement  — every request must carry a valid ``X-API-Key``
   header (unless ``SERVER_API_KEY`` is blank or the path is exempted).
2. Rate limiting        — sliding-window in-process counter per client IP;
   returns HTTP 429 when an IP exceeds ``SERVER_RATE_LIMIT_REQUESTS``
   requests within ``SERVER_RATE_LIMIT_WINDOW_SECONDS`` seconds.

Both checks are skipped for the ``/health`` and ``/docs*`` / ``/openapi``
paths so that monitoring probes and API explorers work unauthenticated.
"""
from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Deque, Dict

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# Paths that are always public (no auth / rate-limit check)
_PUBLIC_PREFIXES = (
    "/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/dashboard",
)


class SecurityMiddleware(BaseHTTPMiddleware):
    """Combined API-key check + per-IP sliding-window rate limiter.

    Constructor parameters (all optional — taken from config defaults):

        api_key               – Required header value; set to "" to disable auth.
        rate_limit_requests   – Max requests per window (0 = disabled).
        rate_limit_window     – Window size in seconds.
    """

    def __init__(
        self,
        app,
        api_key: str = "",
        rate_limit_requests: int = 200,
        rate_limit_window: int = 60,
    ) -> None:
        super().__init__(app)
        self._api_key = api_key
        self._rate_limit = rate_limit_requests
        self._window = rate_limit_window
        # ip -> deque of request timestamps
        self._buckets: Dict[str, Deque[float]] = defaultdict(deque)

    # ------------------------------------------------------------------
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip checks for public paths
        if any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        # 1. Rate limiting (before auth so we can block before doing any work)
        if self._rate_limit > 0:
            client_ip = request.client.host if request.client else "unknown"
            now = time.monotonic()
            bucket = self._buckets[client_ip]

            # Evict timestamps outside the window
            cutoff = now - self._window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

            if len(bucket) >= self._rate_limit:
                logger.warning("Rate limit exceeded for IP %s path %s", client_ip, path)
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Too many requests — please slow down.",
                        "retry_after": self._window,
                    },
                )
            bucket.append(now)

        # 2. API-key check
        if self._api_key:
            key = request.headers.get("X-API-Key", "")
            if key != self._api_key:
                logger.warning("Rejected request with invalid API key (path=%s)", path)
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid or missing X-API-Key header."},
                )

        return await call_next(request)
