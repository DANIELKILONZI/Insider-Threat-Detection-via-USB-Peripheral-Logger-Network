"""
agent/transport.py – Secure event transport to the central SIEM server.

Events are persisted in a SQLite-backed retry queue and flushed
periodically over mTLS (mutual TLS) to the backend REST endpoint.  If
the server is temporarily unreachable, events remain in the queue (up to
``MAX_QUEUE_SIZE`` rows) and are retried on the next flush cycle.  The
queue survives agent restarts and network outages.
"""

from __future__ import annotations

import json
import logging
import ssl
import threading
import time
import urllib.request
from typing import Any, Dict, List, Optional

from agent.config import (
    AGENT_CERT,
    AGENT_KEY,
    FLUSH_INTERVAL,
    MAX_QUEUE_SIZE,
    SERVER_CERT,
    SERVER_URL,
)
from agent.retry_queue import PersistentQueue

logger = logging.getLogger(__name__)

EventDict = Dict[str, Any]

INGEST_ENDPOINT = f"{SERVER_URL}/api/v1/events"
_BATCH_SIZE = 100  # events per HTTP request


def _build_ssl_context() -> Optional[ssl.SSLContext]:
    """Create a mTLS SSLContext if certificates are present, otherwise return None."""
    if not (
        SERVER_CERT
        and AGENT_CERT
        and AGENT_KEY
        and all(
            __import__("os").path.exists(p)
            for p in [SERVER_CERT, AGENT_CERT, AGENT_KEY]
        )
    ):
        logger.warning(
            "mTLS certificates not found – falling back to unverified TLS (dev mode)"
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=SERVER_CERT)
    ctx.load_cert_chain(certfile=AGENT_CERT, keyfile=AGENT_KEY)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx


def _post_events(events: List[EventDict], ssl_ctx: Optional[ssl.SSLContext]) -> bool:
    """POST a batch of events to the SIEM ingest endpoint.  Returns True on success."""
    payload = json.dumps({"events": events}).encode("utf-8")
    req = urllib.request.Request(
        INGEST_ENDPOINT,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as resp:
            if resp.status == 200:
                return True
            logger.warning("Server returned HTTP %d", resp.status)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("Failed to deliver events to %s: %s", INGEST_ENDPOINT, exc)
    return False


class EventTransport:
    """
    Background thread that drains the persistent retry queue and ships
    batches to the central SIEM server at *FLUSH_INTERVAL*-second intervals.

    Usage::

        transport = EventTransport()
        transport.start()
        transport.enqueue(event_dict)
        …
        transport.stop()
    """

    def __init__(self) -> None:
        self._queue = PersistentQueue()
        self._ssl_ctx = _build_ssl_context()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def enqueue(self, event: EventDict) -> None:
        """Persist *event* in the retry queue.  Drops the oldest event if the
        queue has reached ``MAX_QUEUE_SIZE``."""
        if self._queue.size() >= MAX_QUEUE_SIZE:
            logger.error(
                "Retry queue full (%d) – dropping oldest event to make room",
                MAX_QUEUE_SIZE,
            )
            # Commit (discard) the oldest single event to free space
            self._queue.commit(1)
        self._queue.put(event)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            daemon=True,
            name="event-transport",
        )
        self._thread.start()
        logger.info("EventTransport thread started (flush every %ds)", FLUSH_INTERVAL)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=FLUSH_INTERVAL + 5)
        self._flush()  # drain remaining events on shutdown
        self._queue.close()
        logger.info("EventTransport thread stopped")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _flush(self) -> None:
        batch = self._queue.peek(_BATCH_SIZE)
        if not batch:
            return
        logger.debug("Flushing %d events to SIEM", len(batch))
        if _post_events(batch, self._ssl_ctx):
            self._queue.commit(len(batch))
        else:
            logger.warning(
                "Delivery failed; %d events remain in retry queue (will retry)",
                self._queue.size(),
            )

    def _loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(FLUSH_INTERVAL)
            self._flush()

