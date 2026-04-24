"""
agent/transport.py – Secure event transport to the central SIEM server.

Events are batched in an in-memory queue and flushed periodically over
mTLS (mutual TLS) to the backend REST endpoint.  If the server is
temporarily unreachable, events are held in the queue (up to MAX_QUEUE_SIZE)
and retried on the next flush cycle.
"""

from __future__ import annotations

import json
import logging
import queue
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

logger = logging.getLogger(__name__)

EventDict = Dict[str, Any]

INGEST_ENDPOINT = f"{SERVER_URL}/api/v1/events"


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
    Background thread that drains an event queue and ships batches to the
    central SIEM server at *FLUSH_INTERVAL*-second intervals.

    Usage::

        transport = EventTransport()
        transport.start()
        transport.enqueue(event_dict)
        …
        transport.stop()
    """

    def __init__(self) -> None:
        self._q: queue.Queue[EventDict] = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self._ssl_ctx = _build_ssl_context()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def enqueue(self, event: EventDict) -> None:
        """Add *event* to the send queue.  Drops the event if the queue is full."""
        try:
            self._q.put_nowait(event)
        except queue.Full:
            logger.error("Event queue full – dropping event for %s", event.get("device_id"))

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
        logger.info("EventTransport thread stopped")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _drain(self) -> List[EventDict]:
        """Drain all currently available events from the queue."""
        batch: List[EventDict] = []
        while True:
            try:
                batch.append(self._q.get_nowait())
            except queue.Empty:
                break
        return batch

    def _flush(self) -> None:
        batch = self._drain()
        if not batch:
            return
        logger.debug("Flushing %d events to SIEM", len(batch))
        if not _post_events(batch, self._ssl_ctx):
            # Re-enqueue for retry (best-effort; may drop if full)
            for evt in batch:
                try:
                    self._q.put_nowait(evt)
                except queue.Full:
                    logger.error("Re-enqueue failed – event lost for %s", evt.get("device_id"))

    def _loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(FLUSH_INTERVAL)
            self._flush()
