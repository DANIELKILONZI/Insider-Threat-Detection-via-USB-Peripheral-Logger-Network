"""
agent/anchor_scheduler.py – Periodically anchors the local audit chain head
on the central ITDN server for tamper-evident remote attestation.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request
from typing import Optional

logger = logging.getLogger(__name__)


class AnchorScheduler:
    """
    Background thread that POSTs the current audit chain head hash to
    /api/v1/anchor every ANCHOR_INTERVAL seconds.
    """

    def __init__(self, audit_logger, transport) -> None:
        from agent.config import ANCHOR_INTERVAL, HOSTNAME, SERVER_URL
        self._audit_logger = audit_logger
        self._transport = transport
        self._interval = ANCHOR_INTERVAL
        self._agent_id = HOSTNAME
        self._anchor_url = f"{SERVER_URL}/api/v1/anchor"
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="anchor-scheduler"
        )
        self._thread.start()
        logger.info("AnchorScheduler started (interval=%ds)", self._interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _post_anchor(self, chain_head: str) -> bool:
        """POST anchor to server. Returns True on success."""
        payload = json.dumps({
            "agent_id": self._agent_id,
            "chain_head_hash": chain_head,
        }).encode("utf-8")
        req = urllib.request.Request(
            self._anchor_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        ssl_ctx = getattr(self._transport, "_ssl_ctx", None)
        try:
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as resp:
                return resp.status == 200
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Failed to post anchor to %s: %s", self._anchor_url, exc)
            return False

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(self._interval)
            if self._stop.is_set():
                break
            chain_head = self._audit_logger.chain_head
            if chain_head and chain_head != "0" * 64:
                success = self._post_anchor(chain_head)
                if success:
                    logger.info("Anchored chain head %s…", chain_head[:16])
                else:
                    logger.warning("Anchor post failed for hash %s…", chain_head[:16])
