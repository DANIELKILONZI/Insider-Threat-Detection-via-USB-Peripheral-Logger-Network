"""
agent/integrity.py – Agent runtime integrity verification.
"""

from __future__ import annotations

import hashlib
import json
import logging
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def compute_agent_hash() -> str:
    """Compute SHA-256 of all .py files in the agent package, sorted, concatenated."""
    agent_dir = Path(__file__).parent
    py_files = sorted(agent_dir.glob("*.py"))
    combined = hashlib.sha256()
    for f in py_files:
        try:
            combined.update(f.read_bytes())
        except OSError:
            pass
    return combined.hexdigest()


class IntegrityChecker:
    """Checks and registers agent runtime integrity with the ITDN server."""

    def __init__(self) -> None:
        from agent.config import HOSTNAME, SERVER_URL
        self._agent_id = HOSTNAME
        self._server_url = SERVER_URL
        self._agent_hash = compute_agent_hash()

    def check_with_server(self, transport: Any) -> bool:
        """POST agent hash to /api/v1/integrity/check. Returns True if trusted."""
        ssl_ctx = getattr(transport, "_ssl_ctx", None)
        url = f"{self._server_url}/api/v1/integrity/check"
        payload = json.dumps({
            "agent_id": self._agent_id,
            "agent_hash": self._agent_hash,
        }).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as resp:
                body = json.loads(resp.read())
                return bool(body.get("trusted", False))
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Integrity check failed: %s", exc)
            return False

    def register_with_server(self, transport: Any) -> None:
        """POST agent hash to /api/v1/integrity/register to set initial trusted hash."""
        ssl_ctx = getattr(transport, "_ssl_ctx", None)
        url = f"{self._server_url}/api/v1/integrity/register"
        payload = json.dumps({
            "agent_id": self._agent_id,
            "agent_hash": self._agent_hash,
        }).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as resp:
                logger.info("Integrity hash registered: %s", self._agent_hash[:16])
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Integrity registration failed: %s", exc)
