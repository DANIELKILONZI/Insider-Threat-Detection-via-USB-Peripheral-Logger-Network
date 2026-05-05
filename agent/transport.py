"""HTTP/mTLS transport layer — sends events and anchors to the server."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import httpx

from shared.schema import NormalizedEvent

logger = logging.getLogger(__name__)


class AgentTransport:
    """Sends events and anchors to the server via HTTPS (mTLS or API key)."""

    def __init__(
        self,
        server_url: str,
        api_key: str = "",
        cert_path: str = "",
        key_path: str = "",
        ca_cert_path: str = "",
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key

        client_kwargs: dict = {"timeout": 10.0}

        if cert_path and key_path:
            client_kwargs["cert"] = (cert_path, key_path)

        if ca_cert_path:
            client_kwargs["verify"] = ca_cert_path
        else:
            # Disable verification in dev when no CA cert provided
            client_kwargs["verify"] = False

        self._client = httpx.Client(**client_kwargs)
        self._headers = {}
        if api_key:
            self._headers["X-API-Key"] = api_key

    # ------------------------------------------------------------------
    def send_event(self, event: NormalizedEvent) -> bool:
        """POST a NormalizedEvent to /api/v1/events. Returns True on success."""
        try:
            resp = self._client.post(
                f"{self.server_url}/api/v1/events",
                json=event.model_dump(mode="json"),
                headers=self._headers,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            logger.warning("send_event failed: %s", exc)
            return False

    def send_anchor(
        self, agent_id: str, chain_head_hash: str, timestamp: Optional[datetime] = None
    ) -> dict:
        """POST an anchor to /api/v1/anchor. Returns server response dict."""
        ts = timestamp or datetime.now(timezone.utc)
        payload = {
            "agent_id": agent_id,
            "chain_head_hash": chain_head_hash,
            "timestamp": ts.isoformat(),
        }
        try:
            resp = self._client.post(
                f"{self.server_url}/api/v1/anchor",
                json=payload,
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            logger.warning("send_anchor failed: %s", exc)
            return {}

    def request_certificate(self, agent_id: str, csr_pem: str) -> str:
        """POST a CSR to /api/v1/certs/issue. Returns signed cert PEM."""
        try:
            resp = self._client.post(
                f"{self.server_url}/api/v1/certs/issue",
                json={"agent_id": agent_id, "csr_pem": csr_pem},
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json().get("cert_pem", "")
        except Exception as exc:
            logger.warning("request_certificate failed: %s", exc)
            return ""

    def get_trusted_hash(self, agent_id: str) -> str:
        """GET /api/v1/certs/trusted-hash/{agent_id}. Returns hex hash."""
        try:
            resp = self._client.get(
                f"{self.server_url}/api/v1/certs/trusted-hash/{agent_id}",
                headers=self._headers,
            )
            resp.raise_for_status()
            return resp.json().get("hash_value", "")
        except Exception as exc:
            logger.warning("get_trusted_hash failed: %s", exc)
            return ""

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "AgentTransport":
        return self

    def __exit__(self, *_) -> None:
        self.close()
