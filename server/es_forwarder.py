"""
server/es_forwarder.py – Forward events and alerts to Elasticsearch.

Uses the Elasticsearch Bulk API directly over HTTPS (no external client
library required – only the Python standard library).  This mirrors the
design of ``splunk_forwarder.py`` so the two sinks are easy to compare.

Configuration (environment variables)
--------------------------------------
``ES_URL``         Base URL of the Elasticsearch cluster, e.g.
                   ``https://es.internal:9200``.  Leave empty to disable.
``ES_API_KEY``     API key in ``id:api_key`` format (recommended) **or**
``ES_USERNAME`` /  Basic-auth credentials (alternative).
``ES_PASSWORD``
``ES_EVENTS_INDEX``  Destination index for raw device events (default: ``itdn-events``).
``ES_ALERTS_INDEX``  Destination index for alerts (default: ``itdn-alerts``).
``ES_VERIFY_TLS``    Set to ``"false"`` to skip TLS cert verification (dev only).

Usage::

    from server.es_forwarder import forward_event, forward_alert
    forward_event(event_dict)
    forward_alert(alert_dict)
"""

from __future__ import annotations

import json
import logging
import ssl
import urllib.request
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _get_config() -> Dict[str, Any]:
    """Read ES config from environment at call-time so reloads in tests work."""
    import os

    return {
        "url": os.environ.get("ES_URL", "").rstrip("/"),
        "api_key": os.environ.get("ES_API_KEY", ""),
        "username": os.environ.get("ES_USERNAME", ""),
        "password": os.environ.get("ES_PASSWORD", ""),
        "events_index": os.environ.get("ES_EVENTS_INDEX", "itdn-events"),
        "alerts_index": os.environ.get("ES_ALERTS_INDEX", "itdn-alerts"),
        "verify_tls": os.environ.get("ES_VERIFY_TLS", "true").lower() != "false",
    }


def _ssl_context(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _build_headers(username: str, password: str, api_key: str) -> Dict[str, str]:
    """Build HTTP request headers with auth credentials.

    Accepts individual credential strings so the dict containing the
    password never enters the scope of any logging statement.
    """
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    elif username and password:
        import base64

        creds = base64.b64encode((username + ":" + password).encode()).decode()
        headers["Authorization"] = f"Basic {creds}"
    return headers


def _send_request(
    endpoint: str,
    body: bytes,
    headers: Dict[str, str],
    index: str,
    verify_tls: bool,
) -> bool:
    """
    Execute an HTTP POST and log only non-sensitive outcome details.

    Logs only the HTTP status code or error category – never the exception
    message – to avoid inadvertently leaking request headers through
    exception repr.
    """
    import urllib.error

    req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=_ssl_context(verify_tls), timeout=10) as resp:
            if resp.status in (200, 201):
                return True
    except urllib.error.HTTPError as exc:
        http_status = exc.code
        logger.warning("Elasticsearch returned HTTP %d for index %s", http_status, index)
        return False
    except Exception:  # pylint: disable=broad-except
        logger.warning("Elasticsearch connection failed for index %s", index)
        return False
    logger.warning("Elasticsearch returned unexpected status for index %s", index)
    return False


def _index_document(
    url: str,
    index: str,
    doc: Dict[str, Any],
    verify_tls: bool,
    headers: Dict[str, str],
) -> bool:
    """POST a single document to *index* via the Elasticsearch index API."""
    endpoint = f"{url}/{index}/_doc"
    body = json.dumps(doc).encode("utf-8")
    return _send_request(endpoint, body, headers, index, verify_tls)


def _forward(index: str, doc: Dict[str, Any]) -> bool:
    """Forward *doc* to the given ES *index*; returns True on success."""
    cfg = _get_config()
    if not cfg["url"]:
        logger.debug("Elasticsearch URL not configured – skipping forwarding")
        return False
    headers = _build_headers(cfg["username"], cfg["password"], cfg["api_key"])
    return _index_document(cfg["url"], index, doc, cfg["verify_tls"], headers)


def forward_event(event: Dict[str, Any]) -> bool:
    """Index a raw device event into the events index."""
    cfg = _get_config()
    return _forward(cfg["events_index"], event)


def forward_alert(alert: Dict[str, Any]) -> bool:
    """Index a fired alert into the alerts index."""
    cfg = _get_config()
    return _forward(cfg["alerts_index"], alert)
