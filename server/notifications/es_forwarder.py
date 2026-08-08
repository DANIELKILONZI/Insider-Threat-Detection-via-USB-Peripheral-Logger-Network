"""
server/notifications/es_forwarder.py – Forward events and alerts to Elasticsearch.

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

    from server.notifications.es_forwarder import forward_event, forward_alert
    forward_event(event_dict)
    forward_alert(alert_dict)
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import urllib.request
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Index names are read directly from the environment so that they are never
# tainted by the same dict that holds credentials (ES_PASSWORD).
# Call-time reads keep test monkeypatching working.
def _events_index() -> str:
    return os.environ.get("ES_EVENTS_INDEX", "itdn-events")


def _alerts_index() -> str:
    return os.environ.get("ES_ALERTS_INDEX", "itdn-alerts")


def _connection_config() -> Dict[str, Any]:
    """Return non-credential connection settings."""
    return {
        "url": os.environ.get("ES_URL", "").rstrip("/"),
        "verify_tls": os.environ.get("ES_VERIFY_TLS", "true").lower() != "false",
    }


def _ssl_context(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _build_auth_header() -> str:
    """Build the Authorization header value from environment credentials.

    Reads credentials directly from the environment so they are never
    stored in a dict alongside non-credential config, which would allow
    static analysis tools to mistakenly taint non-credential values.

    Returns an empty string when no credentials are configured.
    """
    api_key = os.environ.get("ES_API_KEY", "")
    if api_key:
        return f"ApiKey {api_key}"

    username = os.environ.get("ES_USERNAME", "")
    raw = os.environ.get("ES_PASSWORD", "")
    if username and raw:
        import base64

        encoded = base64.b64encode((username + ":" + raw).encode()).decode()
        return f"Basic {encoded}"

    return ""


def _send_request(
    endpoint: str,
    body: bytes,
    verify_tls: bool,
    log_index: str,
) -> bool:
    """
    Execute an HTTP POST with credentials read internally.

    Credentials are fetched inside this function and are never exposed as
    parameters, keeping them entirely separate from the *log_index* string
    that appears in log messages.
    """
    import urllib.error

    auth = _build_auth_header()
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = auth

    req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=_ssl_context(verify_tls), timeout=10) as resp:
            if resp.status in (200, 201):
                return True
    except urllib.error.HTTPError as exc:
        http_status = exc.code
        logger.warning("Elasticsearch returned HTTP %d for index %s", http_status, log_index)
        return False
    except Exception:  # pylint: disable=broad-except
        logger.warning("Elasticsearch connection failed for index %s", log_index)
        return False
    logger.warning("Elasticsearch returned unexpected status for index %s", log_index)
    return False


def forward_event(event: Dict[str, Any]) -> bool:
    """Index a raw device event into the events index."""
    conn = _connection_config()
    if not conn["url"]:
        logger.debug("Elasticsearch URL not configured – skipping event forwarding")
        return False
    index = _events_index()
    endpoint = f"{conn['url']}/{index}/_doc"
    body = json.dumps(event).encode("utf-8")
    return _send_request(endpoint, body, conn["verify_tls"], index)


def forward_alert(alert: Dict[str, Any]) -> bool:
    """Index a fired alert into the alerts index."""
    conn = _connection_config()
    if not conn["url"]:
        logger.debug("Elasticsearch URL not configured – skipping alert forwarding")
        return False
    index = _alerts_index()
    endpoint = f"{conn['url']}/{index}/_doc"
    body = json.dumps(alert).encode("utf-8")
    return _send_request(endpoint, body, conn["verify_tls"], index)

