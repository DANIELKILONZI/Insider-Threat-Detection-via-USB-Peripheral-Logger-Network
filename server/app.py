"""
server/app.py – Flask REST API for the ITDN central server.

Endpoints
---------
POST /api/v1/events
    Ingest a batch of device events from endpoint agents.
    Body: {"events": [ <event>, … ]}
    Returns: {"ok": true, "stored": <count>}

GET /api/v1/alerts
    List open (or all) alerts.
    Query params:
        hostname    – filter by hostname
        ack         – "true" | "false" (filter by acknowledgement status)
        limit       – max records (default 200)

GET /api/v1/audit
    Retrieve server-side audit chain records for a host.
    Query params:
        hostname    – required
        limit       – max records (default 500)

GET /api/v1/health
    Liveness probe.
"""

from __future__ import annotations

import logging
import os

from flask import Flask, jsonify, request

import server.database as db
import server.splunk_forwarder as splunk
from server.alert_manager import process_alerts
from server.rules import evaluate

logger = logging.getLogger(__name__)

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Ingest endpoint
# ---------------------------------------------------------------------------

@app.route("/api/v1/events", methods=["POST"])
def ingest_events():
    data = request.get_json(silent=True)
    if not data or "events" not in data:
        return jsonify({"error": "Invalid payload – expected {\"events\": [...]}"}), 400

    events = data["events"]
    if not isinstance(events, list):
        return jsonify({"error": "\"events\" must be a list"}), 400

    stored = 0
    for event in events:
        if not isinstance(event, dict):
            continue
        try:
            # 1. Persist to DB
            db.insert_event(event)
            stored += 1

            # 2. Append to server-side audit chain
            db.append_audit_record(event.get("hostname", ""), event)

            # 3. Forward raw event to Splunk
            splunk.forward_event(event)

            # 4. Run anomaly detection rules
            alerts = evaluate(event, db)

            # 5. Deduplicate, persist, and forward alerts
            if alerts:
                process_alerts(event, alerts)

        except Exception:  # pylint: disable=broad-except
            logger.exception("Failed to process event: %s", event)

    return jsonify({"ok": True, "stored": stored}), 200


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@app.route("/api/v1/alerts", methods=["GET"])
def list_alerts():
    hostname = request.args.get("hostname") or None
    ack_param = request.args.get("ack")
    acknowledged: bool | None = None
    if ack_param is not None:
        acknowledged = ack_param.lower() == "true"
    limit = int(request.args.get("limit", 200))

    rows = db.list_alerts(hostname=hostname, acknowledged=acknowledged, limit=limit)
    alerts = [dict(r) for r in rows]
    return jsonify({"alerts": alerts, "count": len(alerts)}), 200


# ---------------------------------------------------------------------------
# Audit chain
# ---------------------------------------------------------------------------

@app.route("/api/v1/audit", methods=["GET"])
def audit_chain():
    hostname = request.args.get("hostname")
    if not hostname:
        return jsonify({"error": "hostname query parameter is required"}), 400
    limit = int(request.args.get("limit", 500))
    rows = db.get_audit_chain(hostname=hostname, limit=limit)
    records = [dict(r) for r in rows]
    return jsonify({"hostname": hostname, "records": records, "count": len(records)}), 200


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    """Application factory – initialises the DB and returns the Flask app."""
    db.init_db()
    return app


if __name__ == "__main__":
    from server.config import SERVER_HOST, SERVER_PORT, TLS_CERT, TLS_KEY

    _app = create_app()
    ssl_ctx = None
    if os.path.exists(TLS_CERT) and os.path.exists(TLS_KEY):
        import ssl as _ssl

        ssl_ctx = (_ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER))
        ssl_ctx.load_cert_chain(TLS_CERT, TLS_KEY)
        logger.info("TLS enabled with cert %s", TLS_CERT)
    else:
        logger.warning("TLS certificates not found – running in plain HTTP mode (dev only)")

    _app.run(host=SERVER_HOST, port=SERVER_PORT, ssl_context=ssl_ctx)
