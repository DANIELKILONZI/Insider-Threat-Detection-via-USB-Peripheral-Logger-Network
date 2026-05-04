"""
server/app.py – Flask REST API for the ITDN central server.

Endpoints
---------
POST /api/v1/events
    Ingest a batch of device events from endpoint agents.
    Requires: Authorization: Bearer <ITDN_API_KEY>  (if key is configured)
    Body: { "events": [ <event>, … ] }
    Returns: {"ok": true, "stored": <count>, "validation_errors": [...]}

PATCH /api/v1/alerts/<id>/ack
    Mark an alert as acknowledged by a SOC analyst.
    Returns: {"ok": true, "alert_id": <id>}

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

GET  /api/v1/config
    Return the current runtime anomaly-detection thresholds.

PATCH /api/v1/config
    Update one or more anomaly-detection thresholds at runtime.
    Body: { "rapid_cycle_count": 3, "after_hours_start": 20, ... }
    Returns: {"ok": true, "config": {...}, "errors": [...]}

GET /api/v1/health
    Liveness probe.

GET /dashboard
    Minimal SOC dashboard (HTML).
"""

from __future__ import annotations

import logging
import os

from flask import Flask, jsonify, render_template, request

import server.database as db
import server.splunk_forwarder as splunk
from server.alert_manager import process_alerts
from server.auth import rate_limit, require_api_key
from server.rule_config import get_config, update_config
from server.rules import evaluate
from server.schema import EventBatch

logger = logging.getLogger(__name__)

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Ingest endpoint
# ---------------------------------------------------------------------------

@app.route("/api/v1/events", methods=["POST"])
@require_api_key
@rate_limit
def ingest_events():
    raw = request.get_json(silent=True)
    if not raw or "events" not in raw:
        return jsonify({"error": 'Invalid payload – expected {"events": [...]}'}), 400
    if not isinstance(raw.get("events"), list):
        return jsonify({"error": '"events" must be a list'}), 400

    # Validate with Pydantic; collect per-event errors but continue processing
    # valid events so a single malformed entry doesn't block the entire batch.
    try:
        from pydantic import ValidationError
        batch = EventBatch.model_validate(raw)
        events = [e.model_dump() for e in batch.events]
        validation_errors: list = []
    except Exception as exc:  # pylint: disable=broad-except
        try:
            from pydantic import ValidationError as VE
            if isinstance(exc, VE):
                return jsonify({"error": "Validation failed", "details": exc.errors()}), 400
        except ImportError:
            pass
        return jsonify({"error": f"Validation failed: {exc}"}), 400

    stored = 0
    for event in events:
        try:
            db.insert_event(event)
            stored += 1
            db.append_audit_record(event.get("hostname", ""), event)
            splunk.forward_event(event)
            alerts = evaluate(event, db)
            if alerts:
                process_alerts(event, alerts)
        except Exception:  # pylint: disable=broad-except
            logger.exception("Failed to process event: %s", event)

    return jsonify({"ok": True, "stored": stored, "validation_errors": validation_errors}), 200


# ---------------------------------------------------------------------------
# Alert acknowledgement
# ---------------------------------------------------------------------------

@app.route("/api/v1/alerts/<int:alert_id>/ack", methods=["PATCH"])
def ack_alert(alert_id: int):
    updated = db.acknowledge_alert(alert_id)
    if not updated:
        return jsonify({"error": f"Alert {alert_id} not found or already acknowledged"}), 404
    return jsonify({"ok": True, "alert_id": alert_id}), 200


# ---------------------------------------------------------------------------
# Alerts list
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
    return jsonify({"alerts": rows, "count": len(rows)}), 200


# ---------------------------------------------------------------------------
# Audit chain
# ---------------------------------------------------------------------------

@app.route("/api/v1/audit", methods=["GET"])
def audit_chain():
    hostname = request.args.get("hostname")
    if not hostname:
        return jsonify({"error": "hostname query parameter is required"}), 400
    limit = int(request.args.get("limit", 500))
    records = db.get_audit_chain(hostname=hostname, limit=limit)
    return jsonify({"hostname": hostname, "records": records, "count": len(records)}), 200


# ---------------------------------------------------------------------------
# Runtime config
# ---------------------------------------------------------------------------

@app.route("/api/v1/config", methods=["GET"])
def get_runtime_config():
    return jsonify({"config": get_config()}), 200


@app.route("/api/v1/config", methods=["PATCH"])
def patch_runtime_config():
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    new_cfg, errors = update_config(data)
    status = 200 if not errors else 207  # 207 Multi-Status: partial success
    return jsonify({"ok": True, "config": new_cfg, "errors": errors}), status


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@app.route("/")
def dashboard():
    return render_template("dashboard.html")


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

        ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(TLS_CERT, TLS_KEY)
        logger.info("TLS enabled with cert %s", TLS_CERT)
    else:
        logger.warning("TLS certificates not found – running in plain HTTP mode (dev only)")

    _app.run(host=SERVER_HOST, port=SERVER_PORT, ssl_context=ssl_ctx)
