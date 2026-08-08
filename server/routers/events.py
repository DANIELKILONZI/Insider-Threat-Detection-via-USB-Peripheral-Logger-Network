"""
server/routers/events.py – Event ingest.

POST /api/v1/events
    Ingest a batch of device events from endpoint agents.
    Requires: Authorization: Bearer <ITDN_API_KEY>  (if a key is configured)
    Body: { "events": [ <event>, … ] }
    Returns: {"ok": true, "stored": <count>, "validation_errors": [...]}
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

import server.database as db
import server.notifications.es_forwarder as es
import server.notifications.splunk_forwarder as splunk
from server import alert_manager
from server.auth import rate_limit, require_api_key
from server.detection import rules
from server.metrics import METRICS
from server.schema import EventBatch
from server.scoring import risk_scoring

logger = logging.getLogger(__name__)

events_bp = Blueprint("events", __name__)


@events_bp.route("/api/v1/events", methods=["POST"])
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
        logger.debug("Event batch validation failed: %s", exc)
        return jsonify({"error": "Validation failed"}), 400

    stored = 0
    for event in events:
        try:
            # Evaluate rules BEFORE inserting so device_is_new returns True
            # for the very first occurrence of a device on a host.
            alerts = rules.evaluate(event, db)
            db.insert_event(event)
            stored += 1
            METRICS.inc_events_ingested()
            db.append_audit_record(event.get("hostname", ""), event)
            splunk.forward_event(event)
            es.forward_event(event)
            # Update device baseline and compute risk score
            hostname = event.get("hostname", "")
            device_id = event.get("device_id", "")
            if hostname and device_id:
                db.update_device_baseline(hostname, device_id)
                # User behaviour analytics – update per-user baseline if 'user' is present
                username = event.get("user", "")
                if username:
                    db.update_user_baseline(username, hostname, device_id)
                # Timezone inference: record UTC offset from event timestamp when provided
                utc_offset = event.get("utc_offset_hours")
                if utc_offset is not None:
                    try:
                        db.update_host_timezone(hostname, float(utc_offset))
                    except Exception:  # pylint: disable=broad-except
                        pass
            if alerts:
                alert_manager.process_alerts(event, alerts)
                scorer = risk_scoring.RiskScorer(db)
                risk_score = scorer.score_event(hostname, alerts)
                if risk_score > 100:
                    logger.critical(
                        "HIGH RISK: host %s cumulative risk score=%d", hostname, risk_score
                    )
        except Exception:  # pylint: disable=broad-except
            logger.exception("Failed to process event: %s", event)

    return jsonify({"ok": True, "stored": stored, "validation_errors": validation_errors}), 200
