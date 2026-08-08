"""
server/routers/alerts.py – Alert listing and acknowledgement.

GET   /api/v1/alerts
    List open (or all) alerts.
    Query params:
        hostname    – filter by hostname
        ack         – "true" | "false" (filter by acknowledgement status)
        limit       – max records (default 200)

PATCH /api/v1/alerts/<id>/ack
    Mark an alert as acknowledged by a SOC analyst.
    Returns: {"ok": true, "alert_id": <id>}
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

import server.database as db
from server.auth import require_role

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("/api/v1/alerts", methods=["GET"])
def list_alerts():
    hostname = request.args.get("hostname") or None
    ack_param = request.args.get("ack")
    acknowledged: bool | None = None
    if ack_param is not None:
        acknowledged = ack_param.lower() == "true"
    limit = int(request.args.get("limit", 200))

    rows = db.list_alerts(hostname=hostname, acknowledged=acknowledged, limit=limit)
    return jsonify({"alerts": rows, "count": len(rows)}), 200


@alerts_bp.route("/api/v1/alerts/<int:alert_id>/ack", methods=["PATCH"])
@require_role("analyst")
def ack_alert(alert_id: int):
    updated = db.acknowledge_alert(alert_id)
    if not updated:
        return jsonify({"error": f"Alert {alert_id} not found or already acknowledged"}), 404
    return jsonify({"ok": True, "alert_id": alert_id}), 200
