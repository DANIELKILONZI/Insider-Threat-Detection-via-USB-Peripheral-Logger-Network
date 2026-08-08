"""
server/routers/audit.py – Server-side audit chain and event timeline.

GET /api/v1/audit
    Retrieve server-side audit chain records for a host.
    Query params:
        hostname    – required
        limit       – max records (default 500)

GET /api/v1/timeline
    Correlated event timeline, optionally filtered by host, device, or start time.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

import server.database as db

audit_bp = Blueprint("audit", __name__)


@audit_bp.route("/api/v1/audit", methods=["GET"])
def audit_chain():
    hostname = request.args.get("hostname")
    if not hostname:
        return jsonify({"error": "hostname query parameter is required"}), 400
    limit = int(request.args.get("limit", 500))
    records = db.get_audit_chain(hostname=hostname, limit=limit)
    return jsonify({"hostname": hostname, "records": records, "count": len(records)}), 200


@audit_bp.route("/api/v1/timeline", methods=["GET"])
def timeline():
    hostname = request.args.get("hostname") or None
    device_id = request.args.get("device_id") or None
    since = request.args.get("since") or None
    limit = int(request.args.get("limit", 500))

    items = db.get_timeline(
        hostname=hostname,
        device_id=device_id,
        since=since,
        limit=limit,
    )
    return jsonify({"items": items, "count": len(items)}), 200
