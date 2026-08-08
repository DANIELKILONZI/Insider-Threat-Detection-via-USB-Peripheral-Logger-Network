"""
server/routers/admin.py – Runtime configuration, threat feed, and maintenance.

GET   /api/v1/config                 current runtime anomaly-detection thresholds
PATCH /api/v1/config          (admin) update one or more thresholds at runtime
GET   /api/v1/threat_feed            list known-bad device identifiers
POST  /api/v1/threat_feed/reload (admin) re-read the feed from disk or URL
POST  /api/v1/maintenance/purge  (admin) delete records past the retention window
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

import server.database as db
from server.auth import require_role
from server.detection import rule_config, threat_feed

logger = logging.getLogger(__name__)

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/api/v1/config", methods=["GET"])
def get_runtime_config():
    return jsonify({"config": rule_config.get_config()}), 200


@admin_bp.route("/api/v1/config", methods=["PATCH"])
@require_role("admin")
def patch_runtime_config():
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    new_cfg, errors = rule_config.update_config(data)
    status = 200 if not errors else 207  # 207 Multi-Status: partial success
    return jsonify({"ok": True, "config": new_cfg, "errors": errors}), status


@admin_bp.route("/api/v1/threat_feed", methods=["GET"])
def get_threat_feed():
    entries = sorted(threat_feed.get_feed())
    return jsonify({"entries": entries, "count": len(entries)}), 200


@admin_bp.route("/api/v1/threat_feed/reload", methods=["POST"])
@require_role("admin")
def reload_threat_feed():
    count = threat_feed.reload()
    return jsonify({"ok": True, "entries": count}), 200


@admin_bp.route("/api/v1/maintenance/purge", methods=["POST"])
@require_role("admin")
def purge_old_data():
    from server.config import RETENTION_DAYS
    data = request.get_json(silent=True) or {}
    retention_days = int(data.get("retention_days", RETENTION_DAYS))
    counts = db.purge_old_records(retention_days)
    logger.info("Manual purge completed: %s", counts)
    return jsonify({"ok": True, "deleted": counts, "retention_days": retention_days}), 200
