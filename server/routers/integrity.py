"""
server/routers/integrity.py – Agent self-integrity registration and checking.

An agent hashes its own binary at startup and checks that hash against the
trusted value registered here, so a tampered agent can be detected centrally.

POST /api/v1/integrity/register   (admin)  record the trusted hash for an agent
POST /api/v1/integrity/check               compare a reported hash against it
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

import server.database as db
from server.auth import require_api_key, require_role

integrity_bp = Blueprint("integrity", __name__)


@integrity_bp.route("/api/v1/integrity/register", methods=["POST"])
@require_role("admin")
def integrity_register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body required"}), 400
    agent_id = data.get("agent_id", "")
    agent_hash = data.get("agent_hash", "")
    if not agent_id or not agent_hash:
        return jsonify({"error": "agent_id and agent_hash required"}), 400
    db.register_agent_hash(agent_id, agent_hash)
    return jsonify({"ok": True, "agent_id": agent_id}), 200


@integrity_bp.route("/api/v1/integrity/check", methods=["POST"])
@require_api_key
def integrity_check():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body required"}), 400
    agent_id = data.get("agent_id", "")
    agent_hash = data.get("agent_hash", "")
    if not agent_id or not agent_hash:
        return jsonify({"error": "agent_id and agent_hash required"}), 400
    trusted, stored_hash = db.check_agent_hash(agent_id, agent_hash)
    return jsonify({"trusted": trusted, "stored_hash": stored_hash}), 200
