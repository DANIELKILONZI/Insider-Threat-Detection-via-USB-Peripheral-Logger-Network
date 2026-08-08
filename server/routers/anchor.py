"""
server/routers/anchor.py – Remote log-chain anchoring.

Agents periodically submit their local hash-chain head; the server counter-signs
it and stores the anchor, so later tampering with an agent's local log can be
detected by comparing against the server-held anchor.

POST /api/v1/anchor
    Body: {"agent_id": ..., "chain_head_hash": ...}
GET  /api/v1/anchors?agent_id=…
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

import server.database as db
from server.auth import require_api_key

logger = logging.getLogger(__name__)

anchor_bp = Blueprint("anchor", __name__)


@anchor_bp.route("/api/v1/anchor", methods=["POST"])
@require_api_key
def anchor_chain():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body required"}), 400
    agent_id = data.get("agent_id", "")
    chain_head_hash = data.get("chain_head_hash", "")
    if not agent_id or not chain_head_hash:
        return jsonify({"error": "agent_id and chain_head_hash required"}), 400
    try:
        sig = db.insert_anchor(agent_id, chain_head_hash)
    except db.AnchorSigningError as exc:
        # Misconfiguration, not a bad request: the agent did nothing wrong, and
        # it must not be told the anchor succeeded. 503 so agents retry once the
        # server is given a signing key.
        logger.critical("Anchor rejected – server cannot sign: %s", exc)
        return jsonify({"error": "Anchoring unavailable: server has no signing key"}), 503
    return jsonify({"ok": True, "signature": sig, "anchored_at": db._utcnow()}), 200


@anchor_bp.route("/api/v1/anchors", methods=["GET"])
def get_anchors_endpoint():
    agent_id = request.args.get("agent_id")
    if not agent_id:
        return jsonify({"error": "agent_id query parameter required"}), 400
    limit = int(request.args.get("limit", 100))
    anchors = db.get_anchors(agent_id, limit=limit)
    return jsonify({"anchors": anchors, "count": len(anchors)}), 200
