"""
server/routers/analytics.py – Read-only analytical views over collected data.

GET /api/v1/risk?hostname=…           per-host cumulative risk score
GET /api/v1/baseline?hostname=…       known-device baseline for a host
GET /api/v1/anomaly?hostname=…        z-score anomaly rating for latest activity
GET /api/v1/attack_graph?hostname=…   lateral-movement graph and findings
GET /api/v1/uba/baseline?username=…   per-user device baseline
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

import server.database as db
from server.detection import anomaly, attack_graph

analytics_bp = Blueprint("analytics", __name__)


@analytics_bp.route("/api/v1/risk", methods=["GET"])
def get_risk():
    hostname = request.args.get("hostname")
    if not hostname:
        return jsonify({"error": "hostname query parameter required"}), 400
    score = db.get_risk_score(hostname)
    return jsonify({"hostname": hostname, "risk_score": score}), 200


@analytics_bp.route("/api/v1/baseline", methods=["GET"])
def get_baseline():
    hostname = request.args.get("hostname")
    if not hostname:
        return jsonify({"error": "hostname query parameter required"}), 400
    baseline = db.get_device_baseline(hostname)
    return jsonify({"hostname": hostname, "baseline": baseline, "count": len(baseline)}), 200


@analytics_bp.route("/api/v1/anomaly", methods=["GET"])
def get_anomaly():
    hostname = request.args.get("hostname")
    if not hostname:
        return jsonify({"error": "hostname query parameter required"}), 400
    recent = db.get_recent_events(hostname, window_secs=3600)
    detector = anomaly.AnomalyDetector()
    if len(recent) >= 2:
        detector.fit(recent[:-1])
        score = detector.score(recent[-1], recent[:-1])
    elif recent:
        score = 0.0
    else:
        score = 0.0
    return jsonify({"hostname": hostname, "anomaly_score": score, "event_count": len(recent)}), 200


@analytics_bp.route("/api/v1/attack_graph", methods=["GET"])
def get_attack_graph():
    hostname = request.args.get("hostname")
    if not hostname:
        return jsonify({"error": "hostname query parameter required"}), 400
    graph = attack_graph.build_attack_graph(hostname, db)
    findings = attack_graph.detect_exfil_pattern(graph)
    return jsonify({"hostname": hostname, "graph": graph, "findings": findings}), 200


@analytics_bp.route("/api/v1/uba/baseline", methods=["GET"])
def get_uba_baseline():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username query parameter required"}), 400
    baseline = db.get_user_baseline(username)
    return jsonify({"username": username, "baseline": baseline, "count": len(baseline)}), 200
