"""
server/routers/system.py – Liveness, metrics, and the SOC dashboard.

GET /api/v1/health   liveness probe
GET /metrics         Prometheus-format metrics (text/plain; version=0.0.4)
GET /dashboard, /    minimal SOC dashboard (HTML)
"""

from __future__ import annotations

from flask import Blueprint, Response, jsonify, render_template

from server.metrics import METRICS

system_bp = Blueprint("system", __name__)


@system_bp.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@system_bp.route("/metrics", methods=["GET"])
def metrics():
    return Response(METRICS.render(), status=200, mimetype="text/plain; version=0.0.4")


@system_bp.route("/dashboard")
@system_bp.route("/")
def dashboard():
    return render_template("dashboard.html")
