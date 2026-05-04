"""Tests for remote log anchoring endpoint."""
from __future__ import annotations
import pytest


def test_anchor_store_and_retrieve(full_client):
    resp = full_client.post(
        "/api/v1/anchor",
        json={"agent_id": "host1", "chain_head_hash": "abc123"},
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert "signature" in data

    resp2 = full_client.get("/api/v1/anchors?agent_id=host1")
    assert resp2.status_code == 200
    body = resp2.get_json()
    assert body["count"] >= 1
    assert body["anchors"][0]["chain_head_hash"] == "abc123"


def test_anchor_missing_fields(full_client):
    resp = full_client.post("/api/v1/anchor", json={}, content_type="application/json")
    assert resp.status_code == 400


def test_anchors_missing_agent_id(full_client):
    resp = full_client.get("/api/v1/anchors")
    assert resp.status_code == 400
