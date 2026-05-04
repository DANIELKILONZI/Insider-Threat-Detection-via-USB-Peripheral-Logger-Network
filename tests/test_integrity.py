"""Tests for agent integrity check endpoints."""
from __future__ import annotations
import pytest


def test_register_integrity(full_client):
    resp = full_client.post(
        "/api/v1/integrity/register",
        json={"agent_id": "agent1", "agent_hash": "abc123def456"},
        content_type="application/json",
    )
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True


def test_check_integrity_trusted(full_client):
    full_client.post(
        "/api/v1/integrity/register",
        json={"agent_id": "agent2", "agent_hash": "myhash"},
        content_type="application/json",
    )
    resp = full_client.post(
        "/api/v1/integrity/check",
        json={"agent_id": "agent2", "agent_hash": "myhash"},
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["trusted"] is True


def test_check_integrity_untrusted(full_client):
    full_client.post(
        "/api/v1/integrity/register",
        json={"agent_id": "agent3", "agent_hash": "correct_hash"},
        content_type="application/json",
    )
    resp = full_client.post(
        "/api/v1/integrity/check",
        json={"agent_id": "agent3", "agent_hash": "wrong_hash"},
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["trusted"] is False


def test_check_integrity_not_registered(full_client):
    resp = full_client.post(
        "/api/v1/integrity/check",
        json={"agent_id": "unknown_agent", "agent_hash": "anything"},
        content_type="application/json",
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["trusted"] is False


def test_register_missing_fields(full_client):
    resp = full_client.post("/api/v1/integrity/register", json={}, content_type="application/json")
    assert resp.status_code == 400
