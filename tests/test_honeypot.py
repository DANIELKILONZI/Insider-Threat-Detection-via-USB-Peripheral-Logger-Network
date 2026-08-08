"""Tests for honeypot device detection."""
from __future__ import annotations
from unittest.mock import MagicMock, patch
from server.detection.honeypot import is_honeypot_device, HoneypotConfig
from server.detection.rules import rule_honeypot_device


def test_is_honeypot_false_by_default():
    assert is_honeypot_device("1234:5678") is False


def test_honeypot_rule_fires_on_match():
    with patch("server.detection.honeypot._honeypot_config") as mock_cfg:
        mock_cfg.HONEYPOT_VIDS = ["dead:beef"]
        event = {"device_id": "dead:beef", "hostname": "victim"}
        result = rule_honeypot_device(event, MagicMock())
        assert result is not None
        assert result.severity == "CRITICAL"


def test_honeypot_rule_no_fire_on_normal():
    with patch("server.detection.honeypot._honeypot_config") as mock_cfg:
        mock_cfg.HONEYPOT_VIDS = ["dead:beef"]
        event = {"device_id": "1234:5678", "hostname": "victim"}
        result = rule_honeypot_device(event, MagicMock())
        assert result is None
