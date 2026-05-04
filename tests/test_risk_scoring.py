"""Tests for risk scoring engine."""
from __future__ import annotations
from unittest.mock import MagicMock
from server.risk_scoring import RiskScorer, RULE_WEIGHTS


def _mock_alert(rule_name):
    a = MagicMock()
    a.rule_name = rule_name
    return a


def test_score_event_no_alerts():
    mock_db = MagicMock()
    mock_db.get_risk_score.return_value = 0
    scorer = RiskScorer(mock_db)
    score = scorer.score_event("host1", [])
    assert score == 0
    mock_db.upsert_risk_score.assert_not_called()


def test_score_event_with_alerts():
    mock_db = MagicMock()
    mock_db.get_risk_score.return_value = 40
    scorer = RiskScorer(mock_db)
    alerts = [_mock_alert("unknown_device")]
    score = scorer.score_event("host1", alerts)
    mock_db.upsert_risk_score.assert_called_once_with("host1", 40)
    assert score == 40


def test_rule_weights_defined():
    assert "honeypot_device" in RULE_WEIGHTS
    assert RULE_WEIGHTS["honeypot_device"] == 100
