"""Tests for anomaly detector."""
from __future__ import annotations
from server.detection.anomaly import AnomalyDetector, extract_features


def _make_events(n, hour=14, transfer_bytes=0):
    return [
        {
            "event_type": "connected",
            "device_id": f"1234:{i:04d}",
            "hostname": "host1",
            "timestamp": f"2024-01-01T{hour:02d}:00:00Z",
            "transfer_bytes": transfer_bytes,
        }
        for i in range(n)
    ]


def test_extract_features_empty():
    assert extract_features([]) == []


def test_extract_features_non_empty():
    events = _make_events(3, hour=14)
    features = extract_features(events)
    assert len(features) == 3
    assert features[0][0] == 3.0  # event_count
    assert features[0][3] == 14.0  # hour


def test_anomaly_detector_score_no_training():
    det = AnomalyDetector()
    events = _make_events(5)
    score = det.score(events[0], events[1:])
    assert -1.0 <= score <= 1.0


def test_anomaly_detector_fit_and_score():
    det = AnomalyDetector()
    training = _make_events(20, hour=10)
    det.fit(training)
    recent = _make_events(5, hour=10)
    score = det.score(recent[0], recent[1:])
    assert -1.0 <= score <= 1.0
