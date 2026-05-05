"""Tests for IsolationForest anomaly detector."""
import pytest

pytest.importorskip("sklearn", reason="scikit-learn required")

from datetime import datetime, timezone

from server.detection.anomaly import AnomalyDetector, _extract_features


class _FakeEvent:
    def __init__(self, agent_id, device_id, source_type, action, hour):
        self.agent_id = agent_id
        self.device_id = device_id
        self.source_type = source_type
        self.action = action
        self.timestamp = datetime(2024, 1, 1, hour, 0, 0, tzinfo=timezone.utc)


def _make_events(n=50, hour=10):
    return [_FakeEvent("a1", f"dev{i%5}", "usb", "connect", hour) for i in range(n)]


def test_extract_features_shape():
    import numpy as np

    events = _make_events(20, hour=10)
    X = _extract_features(events)
    assert X.shape == (1, 5)


def test_empty_features():
    import numpy as np

    X = _extract_features([])
    assert X.shape == (1, 5)


def test_train_and_predict():
    det = AnomalyDetector(contamination=0.1)
    # Build enough buckets (need >= 2)
    events = []
    for day in range(5):
        for hour in range(8):
            events.extend(
                [
                    _FakeEvent(
                        "a1",
                        f"dev{i}",
                        "usb",
                        "connect",
                        hour,
                    )
                    for i in range(3)
                ]
            )
            # Vary timestamp date by changing agent_id to create different keys
            events[-1].timestamp = datetime(2024, 1, day + 1, hour, 0, 0, tzinfo=timezone.utc)

    det.train(events)
    preds = det.predict(_make_events(10))
    assert len(preds) == 1
    assert preds[0] in (1, -1)


def test_predict_without_training_raises():
    det = AnomalyDetector()
    with pytest.raises(RuntimeError):
        det.predict(_make_events(5))


def test_score_samples():
    det = AnomalyDetector(contamination=0.1)
    events = []
    for day in range(5):
        for hour in range(8):
            ev = _FakeEvent("a1", f"dev{day}", "usb", "connect", hour)
            ev.timestamp = datetime(2024, 1, day + 1, hour, 0, 0, tzinfo=timezone.utc)
            events.extend([ev] * 3)
    det.train(events)
    scores = det.score_samples(_make_events(5))
    assert len(scores) == 1
    assert isinstance(scores[0], float)
