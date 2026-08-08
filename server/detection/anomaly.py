"""
server/detection/anomaly.py – ML-based anomaly detection for ITDN events.

Uses sklearn IsolationForest when available; falls back to z-score statistics.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import IsolationForest as _IsolationForest  # type: ignore
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False
    logger.debug("scikit-learn not available; using z-score fallback for anomaly detection")


_AFTER_HOURS_START = 22
_AFTER_HOURS_END = 6


def _is_after_hours(hour: int) -> float:
    return 1.0 if (hour >= _AFTER_HOURS_START or hour < _AFTER_HOURS_END) else 0.0


def extract_features(events: List[Dict[str, Any]]) -> List[List[float]]:
    """
    Extract feature vectors from a list of events.

    Features per event: [event_count_last_hour, unique_devices_last_hour,
                         transfer_bytes_last_hour, hour_of_day, is_after_hours]
    """
    if not events:
        return []

    feature_list: List[List[float]] = []
    event_count = len(events)
    unique_devices = len({e.get("device_id", "") for e in events})
    total_bytes = sum(int(e.get("transfer_bytes", 0)) for e in events)

    for event in events:
        ts_str = event.get("timestamp", "")
        try:
            ts = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")
            hour = ts.hour
        except (ValueError, TypeError):
            hour = datetime.now(timezone.utc).hour
        feature_list.append([
            float(event_count),
            float(unique_devices),
            float(total_bytes),
            float(hour),
            _is_after_hours(hour),
        ])

    return feature_list


class AnomalyDetector:
    """
    Detects anomalous USB/BT activity using IsolationForest (or z-score fallback).
    """

    def __init__(self) -> None:
        self._model: Any = None
        self._fitted = False
        self._training_features: List[List[float]] = []

    def fit(self, events: List[Dict[str, Any]]) -> None:
        """Train the anomaly detector on historical events."""
        features = extract_features(events)
        if not features:
            return
        self._training_features = features
        if _SKLEARN_AVAILABLE and len(features) >= 10:
            self._model = _IsolationForest(contamination=0.1, random_state=42)
            self._model.fit(features)
            self._fitted = True
        else:
            self._fitted = bool(features)

    def score(self, event: Dict[str, Any], recent_events: List[Dict[str, Any]]) -> float:
        """
        Return anomaly score in range [-1, 1].
        -1 = highly anomalous, 1 = normal.
        """
        all_events = recent_events + [event]
        features = extract_features(all_events)
        if not features:
            return 0.0

        current_feature = features[-1]

        if _SKLEARN_AVAILABLE and self._fitted and self._model is not None:
            try:
                score = self._model.score_samples([current_feature])[0]
                return float(max(-1.0, min(1.0, score)))
            except Exception:
                pass

        return self._zscore_anomaly(current_feature)

    def _zscore_anomaly(self, feature: List[float]) -> float:
        """Simple z-score based anomaly score using training data statistics."""
        if not self._training_features:
            return 0.0
        n_features = len(feature)
        scores: List[float] = []
        for i in range(n_features):
            vals = [f[i] for f in self._training_features]
            mean = sum(vals) / len(vals)
            variance = sum((v - mean) ** 2 for v in vals) / len(vals)
            std = math.sqrt(variance) if variance > 0 else 1.0
            z = abs(feature[i] - mean) / std if std else 0.0
            scores.append(z)
        avg_z = sum(scores) / len(scores) if scores else 0.0
        normalized = 1.0 - min(2.0, avg_z) / 1.0
        return float(max(-1.0, min(1.0, normalized)))
