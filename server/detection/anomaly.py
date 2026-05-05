"""IsolationForest anomaly detector over per-agent event windows."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import joblib  # type: ignore
    import numpy as np  # type: ignore
    from sklearn.ensemble import IsolationForest  # type: ignore

    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False


def _extract_features(events: list) -> "np.ndarray":
    """Extract feature vector from a list of Event ORM objects."""
    import numpy as np

    if not events:
        return np.array([[0, 0, 0, 0, 0]], dtype=float)

    total = len(events)
    devices = {e.device_id for e in events}
    bt_scans = sum(1 for e in events if e.source_type == "bluetooth")
    off_hours = sum(
        1
        for e in events
        if e.timestamp and (e.timestamp.hour >= 18 or e.timestamp.hour < 8)
    )
    actions = {e.action for e in events}

    return np.array(
        [
            [
                total,
                len(devices),
                bt_scans,
                off_hours / max(total, 1),
                len(actions),
            ]
        ],
        dtype=float,
    )


class AnomalyDetector:
    def __init__(
        self,
        contamination: float = 0.1,
        model_path: Optional[str] = None,
    ) -> None:
        if not _ML_AVAILABLE:
            raise ImportError(
                "scikit-learn and joblib are required for anomaly detection. "
                "Install with: pip install scikit-learn joblib"
            )
        self.contamination = contamination
        self.model_path = model_path
        self._model: Optional[IsolationForest] = None

    def train(self, all_events: list) -> None:
        """Train IsolationForest on a flat list of Event ORM objects."""
        import numpy as np

        # Group by agent_id + hour bucket
        buckets: Dict[str, list] = {}
        for e in all_events:
            if e.timestamp is None:
                continue
            key = f"{e.agent_id}_{e.timestamp.strftime('%Y%m%d%H')}"
            buckets.setdefault(key, []).append(e)

        if len(buckets) < 2:
            logger.warning("Not enough data to train anomaly model")
            return

        X = np.vstack([_extract_features(v) for v in buckets.values()])
        self._model = IsolationForest(
            contamination=self.contamination, random_state=42
        )
        self._model.fit(X)
        if self.model_path:
            joblib.dump(self._model, self.model_path)

    def predict(self, events: list) -> List[float]:
        """Return anomaly scores for a flat list of Event objects. -1=anomaly, 1=normal."""
        if self._model is None:
            raise RuntimeError("Model not trained yet.")
        import numpy as np

        X = _extract_features(events)
        return self._model.predict(X).tolist()

    def fit_or_load(self, all_events: list) -> None:
        """Load model from disk if available, otherwise train."""
        if self.model_path:
            from pathlib import Path

            if Path(self.model_path).exists():
                self._model = joblib.load(self.model_path)
                return
        self.train(all_events)

    def score_samples(self, events: list) -> List[float]:
        """Return raw anomaly scores (lower = more anomalous)."""
        if self._model is None:
            raise RuntimeError("Model not trained yet.")
        X = _extract_features(events)
        return self._model.score_samples(X).tolist()
