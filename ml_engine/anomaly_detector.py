
from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest


class AccessAnomalyDetector:
    """Detect unusual access-event patterns using Isolation Forest."""

    FEATURES = [
        "events_last_hour",
        "unique_resources",
        "failed_attempts",
        "privilege_changes",
        "off_hours",
    ]

    def __init__(
        self,
        contamination: float = 0.1,
        random_state: int = 42,
    ) -> None:
        if not 0 < contamination <= 0.5:
            raise ValueError("contamination must be between 0 and 0.5")

        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100,
        )
        self._fitted = False

    def fit(self, events: list[dict[str, Any]]) -> None:
        """Fit on a baseline of representative access events."""
        X = self._features(events)

        if len(X) < 10:
            raise ValueError("At least 10 baseline events are required")

        self.model.fit(X)
        self._training_features = X.copy()
        self._fitted = True


    def predict(self, event: dict[str, Any]) -> dict[str, Any]:
        """Flag unusual access patterns; never authorize remediation."""
        if not self._fitted:
            raise RuntimeError("Call fit() with baseline events first")

        X = self._features([event])
        prediction = int(self.model.predict(X)[0])
        score = float(self.model.decision_function(X)[0])

        # Explicit guardrail for extreme values relative to the baseline.
        baseline = self._training_features
        median = np.median(baseline, axis=0)
        mad = np.median(np.abs(baseline - median), axis=0)

        # Avoid division by zero for constant baseline features.
        scale = np.where(mad > 0, 1.4826 * mad, 1.0)
        deviations = np.abs(X[0] - median) / scale
        extreme_outlier = bool(np.any(deviations >= 8.0))

        is_anomaly = prediction == -1 or extreme_outlier

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(-score, 6),
            "extreme_outlier": extreme_outlier,
            "model": "IsolationForest+RobustOutlierGuard",
            "model_version": "0.2.0",
            "features": {
                name: event[name] for name in self.FEATURES
            },
        }


    @classmethod
    def _features(cls, events: list[dict[str, Any]]) -> np.ndarray:
        if not events:
            raise ValueError("At least one event is required")

        rows = []
        for index, event in enumerate(events):
            missing = [key for key in cls.FEATURES if key not in event]
            if missing:
                raise ValueError(
                    f"Event {index} is missing features: {missing}"
                )

            row = []
            for key in cls.FEATURES:
                value = event[key]
                if isinstance(value, bool) or not isinstance(
                    value, (int, float)
                ):
                    raise ValueError(f"{key} must be numeric")
                if not np.isfinite(value) or value < 0:
                    raise ValueError(
                        f"{key} must be finite and non-negative"
                    )
                row.append(float(value))

            rows.append(row)

        return np.asarray(rows, dtype=float)
