
import pytest

from ml_engine.anomaly_detector import AccessAnomalyDetector


def test_detector_finds_unusual_access_pattern():
    detector = AccessAnomalyDetector(contamination=0.1)

    baseline = [
        {
            "events_last_hour": 8 + (i % 3),
            "unique_resources": 2 + (i % 2),
            "failed_attempts": i % 2,
            "privilege_changes": 0,
            "off_hours": 0,
        }
        for i in range(30)
    ]

    detector.fit(baseline)

    unusual_event = {
        "events_last_hour": 500,
        "unique_resources": 80,
        "failed_attempts": 30,
        "privilege_changes": 12,
        "off_hours": 1,
    }

    result = detector.predict(unusual_event)

    assert result["is_anomaly"] is True
    assert result["model"] == "IsolationForest+RobustOutlierGuard"
    assert 0 <= result["features"]["off_hours"] <= 1


def test_prediction_requires_fitted_model():
    detector = AccessAnomalyDetector()

    event = {
        "events_last_hour": 8,
        "unique_resources": 2,
        "failed_attempts": 0,
        "privilege_changes": 0,
        "off_hours": 0,
    }

    with pytest.raises(RuntimeError):
        detector.predict(event)


def test_missing_features_are_rejected():
    detector = AccessAnomalyDetector()

    with pytest.raises(ValueError):
        detector.fit([{"events_last_hour": 3}])
