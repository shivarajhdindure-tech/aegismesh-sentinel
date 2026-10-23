
import json

import pytest

from ml_engine.baseline_loader import load_baseline, train_detector


def valid_event():
    return {
        "events_last_hour": 8,
        "unique_resources": 2,
        "failed_attempts": 0,
        "privilege_changes": 0,
        "off_hours": 0,
    }


def test_load_valid_baseline(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(
        json.dumps([valid_event() for _ in range(10)]),
        encoding="utf-8",
    )

    events = load_baseline(path)

    assert len(events) == 10


def test_reject_baseline_with_too_few_events(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps([valid_event() for _ in range(9)]))

    with pytest.raises(ValueError, match="At least 10"):
        load_baseline(path)


def test_reject_invalid_json(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text("{invalid json", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid JSON"):
        load_baseline(path)


def test_reject_missing_features(tmp_path):
    path = tmp_path / "baseline.json"
    event = valid_event()
    del event["failed_attempts"]
    path.write_text(json.dumps([event for _ in range(10)]))

    with pytest.raises(ValueError, match="missing features"):
        load_baseline(path)


def test_train_detector_from_baseline(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(
        json.dumps([valid_event() for _ in range(10)]),
        encoding="utf-8",
    )

    detector = train_detector(path)

    result = detector.predict(valid_event())

    assert "is_anomaly" in result
    assert "anomaly_score" in result
