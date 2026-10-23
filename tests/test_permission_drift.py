
import pytest

from ml_engine.permission_drift import PermissionDriftDetector


def test_detects_unexpected_permission():
    detector = PermissionDriftDetector()

    result = detector.detect(
        expected_permissions=[
            {
                "identity": "user:alice",
                "resource": "resource:customer-db",
                "action": "read",
            }
        ],
        observed_permissions=[
            {
                "identity": "user:alice",
                "resource": "resource:customer-db",
                "action": "read",
            },
            {
                "identity": "user:alice",
                "resource": "resource:customer-db",
                "action": "delete",
            },
        ],
    )

    assert result["drift_detected"] is True
    assert result["finding_count"] == 1
    assert result["findings"][0]["action"] == "delete"
    assert result["findings"][0]["finding"] == "unexpected_permission"
    assert result["findings"][0]["severity"] == "high"


def test_no_drift_when_permissions_match():
    detector = PermissionDriftDetector()

    permissions = [
        {
            "identity": "user:alice",
            "resource": "resource:customer-db",
            "action": "read",
        }
    ]

    result = detector.detect(permissions, permissions)

    assert result["drift_detected"] is False
    assert result["finding_count"] == 0
    assert result["findings"] == []


def test_duplicate_unexpected_permissions_are_reported_once():
    detector = PermissionDriftDetector()

    unexpected = {
        "identity": "user:alice",
        "resource": "resource:customer-db",
        "action": "delete",
    }

    result = detector.detect([], [unexpected, unexpected])

    assert result["finding_count"] == 1


def test_rejects_missing_permission_fields():
    detector = PermissionDriftDetector()

    with pytest.raises(ValueError, match="resource"):
        detector.detect(
            [],
            [{"identity": "user:alice", "action": "read"}],
        )


def test_rejects_non_list_permissions():
    detector = PermissionDriftDetector()

    with pytest.raises(ValueError, match="must be a list"):
        detector.detect([], None)
