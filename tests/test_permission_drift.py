
import pytest

from ml_engine.permission_drift import PermissionDriftDetector
from ml_engine.attack_graph import AttackGraph


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


def test_candidate_permission_identifies_new_sensitive_attack_path():
    detector = PermissionDriftDetector()
    graph = AttackGraph()

    graph.add_relationship(
        "user:alice", "role:developer", "assumes"
    )

    result = detector.analyze_attack_path(
        graph=graph,
        identity_id="user:alice",
        source="role:developer",
        target="resource:customer-db",
        relationship="can_read",
        sensitive_resources=["resource:customer-db"],
    )

    assert result["creates_new_attack_path"] is True
    assert result["newly_reachable_sensitive_resources"] == [
        "resource:customer-db"
    ]
    assert result["paths"]["resource:customer-db"] == [
        "user:alice",
        "role:developer",
        "resource:customer-db",
    ]

    # Analysis must not mutate the original graph.
    assert not graph.graph.has_edge(
        "role:developer", "resource:customer-db"
    )



def test_candidate_permission_does_not_report_existing_attack_path_as_new():
    detector = PermissionDriftDetector()
    graph = AttackGraph()

    graph.add_relationship(
        "user:alice", "role:developer", "assumes"
    )
    graph.add_relationship(
        "role:developer", "resource:customer-db", "can_read"
    )

    result = detector.analyze_attack_path(
        graph=graph,
        identity_id="user:alice",
        source="role:developer",
        target="resource:customer-db",
        relationship="can_read",
        sensitive_resources=["resource:customer-db"],
    )

    assert result["creates_new_attack_path"] is False
    assert result["newly_reachable_sensitive_resources"] == []
    assert result["paths"] == {}
