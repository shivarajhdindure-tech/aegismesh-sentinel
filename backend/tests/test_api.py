
from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_endpoint_returns_assessment():
    response = client.post(
        "/analyze",
        json={
            "incident_id": "incident-test-001",
            "identity_id": "user:alice",
            "events_last_hour": 500,
            "unique_resources": 80,
            "failed_attempts": 30,
            "privilege_changes": 12,
            "off_hours": 1,
            "relationships": [
                ["user:alice", "role:developer", "assumes"],
                [
                    "role:developer",
                    "resource:customer-db",
                    "accesses",
                ],
            ],
            "sensitive_resources": ["resource:customer-db"],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == "incident-test-001"
    assert body["risk_score"] >= 80
    assert body["severity"] == "critical"
    assert body["anomaly_detected"] is True
    assert body["reachable_resources"] == ["resource:customer-db"]


def test_analyze_rejects_invalid_input():
    response = client.post(
        "/analyze",
        json={
            "incident_id": "incident-invalid",
            "identity_id": "user:alice",
            "events_last_hour": -1,
            "unique_resources": 2,
            "failed_attempts": 0,
            "privilege_changes": 0,
            "off_hours": 0,
        },
    )

    assert response.status_code == 422


def test_replay_endpoint_tracks_grants_and_revocations():
    response = client.post(
        "/replay",
        json={
            "events": [
                {
                    "source": "user:alice",
                    "target": "role:developer",
                    "relationship": "assumes",
                    "action": "grant",
                },
                {
                    "source": "role:developer",
                    "target": "resource:customer-db",
                    "relationship": "accesses",
                    "action": "grant",
                },
                {
                    "source": "role:developer",
                    "target": "resource:customer-db",
                    "relationship": "accesses",
                    "action": "revoke",
                },
            ],
            "sensitive_resources": ["resource:customer-db"],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["events_replayed"] == 3
    assert body["timeline"][1]["reachable_sensitive_resources"] == [
        "resource:customer-db"
    ]
    assert body["timeline"][2]["reachable_sensitive_resources"] == []
    assert body["final_reachable_sensitive_resources"] == []


def test_replay_endpoint_rejects_invalid_action():
    response = client.post(
        "/replay",
        json={
            "events": [
                {
                    "source": "user:alice",
                    "target": "role:developer",
                    "relationship": "assumes",
                    "action": "delete-everything",
                }
            ]
        },
    )

    assert response.status_code == 422


def test_replay_endpoint_rejects_empty_events():
    response = client.post(
        "/replay",
        json={"events": []},
    )

    assert response.status_code == 422
