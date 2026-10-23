
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app
from unittest.mock import patch


client = TestClient(app, raise_server_exceptions=False)


def test_analyze_rejects_negative_failed_attempts(monkeypatch):
    response = client.post(
        "/analyze",
        json={
            "incident_id": "incident-api-001",
            "identity_id": "user:alice",
            "events_last_hour": 8,
            "unique_resources": 2,
            "failed_attempts": -1,
            "privilege_changes": 0,
            "off_hours": 0,
            "relationships": [],
            "sensitive_resources": [],
        },
    )

    assert response.status_code == 422


def test_analyze_rejects_invalid_off_hours():
    response = client.post(
        "/analyze",
        json={
            "incident_id": "incident-api-002",
            "identity_id": "user:alice",
            "events_last_hour": 8,
            "unique_resources": 2,
            "failed_attempts": 0,
            "privilege_changes": 0,
            "off_hours": 2,
            "relationships": [],
            "sensitive_resources": [],
        },
    )

    assert response.status_code == 422


def test_analyze_rejects_malformed_relationship():
    response = client.post(
        "/analyze",
        json={
            "incident_id": "incident-api-003",
            "identity_id": "user:alice",
            "events_last_hour": 8,
            "unique_resources": 2,
            "failed_attempts": 0,
            "privilege_changes": 0,
            "off_hours": 0,
            "relationships": [["user:alice", "role:developer"]],
            "sensitive_resources": [],
        },
    )

    assert response.status_code == 422


def test_replay_rejects_invalid_action():
    response = client.post(
        "/replay",
        json={
            "events": [
                {
                    "source": "user:alice",
                    "target": "role:developer",
                    "relationship": "assumes",
                    "action": "delete",
                }
            ],
            "sensitive_resources": [],
        },
    )

    assert response.status_code == 422


def test_replay_rejects_missing_required_relationship():
    response = client.post(
        "/replay",
        json={
            "events": [
                {
                    "source": "user:alice",
                    "target": "role:developer",
                    "action": "grant",
                }
            ],
            "sensitive_resources": [],
        },
    )

    assert response.status_code == 422


def test_analyze_accepts_valid_request():
    response = client.post(
        "/analyze",
        json={
            "incident_id": "incident-api-valid-001",
            "identity_id": "user:alice",
            "events_last_hour": 9,
            "unique_resources": 2,
            "failed_attempts": 0,
            "privilege_changes": 0,
            "off_hours": 0,
            "relationships": [
                ["user:alice", "resource:customer-db", "accesses"]
            ],
            "sensitive_resources": ["resource:customer-db"],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == "incident-api-valid-001"
    assert body["identity_id"] == "user:alice"
    assert 0 <= body["risk_score"] <= 100
    assert body["severity"] in {"low", "medium", "high", "critical"}
    assert "anomaly_detected" in body
    assert "reachable_resources" in body


def test_replay_accepts_valid_grant_request():
    response = client.post(
        "/replay",
        json={
            "events": [
                {
                    "source": "user:alice",
                    "target": "resource:customer-db",
                    "relationship": "accesses",
                    "action": "grant",
                }
            ],
            "sensitive_resources": ["resource:customer-db"],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["events_replayed"] == 1
    assert body["relationships_processed"] == 1
    assert body["summary"]["outcome_counts"]["granted"] == 1
    assert body["final_reachable_sensitive_resources"] == [
        "resource:customer-db"
    ]
    assert len(body["timeline"]) == 1
    assert body["timeline"][0]["outcome"] == "granted"


def test_health_endpoint_returns_service_status():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "aegismesh-sentinel",
        "version": "0.1.0",
    }


def test_analyze_unexpected_error_does_not_expose_internal_details():
    with patch(
        "backend.app.api.routes._pipeline.analyze",
        side_effect=RuntimeError("internal database password details"),
    ):
        response = client.post(
            "/analyze",
            json={
                "incident_id": "incident-api-error-001",
                "identity_id": "user:alice",
                "events_last_hour": 9,
                "unique_resources": 2,
                "failed_attempts": 0,
                "privilege_changes": 0,
                "off_hours": 0,
                "relationships": [],
                "sensitive_resources": [],
            },
        )

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "internal database password details" not in response.text


def test_replay_invalid_event_returns_422():
    response = client.post(
        "/replay",
        json={
            "events": [
                {
                    "source": "user:alice",
                    "target": "role:developer",
                    "relationship": "assumes",
                    "action": "invalid-action",
                }
            ],
            "sensitive_resources": [],
        },
    )

    assert response.status_code == 422


def test_replay_unexpected_error_does_not_expose_internal_details():
    with patch(
        "backend.app.api.routes.IncidentReplay.replay",
        side_effect=RuntimeError("internal storage credentials"),
    ):
        response = client.post(
            "/replay",
            json={
                "events": [
                    {
                        "source": "user:alice",
                        "target": "role:developer",
                        "relationship": "assumes",
                        "action": "grant",
                    }
                ],
                "sensitive_resources": [],
            },
        )

    assert response.status_code == 500
    assert "internal storage credentials" not in response.text


def test_analyze_unexpected_exception_returns_generic_500():
    with patch(
        "backend.app.api.routes._pipeline.analyze",
        side_effect=LookupError("sensitive internal implementation details"),
    ):
        response = client.post(
            "/analyze",
            json={
                "incident_id": "incident-api-error-002",
                "identity_id": "user:alice",
                "events_last_hour": 9,
                "unique_resources": 2,
                "failed_attempts": 0,
                "privilege_changes": 0,
                "off_hours": 0,
                "relationships": [],
                "sensitive_resources": [],
            },
        )

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "sensitive internal implementation details" not in response.text
