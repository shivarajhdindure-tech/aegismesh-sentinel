
import pytest
from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


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
