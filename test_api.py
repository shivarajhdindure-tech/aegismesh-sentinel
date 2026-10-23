
from fastapi.testclient import TestClient
import uuid
from backend.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_list_events():
    response = client.get("/events")

    assert response.status_code == 200
    assert "events" in response.json()


def test_create_event():
    response = client.post(
        "/events",
        json={
            "event_id": f"PYTEST-EVENT-{uuid.uuid4().hex}",
            "identity_id": "PYTEST-USER-001",
            "application": "Test SaaS",
            "permission": "read",
        },
    )

    assert response.status_code == 200
    assert response.json()["event_id"].startswith("PYTEST-EVENT-")


def test_duplicate_event_id():
    event = {
        "event_id": f"PYTEST-DUPLICATE-{uuid.uuid4().hex}",
        "identity_id": "PYTEST-USER-002",
        "application": "Test SaaS",
        "permission": "admin",
    }

    first_response = client.post("/events", json=event)
    second_response = client.post("/events", json=event)

    assert first_response.status_code == 200
    assert second_response.status_code == 409
