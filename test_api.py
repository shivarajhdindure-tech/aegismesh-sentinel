
import uuid
from contextlib import asynccontextmanager
from unittest.mock import patch, MagicMock

from fastapi.testclient import TestClient
from backend.main import app


@asynccontextmanager
async def lifespan_for_tests(app):
    yield


app.router.lifespan_context = lifespan_for_tests
client = TestClient(app)


def test_health_check():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


@patch("backend.main.security_events")
def test_list_events(mock_collection):
    mock_collection.find.return_value.sort.return_value.limit.return_value = []

    response = client.get("/events")

    assert response.status_code == 200
    assert response.json() == {"events": []}


@patch("backend.main.security_events")
def test_create_event(mock_collection):
    event_id = f"PYTEST-EVENT-{uuid.uuid4().hex}"

    response = client.post(
        "/events",
        json={
            "event_id": event_id,
            "identity_id": "PYTEST-USER-001",
            "application": "Test SaaS",
            "permission": "read",
        },
    )

    assert response.status_code == 200
    assert response.json()["event_id"] == event_id
    mock_collection.insert_one.assert_called_once()


@patch("backend.main.security_events")
def test_duplicate_event_id(mock_collection):
    from pymongo.errors import DuplicateKeyError

    mock_collection.insert_one.side_effect = [
        MagicMock(),
        DuplicateKeyError("Duplicate event_id"),
    ]

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
