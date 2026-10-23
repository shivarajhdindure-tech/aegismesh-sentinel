
from fastapi.testclient import TestClient
from unittest.mock import patch

from backend.app.main import app

client = TestClient(app)


def permission_risk_payload():
    return {
        "incident_id": "incident-permission-001",
        "identity_id": "user:alice",
        "events_last_hour": 9,
        "unique_resources": 2,
        "failed_attempts": 0,
        "privilege_changes": 0,
        "off_hours": 0,
        "relationships": [["user:alice", "role:developer", "assumes"]],
        "sensitive_resources": ["resource:customer-db"],
        "expected_permissions": [
            {
                "identity": "user:alice",
                "resource": "role:developer",
                "action": "assumes",
            }
        ],
        "observed_permissions": [
            {
                "identity": "user:alice",
                "resource": "role:developer",
                "action": "assumes",
            },
            {
                "identity": "user:alice",
                "resource": "resource:customer-db",
                "action": "read",
            },
        ],
        "candidate_relationship": {
            "source": "role:developer",
            "target": "resource:customer-db",
            "relationship": "can_read",
        },
    }


def test_permission_risk_endpoint_returns_drift_and_simulated_path():
    from backend.app.api import routes

    with patch.object(
        routes._pipeline,
        "analyze_permission_risk",
        wraps=routes._pipeline.analyze_permission_risk,
    ) as analyze:
        response = client.post(
            "/analyze/permissions",
            json=permission_risk_payload(),
        )

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == "incident-permission-001"
    assert body["evidence"]["permission_drift"]["finding_count"] == 1
    assert body["evidence"]["permission_drift"]["findings"][0]["finding"] == (
        "unexpected_permission"
    )
    assert body["evidence"]["candidate_attack_path_simulation_only"] is True
    candidate_path = body["evidence"]["candidate_attack_path"]
    assert candidate_path["creates_new_attack_path"] is True
    assert candidate_path["newly_reachable_sensitive_resources"] == [
        "resource:customer-db"
    ]
    assert candidate_path["paths"]["resource:customer-db"] == [
        "user:alice",
        "role:developer",
        "resource:customer-db",
    ]

    # Candidate relationships are analyzed on a copy; the input graph is unchanged.
    graph = analyze.call_args.kwargs["attack_graph"]
    assert not graph.graph.has_edge("role:developer", "resource:customer-db")


def test_permission_risk_endpoint_rejects_invalid_inputs():
    payload = permission_risk_payload()
    payload["failed_attempts"] = -1
    response = client.post("/analyze/permissions", json=payload)
    assert response.status_code == 422

    payload = permission_risk_payload()
    del payload["observed_permissions"][0]["action"]
    response = client.post("/analyze/permissions", json=payload)
    assert response.status_code == 422

    payload = permission_risk_payload()
    payload["unexpected"] = True
    response = client.post("/analyze/permissions", json=payload)
    assert response.status_code == 422


def test_permission_risk_endpoint_bounds_relationship_and_resource_strings():
    payload = permission_risk_payload()
    payload["relationships"] = [["i" * 257, "role:developer", "assumes"]]
    response = client.post("/analyze/permissions", json=payload)
    assert response.status_code == 422

    payload = permission_risk_payload()
    payload["relationships"] = [["user:alice", "r" * 257, "assumes"]]
    response = client.post("/analyze/permissions", json=payload)
    assert response.status_code == 422

    payload = permission_risk_payload()
    payload["relationships"] = [["user:alice", "role:developer", "a" * 129]]
    response = client.post("/analyze/permissions", json=payload)
    assert response.status_code == 422

    payload = permission_risk_payload()
    payload["sensitive_resources"] = ["r" * 257]
    response = client.post("/analyze/permissions", json=payload)
    assert response.status_code == 422


def test_permission_risk_endpoint_hides_unexpected_error_details():
    from backend.app.api import routes

    with patch.object(
        routes._pipeline,
        "analyze_permission_risk",
        side_effect=RuntimeError("sensitive internal implementation detail"),
    ):
        response = client.post(
            "/analyze/permissions",
            json=permission_risk_payload(),
        )

    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "sensitive internal implementation detail" not in response.text


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


def test_api_rejects_oversized_request_body():
    response = client.post(
        "/replay",
        content=b"x" * (1024 * 1024 + 1),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}


def test_api_rejects_oversized_chunked_request_body():

    from backend.app.main import RequestBodyLimitMiddleware

    async def downstream_app(scope, receive, send):
        # The downstream app must not be called for oversized requests.
        raise AssertionError("Oversized request reached the application")

    middleware = RequestBodyLimitMiddleware(
        downstream_app,
        max_body_bytes=8,
    )

    async def run_test():
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/test",
            "raw_path": b"/test",
            "query_string": b"",
            "headers": [(b"content-type", b"application/json")],
            "client": ("testclient", 123),
            "server": ("testserver", 80),
        }

        chunks = [
            {
                "type": "http.request",
                "body": b'{"a":',
                "more_body": True,
            },
            {
                "type": "http.request",
                "body": b'"123"}',
                "more_body": False,
            },
        ]

        async def receive():
            return chunks.pop(0)

        sent = []

        async def send(message):
            sent.append(message)

        await middleware(scope, receive, send)

        assert sent[0]["status"] == 413
        assert b"".join(
            message.get("body", b"")
            for message in sent
            if message["type"] == "http.response.body"
        ) == b'{"detail":"Request body too large"}'

    import asyncio

    asyncio.run(run_test())
