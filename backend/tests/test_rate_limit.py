import asyncio
import ipaddress
import json

import pytest
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from backend.app.main import (
    RequestBodyLimitMiddleware,
    TokenBucketRateLimiter,
    app,
    load_rate_limit_settings,
)


def invoke(
    middleware,
    *,
    path="/analyze",
    client=("192.0.2.1", 1234),
    body=b"",
    chunks=None,
):
    sent = []
    body_chunks = [body] if chunks is None else list(chunks)

    async def receive():
        if not body_chunks:
            return {"type": "http.disconnect"}
        chunk = body_chunks.pop(0)
        return {
            "type": "http.request",
            "body": chunk,
            "more_body": bool(body_chunks),
        }

    async def send(message):
        sent.append(message)

    headers = [(b"content-type", b"application/json")]
    if chunks is None:
        headers.append((b"content-length", str(len(body)).encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers,
        "client": client,
        "server": ("testserver", 80),
    }

    asyncio.run(middleware(scope, receive, send))
    status = next(
        item["status"]
        for item in sent
        if item["type"] == "http.response.start"
    )
    response_headers = {
        name.lower(): value
        for item in sent
        if item["type"] == "http.response.start"
        for name, value in item.get("headers", [])
    }
    response_body = b"".join(
        item.get("body", b"")
        for item in sent
        if item["type"] == "http.response.body"
    )
    return status, response_headers, response_body


def downstream_app():
    async def app(scope, receive, send):
        response = JSONResponse({"ok": True})
        await response(scope, receive, send)

    return app


def make_limiter(*, burst=2, refill_per_minute=60, max_client_buckets=10, clock=None):
    settings = {
        "burst": burst,
        "refill_per_minute": refill_per_minute,
        "max_client_buckets": max_client_buckets,
    }
    if clock is not None:
        settings["clock"] = clock
    return TokenBucketRateLimiter(**settings)


def configure_application_limiter(monkeypatch, *, burst=1, refill_per_minute=60):
    limiter = app.state.rate_limiter
    monkeypatch.setattr(limiter, "burst", burst)
    monkeypatch.setattr(limiter, "refill_per_second", refill_per_minute / 60.0)
    monkeypatch.setattr(
        limiter,
        "idle_expiry_seconds",
        burst / (refill_per_minute / 60.0),
    )
    limiter.reset()
    return limiter


def replay_payload():
    return {
        "events": [
            {
                "source": "user:alice",
                "target": "resource:customer-db",
                "relationship": "accesses",
                "action": "grant",
            }
        ],
        "sensitive_resources": ["resource:customer-db"],
    }


def test_analysis_paths_share_client_bucket_and_allow_requests_within_limit():
    middleware = RequestBodyLimitMiddleware(
        downstream_app(),
        max_body_bytes=1024,
        rate_limiter=make_limiter(burst=2),
    )

    assert invoke(middleware, path="/analyze")[0] == 200
    assert invoke(middleware, path="/replay")[0] == 200
    status, _headers, body = invoke(middleware, path="/analyze/permissions")

    assert status == 429
    assert json.loads(body) == {"detail": "Rate limit exceeded"}


def test_rate_limit_retry_after_is_rounded_up():
    middleware = RequestBodyLimitMiddleware(
        downstream_app(),
        max_body_bytes=1024,
        rate_limiter=make_limiter(burst=1, refill_per_minute=50),
    )

    assert invoke(middleware)[0] == 200
    status, headers, _body = invoke(middleware)

    assert status == 429
    retry_after = headers[b"retry-after"].decode("ascii")
    assert retry_after.isdigit()
    assert int(retry_after) == 2


def test_token_refill_tracks_elapsed_time_deterministically():
    current_time = [0.0]
    middleware = RequestBodyLimitMiddleware(
        downstream_app(),
        max_body_bytes=1024,
        rate_limiter=make_limiter(
            burst=2,
            refill_per_minute=60,
            clock=lambda: current_time[0],
        ),
    )

    assert invoke(middleware)[0] == 200
    assert invoke(middleware)[0] == 200
    assert invoke(middleware)[0] == 429
    current_time[0] += 1.0
    assert invoke(middleware)[0] == 200


def test_rate_limit_refills_and_expired_entries_are_reclaimed_deterministically():
    current_time = [0.0]
    limiter = make_limiter(
        burst=1,
        max_client_buckets=2,
        clock=lambda: current_time[0],
    )
    middleware = RequestBodyLimitMiddleware(
        downstream_app(),
        max_body_bytes=1024,
        rate_limiter=limiter,
    )

    assert invoke(middleware, client=("192.0.2.1", 1000))[0] == 200
    assert invoke(middleware, client=("192.0.2.1", 1000))[0] == 429
    current_time[0] += 1.0
    assert invoke(middleware, client=("192.0.2.2", 1000))[0] == 200
    assert limiter.tracked_client_count == 1
    assert limiter.bucket_count == 1
    assert ipaddress.ip_address("192.0.2.2") in limiter._buckets
    assert ipaddress.ip_address("192.0.2.1") not in limiter._buckets


def test_full_bucket_table_uses_shared_overflow_without_evicting_active_clients():
    current_time = [0.0]
    limiter = make_limiter(
        burst=1,
        max_client_buckets=2,
        clock=lambda: current_time[0],
    )
    middleware = RequestBodyLimitMiddleware(
        downstream_app(),
        max_body_bytes=1024,
        rate_limiter=limiter,
    )

    assert invoke(middleware, client=("192.0.2.1", 1000))[0] == 200
    assert limiter.tracked_client_count == 1
    assert limiter.bucket_count == 1

    # New identities share one bounded overflow bucket while the tracked IP
    # remains active; it is not evicted and cannot reset its own allowance.
    assert invoke(middleware, client=("192.0.2.2", 1000))[0] == 200
    assert limiter.bucket_count == 2
    assert invoke(middleware, client=("192.0.2.3", 1000))[0] == 429
    for last_octet in range(4, 20):
        assert invoke(
            middleware,
            client=(f"192.0.2.{last_octet}", 1000),
        )[0] == 429
        assert limiter.bucket_count == 2
    assert invoke(middleware, client=("192.0.2.1", 1000))[0] == 429
    assert limiter.tracked_client_count == 1
    assert limiter.bucket_count == 2

    # Expired tracked and overflow buckets are reclaimed without evicting a
    # still-active client; a new identity can then use a dedicated bucket.
    current_time[0] += 1.0
    assert invoke(middleware, client=("192.0.2.3", 1000))[0] == 200
    assert limiter.tracked_client_count == 1
    assert limiter.bucket_count == 1
    assert ipaddress.ip_address("192.0.2.3") in limiter._buckets


def test_capacity_one_counts_the_overflow_bucket_as_the_only_bucket():
    limiter = make_limiter(burst=2, max_client_buckets=1)
    middleware = RequestBodyLimitMiddleware(
        downstream_app(),
        max_body_bytes=1024,
        rate_limiter=limiter,
    )

    assert invoke(middleware, client=("192.0.2.1", 1000))[0] == 200
    assert invoke(middleware, client=("192.0.2.2", 1000))[0] == 200
    assert invoke(middleware, client=("192.0.2.3", 1000))[0] == 429
    assert limiter.tracked_client_count == 0
    assert limiter.bucket_count == 1


def test_independent_client_ips_have_independent_limits():
    middleware = RequestBodyLimitMiddleware(
        downstream_app(),
        max_body_bytes=1024,
        rate_limiter=make_limiter(burst=1),
    )

    assert invoke(middleware, client=("192.0.2.10", 1234))[0] == 200
    assert invoke(middleware, client=("192.0.2.10", 1234))[0] == 429
    assert invoke(middleware, client=("192.0.2.11", 1234))[0] == 200


def test_missing_or_malformed_client_address_uses_shared_fallback_bucket():
    middleware = RequestBodyLimitMiddleware(
        downstream_app(),
        max_body_bytes=1024,
        rate_limiter=make_limiter(burst=1),
    )

    assert invoke(middleware, client=None)[0] == 200
    assert invoke(middleware, client=(object(), 1234))[0] == 429


def test_health_is_available_after_real_application_client_is_limited(monkeypatch):
    configure_application_limiter(monkeypatch, burst=1)
    client = TestClient(app, client=("192.0.2.10", 1234))

    assert client.post("/replay", json=replay_payload()).status_code == 200
    limited = client.post("/replay", json=replay_payload())
    assert limited.status_code == 429
    retry_after = limited.headers["retry-after"]
    assert retry_after.isdigit() and int(retry_after) > 0
    assert limited.json() == {"detail": "Rate limit exceeded"}
    assert client.get("/health").status_code == 200


def test_real_application_keeps_clients_independent(monkeypatch):
    configure_application_limiter(monkeypatch, burst=1)
    first_client = TestClient(app, client=("192.0.2.10", 1234))
    second_client = TestClient(app, client=("192.0.2.11", 1234))

    assert first_client.post("/replay", json=replay_payload()).status_code == 200
    assert first_client.post("/replay", json=replay_payload()).status_code == 429
    assert second_client.post("/replay", json=replay_payload()).status_code == 200


def test_real_application_charges_oversized_declared_request_and_returns_413(monkeypatch):
    configure_application_limiter(monkeypatch, burst=1)
    client = TestClient(app, client=("192.0.2.12", 1234))

    oversized = client.post(
        "/replay",
        content=b"x" * (1024 * 1024 + 1),
        headers={"content-type": "application/json"},
    )
    assert oversized.status_code == 413
    assert oversized.json() == {"detail": "Request body too large"}

    # The oversized request consumed its token even though 413 takes precedence.
    limited = client.post("/replay", json=replay_payload())
    assert limited.status_code == 429
    assert limited.headers["retry-after"].isdigit()


def test_real_application_chunked_body_limit_and_rate_limit_both_apply(monkeypatch):
    configure_application_limiter(monkeypatch, burst=1)

    status, _headers, body = invoke(
        app,
        path="/replay",
        client=("192.0.2.13", 1234),
        chunks=[b"x" * 600_000, b"x" * 600_000],
    )
    assert status == 413
    assert json.loads(body) == {"detail": "Request body too large"}

    next_status, headers, _body = invoke(
        app,
        path="/replay",
        client=("192.0.2.13", 1234),
        body=json.dumps(replay_payload()).encode(),
    )
    assert next_status == 429
    assert headers[b"retry-after"].isdigit()


def test_rate_limit_settings_enforce_defaults_and_all_bounds():
    assert load_rate_limit_settings({}) == (10, 60, 10_000)

    bounds = {
        "AEGISMESH_RATE_LIMIT_BURST": 10_000,
        "AEGISMESH_RATE_LIMIT_REFILL_PER_MINUTE": 100_000,
        "AEGISMESH_RATE_LIMIT_MAX_CLIENT_BUCKETS": 100_000,
    }
    for name, maximum in bounds.items():
        for value in (
            "0",
            "-1",
            "NaN",
            "Infinity",
            "1.5",
            str(maximum + 1),
            "9" * 5000,
        ):
            with pytest.raises(RuntimeError, match=name):
                load_rate_limit_settings({name: value})


def test_limiter_reset_clears_bucket_state():
    limiter = make_limiter(burst=1)
    middleware = RequestBodyLimitMiddleware(
        downstream_app(),
        max_body_bytes=1024,
        rate_limiter=limiter,
    )

    assert invoke(middleware)[0] == 200
    assert invoke(middleware)[0] == 429
    limiter.reset()
    assert invoke(middleware)[0] == 200
