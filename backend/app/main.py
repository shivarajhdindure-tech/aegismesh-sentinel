
import ipaddress
import logging
import math
import os
import threading
import time
from collections import OrderedDict
from collections.abc import Mapping


from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from backend.app.api.routes import router

logger = logging.getLogger(__name__)

app = FastAPI(
    title="AegisMesh Sentinel",
    description="Security analysis and controlled remediation platform",
    version="0.1.0",
)


MAX_REQUEST_BODY_BYTES = int(
    os.getenv("AEGISMESH_MAX_REQUEST_BODY_BYTES", str(1024 * 1024))
)


RATE_LIMITED_PATHS = frozenset(
    {"/analyze", "/analyze/permissions", "/replay"}
)
MAX_RATE_LIMIT_BURST = 10_000
MAX_RATE_LIMIT_REFILL_PER_MINUTE = 100_000
DEFAULT_RATE_LIMIT_MAX_CLIENT_BUCKETS = 10_000
MAX_RATE_LIMIT_CLIENT_BUCKETS = 100_000


def load_rate_limit_settings(
    environ: Mapping[str, str] | None = None,
) -> tuple[int, int, int]:
    """Load bounded positive integer token-bucket settings."""
    settings = os.environ if environ is None else environ
    defaults = {
        "AEGISMESH_RATE_LIMIT_BURST": (10, MAX_RATE_LIMIT_BURST),
        "AEGISMESH_RATE_LIMIT_REFILL_PER_MINUTE": (
            60,
            MAX_RATE_LIMIT_REFILL_PER_MINUTE,
        ),
        "AEGISMESH_RATE_LIMIT_MAX_CLIENT_BUCKETS": (
            DEFAULT_RATE_LIMIT_MAX_CLIENT_BUCKETS,
            MAX_RATE_LIMIT_CLIENT_BUCKETS,
        ),
    }
    values = []
    for name, (default, maximum) in defaults.items():
        raw_value = settings.get(name, str(default))
        try:
            value = int(raw_value)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                f"{name} must be an integer between 1 and {maximum}"
            ) from exc
        if not 1 <= value <= maximum:
            raise RuntimeError(
                f"{name} must be an integer between 1 and {maximum}"
            )
        values.append(value)
    return values[0], values[1], values[2]


class TokenBucketRateLimiter:
    """Thread-safe, in-memory token buckets keyed by client IP address."""

    def __init__(
        self,
        *,
        burst: int,
        refill_per_minute: int,
        max_client_buckets: int,
        clock=time.monotonic,
    ) -> None:
        if (
            isinstance(burst, bool)
            or not isinstance(burst, int)
            or not 1 <= burst <= MAX_RATE_LIMIT_BURST
        ):
            raise ValueError(
                f"burst must be between 1 and {MAX_RATE_LIMIT_BURST}"
            )
        if (
            isinstance(refill_per_minute, bool)
            or not isinstance(refill_per_minute, int)
            or not 1 <= refill_per_minute <= MAX_RATE_LIMIT_REFILL_PER_MINUTE
        ):
            raise ValueError(
                "refill_per_minute must be between 1 and "
                f"{MAX_RATE_LIMIT_REFILL_PER_MINUTE}"
            )
        if (
            isinstance(max_client_buckets, bool)
            or not isinstance(max_client_buckets, int)
            or not 1 <= max_client_buckets <= MAX_RATE_LIMIT_CLIENT_BUCKETS
        ):
            raise ValueError(
                "max_client_buckets must be between 1 and "
                f"{MAX_RATE_LIMIT_CLIENT_BUCKETS}"
            )
        self.burst = burst
        self.refill_per_second = refill_per_minute / 60.0
        self.idle_expiry_seconds = burst / self.refill_per_second
        self.max_client_buckets = max_client_buckets
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: OrderedDict[
            ipaddress.IPv4Address | ipaddress.IPv6Address | None,
            tuple[float, float, float],
        ] = OrderedDict()
        self._overflow_bucket: tuple[float, float, float] | None = None

    def retry_after(
        self,
        client_ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None,
    ) -> int | None:
        with self._lock:
            now = self._clock()
            self._prune_expired(now)
            bucket = self._buckets.get(client_ip)

            if bucket is None and (
                self._overflow_bucket is not None
                or len(self._buckets) >= self.max_client_buckets - 1
            ):
                self._overflow_bucket, retry_after = self._consume(
                    self._overflow_bucket,
                    now,
                )
                return retry_after

            updated_bucket, retry_after = self._consume(bucket, now)
            self._buckets[client_ip] = updated_bucket
            self._buckets.move_to_end(client_ip)
            return retry_after

    def _consume(
        self,
        bucket: tuple[float, float, float] | None,
        now: float,
    ) -> tuple[tuple[float, float, float], int | None]:
        if bucket is None:
            tokens = float(self.burst)
        else:
            tokens, updated_at, _last_seen = bucket
            elapsed = max(0.0, now - updated_at)
            tokens = min(
                float(self.burst),
                tokens + elapsed * self.refill_per_second,
            )

        if tokens >= 1.0:
            return (tokens - 1.0, now, now), None

        wait_seconds = (1.0 - tokens) / self.refill_per_second
        return (tokens, now, now), max(1, math.ceil(wait_seconds))

    def _prune_expired(self, now: float) -> None:
        while self._buckets:
            _client_ip, (_tokens, _updated_at, last_seen) = next(
                iter(self._buckets.items())
            )
            if now - last_seen < self.idle_expiry_seconds:
                break
            self._buckets.popitem(last=False)
        if (
            self._overflow_bucket is not None
            and now - self._overflow_bucket[2] >= self.idle_expiry_seconds
        ):
            self._overflow_bucket = None

    @property
    def tracked_client_count(self) -> int:
        with self._lock:
            return len(self._buckets)

    @property
    def bucket_count(self) -> int:
        with self._lock:
            return len(self._buckets) + (self._overflow_bucket is not None)

    def reset(self) -> None:
        """Clear buckets for isolated tests or controlled process reset."""
        with self._lock:
            self._buckets.clear()
            self._overflow_bucket = None


def client_ip_from_scope(
    scope: dict,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return a parsed peer IP, or None for missing or unusable ASGI data."""
    try:
        client = scope.get("client")
        if not isinstance(client, (tuple, list)) or not client:
            return None
        host = client[0]
        if not isinstance(host, str) or not host.strip():
            return None
        return ipaddress.ip_address(host.strip())
    except (AttributeError, TypeError, ValueError):
        return None


class RequestBodyLimitMiddleware:
    def __init__(
        self,
        app,
        max_body_bytes: int,
        rate_limiter: TokenBucketRateLimiter | None = None,
    ):
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive")

        self.app = app
        self.max_body_bytes = max_body_bytes
        self.rate_limiter = rate_limiter

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        retry_after = None
        if (
            self.rate_limiter is not None
            and scope.get("path") in RATE_LIMITED_PATHS
        ):
            retry_after = self.rate_limiter.retry_after(
                client_ip_from_scope(scope)
            )

        async def reject(
            status_code: int,
            detail: str,
            headers: dict[str, str] | None = None,
        ):
            response = JSONResponse(
                status_code=status_code,
                content={"detail": detail},
                headers=headers,
            )
            await response(scope, receive, send)

        content_length = next(
            (
                value.decode("latin-1")
                for name, value in scope["headers"]
                if name.lower() == b"content-length"
            ),
            None,
        )

        if content_length is not None:
            try:
                size = int(content_length)
            except ValueError:
                await reject(400, "Invalid Content-Length header")
                return

            if size < 0:
                await reject(400, "Invalid Content-Length header")
                return

            if size > self.max_body_bytes:
                await reject(413, "Request body too large")
                return

        body = bytearray()

        while True:
            message = await receive()

            if message["type"] == "http.disconnect":
                return

            if message["type"] != "http.request":
                continue

            chunk = message.get("body", b"")

            if len(body) + len(chunk) > self.max_body_bytes:
                await reject(413, "Request body too large")
                return

            body.extend(chunk)

            if not message.get("more_body", False):
                break

        if retry_after is not None:
            await reject(
                429,
                "Rate limit exceeded",
                headers={"Retry-After": str(retry_after)},
            )
            return

        body_sent = False

        async def replay_receive():
            nonlocal body_sent

            if not body_sent:
                body_sent = True
                return {
                    "type": "http.request",
                    "body": bytes(body),
                    "more_body": False,
                }

            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)



(
    RATE_LIMIT_BURST,
    RATE_LIMIT_REFILL_PER_MINUTE,
    RATE_LIMIT_MAX_CLIENT_BUCKETS,
) = load_rate_limit_settings()
rate_limiter = TokenBucketRateLimiter(
    burst=RATE_LIMIT_BURST,
    refill_per_minute=RATE_LIMIT_REFILL_PER_MINUTE,
    max_client_buckets=RATE_LIMIT_MAX_CLIENT_BUCKETS,
)
app.state.rate_limiter = rate_limiter

# The body-size middleware also performs rate admission: it charges each target
# API request before reading the body, but returns 429 only after the body is
# consumed under the existing size cap. Existing 400/413 checks take precedence.
app.add_middleware(
    RequestBodyLimitMiddleware,
    max_body_bytes=MAX_REQUEST_BODY_BYTES,
    rate_limiter=rate_limiter,
)


app.include_router(router)


@app.exception_handler(Exception)
async def handle_unexpected_exception(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    logger.error(
        "Unhandled exception during %s %s",
        request.method,
        request.url.path,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "aegismesh-sentinel",
        "version": "0.1.0",
    }
