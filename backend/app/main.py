
import logging
import os


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



class RequestBodyLimitMiddleware:
    def __init__(self, app, max_body_bytes: int):
        if max_body_bytes <= 0:
            raise ValueError("max_body_bytes must be positive")

        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def reject(status_code: int, detail: str):
            response = JSONResponse(
                status_code=status_code,
                content={"detail": detail},
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



app.add_middleware(
    RequestBodyLimitMiddleware,
    max_body_bytes=MAX_REQUEST_BODY_BYTES,
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
