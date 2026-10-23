
import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from backend.app.api.routes import router

logger = logging.getLogger(__name__)

app = FastAPI(
    title="AegisMesh Sentinel",
    description="Security analysis and controlled remediation platform",
    version="0.1.0",
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
