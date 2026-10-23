
from fastapi import FastAPI

from backend.app.api.routes import router

app = FastAPI(
    title="AegisMesh Sentinel",
    description="Security analysis and controlled remediation platform",
    version="0.1.0",
)

app.include_router(router)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "aegismesh-sentinel",
        "version": "0.1.0",
    }
