
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from pymongo.errors import DuplicateKeyError, PyMongoError

from backend.database import security_events

app = FastAPI(title="AegisMesh Sentinel API")


class SecurityEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=100)
    identity_id: str = Field(min_length=1, max_length=100)
    application: str = Field(min_length=1, max_length=100)
    permission: str = Field(min_length=1, max_length=100)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "AegisMesh Sentinel Backend",
    }


@app.post("/events")
def create_event(event: SecurityEvent):
    document = event.model_dump()
    document["timestamp"] = datetime.now(timezone.utc)
    document["synthetic"] = True
    try:
        security_events.insert_one(document)
        return {
            "message": "Security event saved successfully",
            "event_id": event.event_id
        }
    except DuplicateKeyError:
        raise HTTPException(
            status_code=409,
            detail="A security event with this event_id already exists"
        )
    except PyMongoError:
        raise HTTPException(
            status_code=503,
            detail="Unable to save the security event"
        )
