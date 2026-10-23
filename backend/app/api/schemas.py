
from pydantic import BaseModel, ConfigDict, Field


class AccessEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1, max_length=128)
    identity_id: str = Field(min_length=1, max_length=256)

    events_last_hour: int = Field(ge=0, le=1_000_000)
    unique_resources: int = Field(ge=0, le=100_000)
    failed_attempts: int = Field(ge=0, le=100_000)
    privilege_changes: int = Field(ge=0, le=100_000)
    off_hours: int = Field(ge=0, le=1)

    # Graph relationships are supplied as source/target/type triples.
    relationships: list[tuple[str, str, str]] = Field(
        default_factory=list,
        max_length=5000,
    )
    sensitive_resources: list[str] = Field(
        default_factory=list,
        max_length=1000,
    )
