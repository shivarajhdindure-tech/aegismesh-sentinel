
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class RiskAssessment(BaseModel):
    """Standard output shared by the ML engine and backend."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(min_length=1)
    identity_id: str = Field(min_length=1)

    risk_score: int = Field(ge=0, le=100)
    severity: Literal["low", "medium", "high", "critical"]

    anomaly_detected: bool
    reachable_resources: list[str] = Field(default_factory=list)
    attack_path: list[str] | None = None

    reasons: list[str] = Field(default_factory=list)
    model_version: str

    evidence: dict[str, Any] = Field(default_factory=dict)
