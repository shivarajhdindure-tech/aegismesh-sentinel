
import pytest
from pydantic import ValidationError

from contracts.risk_assessment import RiskAssessment


def test_valid_risk_assessment():
    result = RiskAssessment(
        incident_id="incident-001",
        identity_id="user:alice",
        risk_score=85,
        severity="critical",
        anomaly_detected=True,
        reachable_resources=["resource:customer-db"],
        attack_path=[
            "user:alice",
            "role:developer",
            "resource:customer-db",
        ],
        reasons=["Unusual access pattern detected"],
        model_version="0.1.0",
    )

    assert result.risk_score == 85
    assert result.severity == "critical"


def test_invalid_risk_score_is_rejected():
    with pytest.raises(ValidationError):
        RiskAssessment(
            incident_id="incident-001",
            identity_id="user:alice",
            risk_score=150,
            severity="critical",
            anomaly_detected=True,
            model_version="0.1.0",
        )


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError):
        RiskAssessment(
            incident_id="incident-001",
            identity_id="user:alice",
            risk_score=10,
            severity="low",
            anomaly_detected=False,
            model_version="0.1.0",
            unexpected_field="not allowed",
        )
