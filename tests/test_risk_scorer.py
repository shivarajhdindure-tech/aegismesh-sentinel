
import pytest

from ml_engine.risk_scorer import RiskScorer


def test_high_risk_event_is_scored_high():
    result = RiskScorer().score(
        anomaly_detected=True,
        failed_attempts=5,
        privilege_changes=2,
        reachable_critical_resources=2,
        off_hours=True,
    )

    assert result["risk_score"] == 85
    assert result["severity"] == "critical"
    assert len(result["reasons"]) >= 4


def test_no_risk_signals_produce_low_score():
    result = RiskScorer().score(
        anomaly_detected=False,
        failed_attempts=0,
        privilege_changes=0,
        reachable_critical_resources=0,
        off_hours=False,
    )

    assert result["risk_score"] == 0
    assert result["severity"] == "low"


def test_negative_inputs_are_rejected():
    with pytest.raises(ValueError):
        RiskScorer().score(
            anomaly_detected=False,
            failed_attempts=-1,
            privilege_changes=0,
            reachable_critical_resources=0,
            off_hours=False,
        )
