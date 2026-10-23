
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


def test_prioritize_increases_risk_for_attack_path_evidence():
    result = RiskScorer().prioritize(
        base_score=20,
        unexpected_permission_count=2,
        newly_reachable_resource_count=1,
    )

    assert result["risk_score"] == 55
    assert result["severity"] == "medium"
    assert len(result["reasons"]) == 2
    assert result["requires_human_approval"] is True
    assert result["evidence"]["unexpected_permission_count"] == 2


def test_prioritize_caps_score_at_100():
    result = RiskScorer().prioritize(
        base_score=90,
        unexpected_permission_count=5,
        newly_reachable_resource_count=3,
    )

    assert result["risk_score"] == 100
    assert result["severity"] == "critical"


def test_prioritize_rejects_invalid_inputs():
    with pytest.raises(ValueError):
        RiskScorer().prioritize(base_score=-1)

    with pytest.raises(ValueError):
        RiskScorer().prioritize(base_score=101)

    with pytest.raises(ValueError):
        RiskScorer().prioritize(
            base_score=10,
            unexpected_permission_count=True,
        )

