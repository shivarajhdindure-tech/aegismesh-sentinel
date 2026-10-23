
from __future__ import annotations

from typing import Any, Iterable

from contracts.risk_assessment import RiskAssessment
from ml_engine.anomaly_detector import AccessAnomalyDetector
from ml_engine.attack_graph import AttackGraph
from ml_engine.risk_scorer import RiskScorer


class SecurityAnalysisPipeline:
    """Combine anomaly detection, graph analysis, and risk scoring."""

    def __init__(
        self,
        anomaly_detector: AccessAnomalyDetector,
        risk_scorer: RiskScorer | None = None,
    ) -> None:
        self.anomaly_detector = anomaly_detector
        self.risk_scorer = risk_scorer or RiskScorer()

    def analyze(
        self,
        *,
        incident_id: str,
        identity_id: str,
        event: dict[str, Any],
        attack_graph: AttackGraph,
        sensitive_resources: Iterable[str],
    ) -> RiskAssessment:
        anomaly = self.anomaly_detector.predict(event)

        resources = attack_graph.reachable_resources(
            identity_id,
            sensitive_resources,
        )

        paths = [
            attack_graph.shortest_path(identity_id, resource)
            for resource in resources
        ]
        paths = [path for path in paths if path is not None]
        attack_path = min(paths, key=len) if paths else None

        risk = self.risk_scorer.score(
            anomaly_detected=anomaly["is_anomaly"],
            failed_attempts=event["failed_attempts"],
            privilege_changes=event["privilege_changes"],
            reachable_critical_resources=len(resources),
            off_hours=bool(event["off_hours"]),
        )

        return RiskAssessment(
            incident_id=incident_id,
            identity_id=identity_id,
            risk_score=risk["risk_score"],
            severity=risk["severity"],
            anomaly_detected=anomaly["is_anomaly"],
            reachable_resources=resources,
            attack_path=attack_path,
            reasons=risk["reasons"],
            model_version=(
                f"{anomaly['model_version']}+{risk['model_version']}"
            ),
            evidence={
                "anomaly_score": anomaly["anomaly_score"],
                "extreme_outlier": anomaly["extreme_outlier"],
                "risk_model": risk["model_version"],
            },
        )
