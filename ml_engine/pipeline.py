
from __future__ import annotations

from typing import Any, Iterable

from contracts.risk_assessment import RiskAssessment
from ml_engine.anomaly_detector import AccessAnomalyDetector
from ml_engine.attack_graph import AttackGraph
from ml_engine.risk_scorer import RiskScorer
from ml_engine.permission_drift import PermissionDriftDetector


class SecurityAnalysisPipeline:
    """Combine anomaly detection, graph analysis, and risk scoring."""

    def __init__(
        self,
        anomaly_detector: AccessAnomalyDetector,
        risk_scorer: RiskScorer | None = None,
        permission_drift_detector: PermissionDriftDetector | None = None,
    ) -> None:
        self.anomaly_detector = anomaly_detector
        self.risk_scorer = risk_scorer or RiskScorer()
        self.permission_drift_detector = (
            permission_drift_detector or PermissionDriftDetector()
        )

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

    def analyze_permission_risk(
        self,
        *,
        incident_id: str,
        identity_id: str,
        event: dict[str, Any],
        attack_graph: AttackGraph,
        sensitive_resources: list[str],
        expected_permissions: list[dict[str, Any]],
        observed_permissions: list[dict[str, Any]],
        candidate_relationship: dict[str, str] | None = None,
    ) -> RiskAssessment:
        """Combine behavioral, permission-drift, and attack-path evidence."""

        drift = self.permission_drift_detector.detect(
            expected_permissions,
            observed_permissions,
        )

        path_analysis = None
        newly_reachable_count = 0

        if candidate_relationship is not None:
            path_analysis = self.permission_drift_detector.analyze_attack_path(
                graph=attack_graph,
                identity_id=identity_id,
                source=candidate_relationship["source"],
                target=candidate_relationship["target"],
                relationship=candidate_relationship["relationship"],
                sensitive_resources=sensitive_resources,
            )
            newly_reachable_count = len(
                path_analysis["newly_reachable_sensitive_resources"]
            )

        anomaly = self.anomaly_detector.predict(event)

        reachable_resources = attack_graph.reachable_resources(
            identity_id,
            sensitive_resources,
        )

        paths = [
            attack_graph.shortest_path(identity_id, resource)
            for resource in reachable_resources
        ]
        paths = [path for path in paths if path is not None]
        attack_path = min(paths, key=len) if paths else None

        base_risk = self.risk_scorer.score(
            anomaly_detected=anomaly["is_anomaly"],
            failed_attempts=event["failed_attempts"],
            privilege_changes=event["privilege_changes"],
            reachable_critical_resources=len(reachable_resources),
            off_hours=bool(event["off_hours"]),
        )

        prioritized = self.risk_scorer.prioritize(
            base_score=base_risk["risk_score"],
            unexpected_permission_count=drift["finding_count"],
            newly_reachable_resource_count=newly_reachable_count,
        )

        reasons = list(base_risk["reasons"])
        reasons.extend(prioritized["reasons"])

        return RiskAssessment(
            incident_id=incident_id,
            identity_id=identity_id,
            risk_score=prioritized["risk_score"],
            severity=prioritized["severity"],
            anomaly_detected=anomaly["is_anomaly"],
            reachable_resources=reachable_resources,
            attack_path=attack_path,
            reasons=reasons,
            model_version=(
                f"{anomaly['model_version']}+"
                f"{base_risk['model_version']}"
            ),
            evidence={
                "anomaly_score": anomaly["anomaly_score"],
                "extreme_outlier": anomaly["extreme_outlier"],
                "permission_drift": drift,
                "candidate_attack_path": path_analysis,
                "risk_prioritization": prioritized,
            },
        )