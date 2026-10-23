
from __future__ import annotations

from typing import Any


class RiskScorer:
    """Combine security signals into an explainable 0–100 risk score."""

    MODEL_VERSION = "0.1.0"

    def score(
        self,
        *,
        anomaly_detected: bool,
        failed_attempts: int,
        privilege_changes: int,
        reachable_critical_resources: int,
        off_hours: bool,
    ) -> dict[str, Any]:
        values = {
            "failed_attempts": failed_attempts,
            "privilege_changes": privilege_changes,
            "reachable_critical_resources": reachable_critical_resources,
        }

        for name, value in values.items():
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            if value < 0:
                raise ValueError(f"{name} cannot be negative")

        score = 0
        reasons: list[str] = []

        if anomaly_detected:
            score += 25
            reasons.append("Unusual access pattern detected")

        if failed_attempts:
            points = min(failed_attempts * 3, 20)
            score += points
            reasons.append(
                f"{failed_attempts} failed access attempt(s)"
            )

        if privilege_changes:
            points = min(privilege_changes * 10, 30)
            score += points
            reasons.append(
                f"{privilege_changes} privilege change(s)"
            )

        if reachable_critical_resources:
            points = min(reachable_critical_resources * 10, 20)
            score += points
            reasons.append(
                f"{reachable_critical_resources} critical resource(s) reachable"
            )

        if off_hours:
            score += 5
            reasons.append("Access occurred outside expected hours")

        score = min(score, 100)

        if score >= 80:
            severity = "critical"
        elif score >= 60:
            severity = "high"
        elif score >= 30:
            severity = "medium"
        else:
            severity = "low"

        return {
            "risk_score": score,
            "severity": severity,
            "reasons": reasons or ["No configured risk signals detected"],
            "model_version": self.MODEL_VERSION,
        }
    
    def prioritize(
        self,
        *,
        base_score: int,
        unexpected_permission_count: int = 0,
        newly_reachable_resource_count: int = 0,
    ) -> dict[str, Any]:
        """Prioritize risk using permission-drift and attack-path evidence."""
        values = {
            "base_score": base_score,
            "unexpected_permission_count": unexpected_permission_count,
            "newly_reachable_resource_count": newly_reachable_resource_count,
        }

        for name, value in values.items():
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            if value < 0:
                raise ValueError(f"{name} cannot be negative")

        if base_score > 100:
            raise ValueError("base_score cannot exceed 100")

        score = base_score
        reasons: list[str] = []

        if unexpected_permission_count:
            points = min(unexpected_permission_count * 10, 30)
            score += points
            reasons.append(
                f"{unexpected_permission_count} unexpected permission(s) detected"
            )

        if newly_reachable_resource_count:
            points = min(newly_reachable_resource_count * 15, 30)
            score += points
            reasons.append(
                f"{newly_reachable_resource_count} sensitive resource(s) "
                "became newly reachable"
            )

        score = min(score, 100)

        if score >= 80:
            severity = "critical"
        elif score >= 60:
            severity = "high"
        elif score >= 30:
            severity = "medium"
        else:
            severity = "low"

        if not reasons:
            reasons.append("No additional permission-drift or attack-path evidence")

        if severity == "critical":
            recommended_action = "Urgent security review and remediation approval"
        elif severity == "high":
            recommended_action = "Prioritize investigation and review remediation"
        elif severity == "medium":
            recommended_action = "Investigate findings and validate access requirements"
        else:
            recommended_action = "Continue monitoring"

        return {
            "risk_score": score,
            "severity": severity,
            "reasons": reasons,
            "recommended_action": recommended_action,
            "requires_human_approval": True,
            "evidence": {
                "base_score": base_score,
                "unexpected_permission_count": unexpected_permission_count,
                "newly_reachable_resource_count": newly_reachable_resource_count,
            },
            "model_version": self.MODEL_VERSION,
        }

