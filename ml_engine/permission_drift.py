
from typing import Any


class PermissionDriftDetector:
    """Compare expected permissions with observed permissions."""

    @staticmethod
    def _validate_permissions(
        permissions: list[dict[str, Any]],
        label: str,
    ) -> None:
        if not isinstance(permissions, list):
            raise ValueError(f"{label} permissions must be a list")

        for index, permission in enumerate(permissions):
            if not isinstance(permission, dict):
                raise ValueError(
                    f"{label} permission {index} must be an object"
                )

            required_fields = ("identity", "resource", "action")
            for field in required_fields:
                value = permission.get(field)
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(
                        f"{label} permission {index} requires "
                        f"a non-empty {field}"
                    )

    def detect(
        self,
        expected_permissions: list[dict[str, Any]],
        observed_permissions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Report observed permissions that are not in the expected baseline."""
        self._validate_permissions(expected_permissions, "Expected")
        self._validate_permissions(observed_permissions, "Observed")

        expected = {
            (item["identity"], item["resource"], item["action"])
            for item in expected_permissions
        }

        drift_findings = []
        seen = set()

        for permission in observed_permissions:
            key = (
                permission["identity"],
                permission["resource"],
                permission["action"],
            )

            if key not in expected and key not in seen:
                seen.add(key)
                drift_findings.append(
                    {
                        "identity": permission["identity"],
                        "resource": permission["resource"],
                        "action": permission["action"],
                        "finding": "unexpected_permission",
                        "severity": "high",
                        "evidence": {
                            "reason": (
                                "Observed permission is absent from "
                                "the expected baseline"
                            )
                        },
                    }
                )

        return {
            "drift_detected": bool(drift_findings),
            "finding_count": len(drift_findings),
            "findings": drift_findings,
        }
