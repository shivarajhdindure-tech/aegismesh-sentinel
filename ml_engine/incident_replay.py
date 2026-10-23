
from __future__ import annotations

from typing import Any

from ml_engine.attack_graph import AttackGraph


class IncidentReplay:
    """Replay permission grants and revocations in an in-memory graph."""

    def replay(
        self,
        events: list[dict[str, Any]],
        sensitive_resources: list[str] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(events, list):
            raise ValueError("Events must be a list")

        if not events:
            raise ValueError("At least one event is required")

        graph = AttackGraph()
        timeline: list[dict[str, Any]] = []
        relationships_processed = 0

        for index, event in enumerate(events):
            if not isinstance(event, dict):
                raise ValueError(f"Event {index} must be an object")

            source = event.get("source")
            target = event.get("target")
            relationship = event.get("relationship")
            action = event.get("action", "grant")

            if not all(
                isinstance(value, str) and value.strip()
                for value in (source, target, relationship)
            ):
                raise ValueError(
                    f"Event {index} requires non-empty source, "
                    "target, and relationship strings"
                )

            if action not in ("grant", "revoke"):
                raise ValueError(
                    f"Event {index} action must be 'grant' or 'revoke'"
                )

            identity_id = event.get("identity_id", source)
            if not isinstance(identity_id, str) or not identity_id.strip():
                raise ValueError(
                    f"Event {index} has an invalid identity_id"
                )

            if action == "grant":
                graph.add_relationship(source, target, relationship)
            else:
                # Remove only the matching relationship type.
                if graph.graph.has_edge(source, target):
                    existing = graph.graph[source][target]
                    if existing.get("relationship") == relationship:
                        graph.graph.remove_edge(source, target)

            relationships_processed += 1

            reachable = graph.reachable_resources(
                identity_id,
                sensitive_resources or [],
            )

            timeline.append(
                {
                    "event_index": index,
                    "action": action,
                    "identity_id": identity_id,
                    "source": source,
                    "target": target,
                    "relationship": relationship,
                    "reachable_sensitive_resources": reachable,
                }
            )

        return {
            "events_replayed": len(events),
            "relationships_processed": relationships_processed,
            "timeline": timeline,
            "final_reachable_sensitive_resources": (
                timeline[-1]["reachable_sensitive_resources"]
            ),
        }
