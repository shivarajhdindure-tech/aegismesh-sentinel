
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

        initial_reachable: set[str] = set()
        graph = AttackGraph()
        timeline: list[dict[str, Any]] = []
        relationships_processed = 0
        outcome_counts = {
            "granted": 0,
            "already_present": 0,
            "revoked": 0,
            "not_found": 0,
        }

        # Use the first event's identity, or its source, for the whole replay.
        replay_identity = events[0].get("identity_id", events[0].get("source"))
        if not isinstance(replay_identity, str) or not replay_identity.strip():
            raise ValueError("The first event requires a valid identity_id or source")

        for index, event in enumerate(events):
            if not isinstance(event, dict):
                raise ValueError(f"Event {index} must be an object")
            previously_reachable = set(
                graph.reachable_resources(
                    replay_identity, sensitive_resources or []
                )
            )
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
            event_identity = event.get("identity_id")
            if event_identity is not None and (
                not isinstance(event_identity, str) or not event_identity.strip()
            ):
                raise ValueError(f"Event {index} has an invalid identity_id")

            if event_identity is not None and event_identity != replay_identity:
                raise ValueError(
                    f"Event {index} identity_id must match the replay identity "
                    f"{replay_identity!r}"
                )

            if action == "grant":
                existing = (
                    graph.graph[source][target].get("relationship", [])
                    if graph.graph.has_edge(source, target)
                    else []
                )
                if isinstance(existing, str):
                    existing = [existing]

                relationship_changed = relationship not in existing
                graph.add_relationship(source, target, relationship)
                outcome = "granted" if relationship_changed else "already_present"
                outcome_counts[outcome] += 1
            else:
                relationship_changed = graph.remove_relationship(
                    source, target, relationship
                )
                outcome = "revoked" if relationship_changed else "not_found"
                outcome_counts[outcome] += 1

            relationships_processed += 1
            reachable = graph.reachable_resources(
                replay_identity, sensitive_resources or []
            )
            currently_reachable = set(reachable)
            if index == 0:
                initial_reachable = set(previously_reachable)

            access_changes = []
            for resource in sorted(currently_reachable - previously_reachable):
                path = graph.shortest_path(replay_identity, resource)

                access_changes.append(
                    {
                        "resource": resource,
                        "change": "became_reachable",
                        "path": path,
                        "relationship": {
                            "source": source,
                            "target": target,
                            "type": relationship,
                        },
                        "event_index": index,
                        "relationship_changed": relationship_changed,
                        "reachable_before": sorted(previously_reachable),
                        "reachable_after": reachable,
                    }

                )


            for resource in sorted(previously_reachable - currently_reachable):

                access_changes.append(

                    {
                        "resource": resource,
                        "change": "became_unreachable",
                        "path": None,
                        "relationship": {
                            "source": source,
                            "target": target,
                            "type": relationship,
                        },
                        "event_index": index,
                        "relationship_changed": relationship_changed,
                        "reachable_before": sorted(previously_reachable),
                        "reachable_after": reachable,
                    }

                )



            timeline.append(
                {
                    "event_index": index,
                    "action": action,
                    "identity_id": replay_identity,
                    "source": source,
                    "target": target,
                    "relationship": relationship,
                    "outcome": outcome,
                    "reachable_sensitive_resources": reachable,
                    "relationship_changed": relationship_changed,
                    "access_changes": access_changes,
                    "reachable_sensitive_resources_before": sorted(
                        previously_reachable
                    ),
                    "reachable_sensitive_resources_after": reachable,
                }
            )

        final_reachable = set(
            timeline[-1]["reachable_sensitive_resources"]
        )

        all_access_changes = [
            change
            for event in timeline
            for change in event["access_changes"]
        ]

        access_impact = {
            "resources_became_reachable": sorted(
                final_reachable - initial_reachable
            ),
            "resources_became_unreachable": sorted(
                initial_reachable - final_reachable
            ),
            "resources_still_reachable": sorted(
                initial_reachable & final_reachable
            ),
            "total_access_changes": len(all_access_changes),
        }

        return {
            "events_replayed": len(events),
            "relationships_processed": relationships_processed,
            "summary": {
                "events_replayed": len(events),
                "relationships_processed": relationships_processed,
                "outcome_counts": outcome_counts,
            },
            "access_impact": access_impact,
            "timeline": timeline,
            "final_reachable_sensitive_resources": (
                timeline[-1]["reachable_sensitive_resources"]
            ),
        }

