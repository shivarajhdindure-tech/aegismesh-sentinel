
from __future__ import annotations

from collections import deque
from typing import Iterable

import networkx as nx


class AttackGraph:
    """Analyze directed identity-to-resource access relationships."""

    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def add_relationship(
        self,
        source: str,
        target: str,
        relationship: str,
    ) -> None:
        """Add a relationship without overwriting other relationships on the edge."""
        if not isinstance(source, str) or not source.strip():
            raise ValueError("Node identifiers cannot be empty")

        if not isinstance(target, str) or not target.strip():
            raise ValueError("Node identifiers cannot be empty")

        if not isinstance(relationship, str) or not relationship.strip():
            raise ValueError("Relationship cannot be empty")

        if self.graph.has_edge(source, target):
            relationships = self.graph[source][target].get("relationship", [])
            if isinstance(relationships, str):
                relationships = [relationships]
            if relationship not in relationships:
                relationships.append(relationship)
            self.graph[source][target]["relationship"] = relationships
        else:
            self.graph.add_edge(
                source,
                target,
                relationship=[relationship],
            )

    def remove_relationship(
        self,
        source: str,
        target: str,
        relationship: str,
    ) -> bool:
        """Remove one relationship; remove the edge only when none remain."""
        if not self.graph.has_edge(source, target):
            return False

        relationships = self.graph[source][target].get("relationship", [])
        if isinstance(relationships, str):
            relationships = [relationships]

        if relationship not in relationships:
            return False

        remaining = [
            item for item in relationships
            if item != relationship
        ]

        if remaining:
            self.graph[source][target]["relationship"] = remaining
        else:
            self.graph.remove_edge(source, target)

        return True

    def reachable_resources(
        self,
        identity_id: str,
        sensitive_resources: Iterable[str],
    ) -> list[str]:
        """Return supplied sensitive resources reachable from an identity."""
        if identity_id not in self.graph:
            return []

        sensitive = set(sensitive_resources)
        found: set[str] = set()
        visited = {identity_id}
        queue = deque([identity_id])

        while queue:
            current = queue.popleft()

            if current in sensitive:
                found.add(current)

            for neighbor in self.graph.successors(current):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)

        return sorted(found)

    def shortest_path(
        self,
        identity_id: str,
        resource_id: str,
    ) -> list[str] | None:
        """Return a shortest path, or None if no path exists."""
        if (
            identity_id not in self.graph
            or resource_id not in self.graph
        ):
            return None

        try:
            return nx.shortest_path(
                self.graph,
                source=identity_id,
                target=resource_id,
            )
        except nx.NetworkXNoPath:
            return None
