
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
        """Add a directed relationship between two graph nodes."""
        if not source.strip() or not target.strip():
            raise ValueError("Node identifiers cannot be empty")

        if not relationship.strip():
            raise ValueError("Relationship cannot be empty")

        self.graph.add_edge(
            source,
            target,
            relationship=relationship,
        )

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
