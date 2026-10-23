
from ml_engine.attack_graph import AttackGraph


def build_sample_graph():
    graph = AttackGraph()
    graph.add_relationship("user:alice", "role:developer", "assumes")
    graph.add_relationship("role:developer", "perm:read-db", "grants")
    graph.add_relationship("perm:read-db", "resource:customer-db", "accesses")
    graph.add_relationship("user:bob", "role:viewer", "assumes")
    return graph


def test_finds_reachable_sensitive_resource():
    graph = build_sample_graph()

    resources = graph.reachable_resources(
        "user:alice",
        ["resource:customer-db"],
    )

    assert resources == ["resource:customer-db"]


def test_returns_shortest_access_path():
    graph = build_sample_graph()

    path = graph.shortest_path(
        "user:alice",
        "resource:customer-db",
    )

    assert path == [
        "user:alice",
        "role:developer",
        "perm:read-db",
        "resource:customer-db",
    ]


def test_unreachable_resource_is_not_returned():
    graph = build_sample_graph()

    resources = graph.reachable_resources(
        "user:bob",
        ["resource:customer-db"],
    )

    assert resources == []


def test_empty_node_identifier_is_rejected():
    graph = AttackGraph()

    try:
        graph.add_relationship("", "role:developer", "assumes")
        assert False, "Expected ValueError"
    except ValueError:
        pass


def test_multiple_relationships_between_same_nodes_are_preserved():
    graph = AttackGraph()

    graph.add_relationship("user:alice", "role:admin", "assumes")
    graph.add_relationship("user:alice", "role:admin", "delegates")

    assert graph.graph.has_edge("user:alice", "role:admin")
    assert graph.graph["user:alice"]["role:admin"]["relationship"] == [
        "assumes",
        "delegates",
    ]


def test_removing_one_relationship_preserves_other_relationship():
    graph = AttackGraph()

    graph.add_relationship("user:alice", "role:admin", "assumes")
    graph.add_relationship("user:alice", "role:admin", "delegates")

    removed = graph.remove_relationship(
        "user:alice",
        "role:admin",
        "assumes",
    )

    assert removed is True
    assert graph.graph.has_edge("user:alice", "role:admin")
    assert graph.graph["user:alice"]["role:admin"]["relationship"] == [
        "delegates"
    ]
