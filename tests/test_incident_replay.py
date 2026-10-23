
import pytest

from ml_engine.incident_replay import IncidentReplay


def test_replay_tracks_reachable_sensitive_resource():
    replay = IncidentReplay()

    result = replay.replay(
        [
            {
                "source": "user:alice",
                "target": "role:developer",
                "relationship": "assumes",
            },
            {
                "source": "role:developer",
                "target": "resource:customer-db",
                "relationship": "accesses",
            },
        ],
        sensitive_resources=["resource:customer-db"],
    )

    assert result["events_replayed"] == 2
    assert result["relationships_processed"] == 2
    assert result["final_reachable_sensitive_resources"] == [
        "resource:customer-db"
    ]


def test_replay_rejects_empty_event_list():
    with pytest.raises(ValueError, match="At least one event"):
        IncidentReplay().replay([])


def test_replay_rejects_invalid_relationship():
    with pytest.raises(ValueError, match="requires non-empty"):
        IncidentReplay().replay(
            [{"source": "user:alice", "target": "", "relationship": "accesses"}]
        )


def test_replay_records_timeline_after_each_event():
    result = IncidentReplay().replay(
        [
            {
                "source": "user:alice",
                "target": "role:developer",
                "relationship": "assumes",
            },
            {
                "source": "role:developer",
                "target": "resource:customer-db",
                "relationship": "accesses",
            },
        ],
        sensitive_resources=["resource:customer-db"],
    )

    assert result["timeline"][0]["reachable_sensitive_resources"] == []
    assert result["timeline"][1]["reachable_sensitive_resources"] == [
        "resource:customer-db"
    ]


def test_revoke_removes_sensitive_resource_reachability():
    result = IncidentReplay().replay(
        [
            {
                "source": "user:alice",
                "target": "role:developer",
                "relationship": "assumes",
                "action": "grant",
            },
            {
                "source": "role:developer",
                "target": "resource:customer-db",
                "relationship": "accesses",
                "action": "grant",
            },
            {
                "source": "role:developer",
                "target": "resource:customer-db",
                "relationship": "accesses",
                "action": "revoke",
            },
        ],
        sensitive_resources=["resource:customer-db"],
    )

    assert result["timeline"][1]["reachable_sensitive_resources"] == [
        "resource:customer-db"
    ]
    assert result["timeline"][2]["reachable_sensitive_resources"] == []
    assert result["final_reachable_sensitive_resources"] == []


def test_replay_rejects_unknown_action():
    with pytest.raises(ValueError, match="action must be"):
        IncidentReplay().replay(
            [
                {
                    "source": "user:alice",
                    "target": "role:developer",
                    "relationship": "assumes",
                    "action": "delete-everything",
                }
            ]
        )

def test_revoking_one_relationship_preserves_another():
    from ml_engine.attack_graph import AttackGraph

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

def test_replay_uses_one_consistent_identity_across_events():
    result = IncidentReplay().replay(
        [
            {
                "source": "user:alice",
                "target": "role:developer",
                "relationship": "assumes",
            },
            {
                "source": "role:developer",
                "target": "resource:customer-db",
                "relationship": "accesses",
            },
        ],
        sensitive_resources=["resource:customer-db"],
    )

    assert [
        item["identity_id"] for item in result["timeline"]
    ] == ["user:alice", "user:alice"]

    assert result["final_reachable_sensitive_resources"] == [
        "resource:customer-db"
    ]


def test_revoking_one_path_preserves_alternative_path():
    result = IncidentReplay().replay(
        [
            {
                "source": "user:alice",
                "target": "role:developer",
                "relationship": "assumes",
                "action": "grant",
            },
            {
                "source": "role:developer",
                "target": "resource:customer-db",
                "relationship": "accesses",
                "action": "grant",
            },
            {
                "source": "user:alice",
                "target": "role:admin",
                "relationship": "assumes",
                "action": "grant",
            },
            {
                "source": "role:admin",
                "target": "resource:customer-db",
                "relationship": "accesses",
                "action": "grant",
            },
            {
                "source": "role:developer",
                "target": "resource:customer-db",
                "relationship": "accesses",
                "action": "revoke",
            },
        ],
        sensitive_resources=["resource:customer-db"],
    )

    assert result["timeline"][3]["reachable_sensitive_resources"] == [
        "resource:customer-db"
    ]
    assert result["timeline"][4]["reachable_sensitive_resources"] == [
        "resource:customer-db"
    ]
    assert result["final_reachable_sensitive_resources"] == [
        "resource:customer-db"
    ]


def test_replay_marks_missing_revocation_as_no_op():
    result = IncidentReplay().replay(
        [
            {
                "source": "user:alice",
                "target": "role:admin",
                "relationship": "assumes",
                "action": "grant",
            },
            {
                "source": "user:alice",
                "target": "role:admin",
                "relationship": "delegates",
                "action": "revoke",
            },
        ],
    )

    assert result["timeline"][0]["relationship_changed"] is True
    assert result["timeline"][1]["relationship_changed"] is False
