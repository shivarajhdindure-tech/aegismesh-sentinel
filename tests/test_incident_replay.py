
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


def test_replay_reports_grant_and_duplicate_grant_outcomes():
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
                "relationship": "assumes",
                "action": "grant",
            },
        ]
    )

    assert result["timeline"][0]["outcome"] == "granted"
    assert result["timeline"][1]["outcome"] == "already_present"
    assert result["timeline"][0]["relationship_changed"] is True
    assert result["timeline"][1]["relationship_changed"] is False


def test_replay_reports_successful_and_missing_revocation_outcomes():
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
                "relationship": "assumes",
                "action": "revoke",
            },
            {
                "source": "user:alice",
                "target": "role:admin",
                "relationship": "assumes",
                "action": "revoke",
            },
        ]
    )

    assert result["timeline"][1]["outcome"] == "revoked"
    assert result["timeline"][2]["outcome"] == "not_found"
    assert result["timeline"][1]["relationship_changed"] is True
    assert result["timeline"][2]["relationship_changed"] is False


def test_replay_includes_summary_outcome_counts():
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
                "relationship": "assumes",
                "action": "grant",
            },
            {
                "source": "user:alice",
                "target": "role:admin",
                "relationship": "assumes",
                "action": "revoke",
            },
            {
                "source": "user:alice",
                "target": "role:admin",
                "relationship": "assumes",
                "action": "revoke",
            },
        ]
    )

    assert result["summary"]["events_replayed"] == 4
    assert result["summary"]["relationships_processed"] == 4
    assert result["summary"]["outcome_counts"] == {
        "granted": 1,
        "already_present": 1,
        "revoked": 1,
        "not_found": 1,
    }


def test_replay_explains_when_sensitive_resource_becomes_reachable():
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
                "relationship": "can_read",
                "action": "grant",
            },
        ],
        sensitive_resources=["resource:customer-db"],
    )

    assert (
        result["timeline"][0]["reachable_sensitive_resources"] == []
    )
    assert (
        result["timeline"][1]["reachable_sensitive_resources"]
        == ["resource:customer-db"]
    )

    # The explanation field will be implemented in the next step.
    assert (
        result["timeline"][1]["access_changes"][0]["resource"]
        == "resource:customer-db"
    )
    assert (
        result["timeline"][1]["access_changes"][0]["change"]
        == "became_reachable"
    )
    assert (
        result["timeline"][1]["access_changes"][0]["path"]
        == [
            "user:alice",
            "role:developer",
            "resource:customer-db",
        ]
    )


def test_replay_explains_when_sensitive_resource_becomes_unreachable():
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
                "relationship": "can_read",
                "action": "grant",
            },
            {
                "source": "role:developer",
                "target": "resource:customer-db",
                "relationship": "can_read",
                "action": "revoke",
            },
        ],
        sensitive_resources=["resource:customer-db"],
    )

    assert (
        result["timeline"][1]["reachable_sensitive_resources"]
        == ["resource:customer-db"]
    )
    assert result["timeline"][2]["reachable_sensitive_resources"] == []


    assert result["timeline"][2]["access_changes"] == [
        {
            "resource": "resource:customer-db",
            "change": "became_unreachable",
            "path": None,
            "relationship": {
                "source": "role:developer",
                "target": "resource:customer-db",
                "type": "can_read",
            },
            "event_index": 2,
            "relationship_changed": True,
            "reachable_before": ["resource:customer-db"],
            "reachable_after": [],
        }
    ]



def test_replay_keeps_resource_reachable_when_alternate_path_exists():
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
                "relationship": "can_read",
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
                "relationship": "can_read",
                "action": "grant",
            },
            {
                "source": "role:developer",
                "target": "resource:customer-db",
                "relationship": "can_read",
                "action": "revoke",
            },
        ],
        sensitive_resources=["resource:customer-db"],
    )

    final_event = result["timeline"][-1]

    assert final_event["reachable_sensitive_resources"] == [
        "resource:customer-db"
    ]
    assert final_event["access_changes"] == []


def test_access_change_identifies_relationship_that_enabled_access():
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
                "relationship": "can_read",
                "action": "grant",
            },
        ],
        sensitive_resources=["resource:customer-db"],
    )

    change = result["timeline"][1]["access_changes"][0]

    assert change["resource"] == "resource:customer-db"
    assert change["change"] == "became_reachable"
    assert change["path"] == [
        "user:alice",
        "role:developer",
        "resource:customer-db",
    ]
    assert change["relationship"] == {
        "source": "role:developer",
        "target": "resource:customer-db",
        "type": "can_read",
    }
