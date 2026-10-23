
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
