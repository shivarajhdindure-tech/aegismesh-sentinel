
from ml_engine.anomaly_detector import AccessAnomalyDetector
from ml_engine.attack_graph import AttackGraph
from ml_engine.pipeline import SecurityAnalysisPipeline


def test_pipeline_combines_all_security_signals():
    detector = AccessAnomalyDetector(contamination=0.1)

    baseline = [
        {
            "events_last_hour": 8 + (i % 3),
            "unique_resources": 2 + (i % 2),
            "failed_attempts": i % 2,
            "privilege_changes": 0,
            "off_hours": 0,
        }
        for i in range(30)
    ]
    detector.fit(baseline)

    graph = AttackGraph()
    graph.add_relationship("user:alice", "role:developer", "assumes")
    graph.add_relationship("role:developer", "resource:customer-db", "accesses")

    pipeline = SecurityAnalysisPipeline(detector)

    assessment = pipeline.analyze(
        incident_id="incident-001",
        identity_id="user:alice",
        event={
            "events_last_hour": 500,
            "unique_resources": 80,
            "failed_attempts": 30,
            "privilege_changes": 12,
            "off_hours": 1,
        },
        attack_graph=graph,
        sensitive_resources=["resource:customer-db"],
    )

    assert assessment.anomaly_detected is True
    assert assessment.risk_score >= 80
    assert assessment.severity == "critical"
    assert assessment.reachable_resources == ["resource:customer-db"]
    assert assessment.attack_path == [
        "user:alice",
        "role:developer",
        "resource:customer-db",
    ]


def test_pipeline_integrates_permission_drift_and_candidate_attack_path():
    detector = AccessAnomalyDetector(contamination=0.1)

    baseline = [
        {
            "events_last_hour": 8 + (i % 3),
            "unique_resources": 2 + (i % 2),
            "failed_attempts": i % 2,
            "privilege_changes": 0,
            "off_hours": 0,
        }
        for i in range(30)
    ]
    detector.fit(baseline)

    graph = AttackGraph()
    graph.add_relationship("user:alice", "role:developer", "assumes")

    pipeline = SecurityAnalysisPipeline(detector)

    assessment = pipeline.analyze_permission_risk(
        incident_id="incident-002",
        identity_id="user:alice",
        event={
            "events_last_hour": 10,
            "unique_resources": 3,
            "failed_attempts": 0,
            "privilege_changes": 1,
            "off_hours": 0,
        },
        attack_graph=graph,
        sensitive_resources=["resource:customer-db"],
        expected_permissions=[],
        observed_permissions=[
            {
                "identity": "user:alice",
                "resource": "resource:customer-db",
                "action": "read",
            }
        ],
        candidate_relationship={
            "source": "role:developer",
            "target": "resource:customer-db",
            "relationship": "accesses",
        },
    )

    assert assessment.incident_id == "incident-002"
    assert assessment.risk_score > 0
    assert assessment.severity in {"low", "medium", "high", "critical"}
    assert assessment.evidence["permission_drift"]["finding_count"] == 1
    assert assessment.evidence["candidate_attack_path"][
        "newly_reachable_sensitive_resources"
    ] == ["resource:customer-db"]
    assert assessment.evidence["risk_prioritization"][
        "requires_human_approval"
    ] is True

    # Candidate-path simulation must not modify the original graph.
    assert graph.reachable_resources(
        "user:alice",
        ["resource:customer-db"],
    ) == []
    
    assert assessment.recommended_action is not None
    assert len(assessment.recommended_action) > 0
