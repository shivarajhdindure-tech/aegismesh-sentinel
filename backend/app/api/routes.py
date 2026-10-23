
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException

from backend.app.api.schemas import (
    AccessEventRequest,
    IncidentReplayRequest,
)
from ml_engine.incident_replay import IncidentReplay
from ml_engine.anomaly_detector import AccessAnomalyDetector
from ml_engine.attack_graph import AttackGraph
from ml_engine.baseline_loader import train_detector
from ml_engine.pipeline import SecurityAnalysisPipeline

router = APIRouter()

# Explicitly opt into synthetic data only for local development.
_baseline_path = os.getenv("AEGISMESH_BASELINE_PATH")
_use_synthetic = os.getenv("AEGISMESH_USE_SYNTHETIC_BASELINE") == "1"

if _baseline_path:
    _detector = train_detector(_baseline_path)
elif _use_synthetic:
    _detector = AccessAnomalyDetector(contamination=0.1)
    _baseline = [
        {
            "events_last_hour": 8 + (i % 3),
            "unique_resources": 2 + (i % 2),
            "failed_attempts": i % 2,
            "privilege_changes": 0,
            "off_hours": 0,
        }
        for i in range(30)
    ]
    _detector.fit(_baseline)
else:
    raise RuntimeError(
        "Configure AEGISMESH_BASELINE_PATH or explicitly set "
        "AEGISMESH_USE_SYNTHETIC_BASELINE=1 for local development."
    )

_pipeline = SecurityAnalysisPipeline(_detector)


@router.post("/analyze")
def analyze_event(request: AccessEventRequest) -> dict:
    graph = AttackGraph()

    for source, target, relationship in request.relationships:
        try:
            graph.add_relationship(source, target, relationship)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    event = {
        "events_last_hour": request.events_last_hour,
        "unique_resources": request.unique_resources,
        "failed_attempts": request.failed_attempts,
        "privilege_changes": request.privilege_changes,
        "off_hours": request.off_hours,
    }

    try:
        assessment = _pipeline.analyze(
            incident_id=request.incident_id,
            identity_id=request.identity_id,
            event=event,
            attack_graph=graph,
            sensitive_resources=request.sensitive_resources,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail="Internal server error",
        ) from exc

    return assessment.model_dump()


@router.post("/replay")
def replay_incident(request: IncidentReplayRequest) -> dict:
    replay_engine = IncidentReplay()

    events = [event.model_dump(exclude_none=True) for event in request.events]

    try:
        return replay_engine.replay(
            events=events,
            sensitive_resources=request.sensitive_resources,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail="Internal server error",
        ) from exc

