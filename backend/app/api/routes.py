
from fastapi import APIRouter, HTTPException

from backend.app.api.schemas import AccessEventRequest
from ml_engine.anomaly_detector import AccessAnomalyDetector
from ml_engine.attack_graph import AttackGraph
from ml_engine.pipeline import SecurityAnalysisPipeline

router = APIRouter()

# Synthetic baseline for the local prototype only.
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
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return assessment.model_dump()
