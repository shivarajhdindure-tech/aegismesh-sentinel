
import json
from pathlib import Path
from typing import Any

from ml_engine.anomaly_detector import AccessAnomalyDetector


def load_baseline(path: str | Path) -> list[dict[str, Any]]:
    """Load and validate trusted baseline events from a JSON file."""
    baseline_path = Path(path)

    try:
        with baseline_path.open("r", encoding="utf-8") as file:
            events = json.load(file)
    except FileNotFoundError as exc:
        raise ValueError(
            f"Baseline file not found: {baseline_path}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Baseline file contains invalid JSON: {baseline_path}"
        ) from exc

    if not isinstance(events, list):
        raise ValueError("Baseline JSON must contain a list of events")

    if len(events) < 10:
        raise ValueError("At least 10 baseline events are required")

    # Reuse the detector's feature validation without fitting a model.
    AccessAnomalyDetector._features(events)

    return events


def train_detector(path: str | Path) -> AccessAnomalyDetector:
    """Train a detector from an explicitly supplied baseline file."""
    events = load_baseline(path)

    detector = AccessAnomalyDetector(contamination=0.1)
    detector.fit(events)

    return detector
