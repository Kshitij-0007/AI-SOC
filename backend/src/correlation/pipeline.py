"""Composable persistence-aware correlation pipeline."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from .asset_criticality import load_asset_criticality
from .correlation_engine import correlate_incidents
from .dedup import deduplicate_events
from .risk_scorer import score_incidents


def run_correlation(scored_events_path: Path, output_dir: Path, config: dict[str, Any]) -> dict[str, int]:
    """Correlate scored canonical events, write a derived export, and persist summaries."""
    events = pd.read_parquet(scored_events_path)
    required = {"event_id", "timestamp", "predicted_label", "confidence"}
    if missing := required - set(events.columns):
        raise ValueError(f"Scored event input missing required columns: {sorted(missing)}")
    settings = config.get("correlation", {})
    deduped = deduplicate_events(events, int(settings.get("dedup_window_seconds", 60)), settings.get("dedup_key_columns", ["src_ip", "dst_ip", "dst_port", "predicted_label"]))
    correlated = correlate_incidents(deduped, config)
    path = Path(settings.get("asset_criticality_path", "configs/asset_criticality.yaml"))
    if not path.is_absolute(): path = Path(__file__).resolve().parents[2] / path
    incidents = score_incidents(correlated, load_asset_criticality(path), config)
    output_dir.mkdir(parents=True, exist_ok=True)
    incidents.to_parquet(output_dir / "incidents.parquet", index=False)
    from ..db import create_schema, get_session_factory
    from ..db.repositories import persist_incidents
    create_schema()
    with get_session_factory()() as session: persist_incidents(session, incidents.to_dict(orient="records"))
    return {"raw_events_in": len(events), "deduped_alerts": len(deduped), "incidents_out": len(incidents), "critical_count": int((incidents.risk_tier == "critical").sum()), "high_count": int((incidents.risk_tier == "high").sum())}
