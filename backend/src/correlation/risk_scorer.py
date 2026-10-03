"""Incident-level risk scoring with explainable bounded inputs."""
from __future__ import annotations

import json
import math
from collections import Counter
from typing import Any

import pandas as pd

from .asset_criticality import get_criticality
from .mitre_mapper import map_to_mitre


def compute_risk_score(confidence: float, criticality: float, occurrence_count: int, shap_top_features: list[dict[str, Any]] | None = None) -> float:
    """Score confidence with 30% asset and logarithmic repetition adjustments."""
    score = max(0.0, min(1.0, float(confidence or 0))) * 70
    score += max(0.0, min(1.0, float(criticality or 0))) * 30
    score += min(12.0, math.log1p(max(0, occurrence_count)) * 3)
    if shap_top_features:
        score += 3.0
    return round(min(100.0, score), 2)


def score_incidents(incidents_df: pd.DataFrame, criticality_map: dict[str, float], config: dict) -> pd.DataFrame:
    """Flatten incident members into analyst-facing risk summaries."""
    tiers = config.get("correlation", {}).get("risk_tiers", {})
    output: list[dict[str, Any]] = []
    for incident_id, group in incidents_df.groupby("incident_id", sort=False):
        labels = group.get("predicted_label", pd.Series(["UNKNOWN"])).fillna("UNKNOWN")
        label = Counter(labels).most_common(1)[0][0]
        alert_count = int(group.get("occurrence_count", pd.Series(1, index=group.index)).sum())
        destination = group.get("dst_ip", pd.Series([None])).iloc[0]
        score = compute_risk_score(group.get("confidence", pd.Series([0.0])).max(), get_criticality(destination, criticality_map), alert_count)
        tier = "critical" if score >= tiers.get("critical", 80) else "high" if score >= tiers.get("high", 60) else "medium" if score >= tiers.get("medium", 35) else "low"
        members = [event for encoded in group["member_event_ids"] for event in json.loads(encoded)]
        output.append({"incident_id": incident_id, "src_ip": group.get("src_ip", pd.Series([None])).iloc[0], "dst_ip": destination,
            "first_seen": group["first_seen"].min(), "last_seen": group["last_seen"].max(), "alert_count": alert_count,
            "dominant_label": label, "mitre_techniques": sorted({technique for value in labels for technique in map_to_mitre(value)}),
            "risk_score": score, "risk_tier": tier, "member_event_ids": members, "status": "open"})
    return pd.DataFrame(output)
