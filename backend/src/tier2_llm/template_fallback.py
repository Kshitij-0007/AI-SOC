"""Deterministic Tier-2 output used for lower tiers and unavailable LLMs."""
from __future__ import annotations
from typing import Any

def generate_template_summary(incident: dict[str, Any]) -> dict[str, object]:
    """Return narrative fields without inventing data or requiring a model server."""
    label = incident.get("dominant_label", "unknown activity")
    score = incident.get("risk_score", 0)
    tier = incident.get("risk_tier", "medium")
    techniques = ", ".join(incident.get("mitre_techniques", [])) or "unmapped techniques"
    source = incident.get("src_ip", "unknown source")
    destination = incident.get("dst_ip", "unknown destination")
    source_feed = incident.get("source_feed") or incident.get("source_type") or "Live SOC Stream"
    return {
        "summary": f"{label} activity from {source} targeting {destination} was grouped into one incident.",
        "dominant_label": label,
        "src_ip": source,
        "dst_ip": destination,
        "source_feed": source_feed,
        "risk_tier": tier,
        "severity_rationale": f"Risk score {score} ({tier.upper()}) reflects observed confidence, affected asset criticality, and repeated alerts. MITRE: {techniques}.",
        "recommended_actions": [
            "Validate the involved source and destination against asset and change records.",
            "Review related network telemetry and preserve relevant evidence."
        ]
    }
