"""Small polling consumers for feedback-to-KB and feedback-to-retraining queues."""
from __future__ import annotations

from typing import Any

from ..db import create_schema, get_session_factory
from ..db.models import Incident
from ..db.repositories import add_kb_entry, pending_feedback


def apply_feedback_to_knowledge_base(config: dict[str, Any] | None = None) -> int:
    """Turn unapplied analyst feedback into durable, retrievable KB entries."""
    create_schema(config)
    count = 0
    with get_session_factory(config)() as session:
        for feedback in pending_feedback(session, "applied_to_kb"):
            incident = session.get(Incident, feedback.incident_id)
            text = f"Analyst verdict: {feedback.analyst_verdict}. Corrected label: {feedback.corrected_label or 'none'}. Notes: {feedback.notes or 'none'}. Incident techniques: {', '.join(incident.mitre_techniques if incident else [])}."
            add_kb_entry(session, feedback, text)
            count += 1
    return count


def claim_feedback_for_retraining(config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Atomically claim a threshold-sized batch for an external training run."""
    threshold = int((config or {}).get("feedback_loop", {}).get("retrain", {}).get("feedback_row_threshold", 50))
    create_schema(config)
    with get_session_factory(config)() as session:
        rows = pending_feedback(session, "applied_to_train_queue", threshold)
        if len(rows) < threshold: return []
        payload = [{"feedback_id": r.feedback_id, "incident_id": r.incident_id, "corrected_label": r.corrected_label} for r in rows]
        for row in rows: row.applied_to_train_queue = True
        session.commit()
        return payload
