from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import AnalystFeedback, CanonicalEvent, Incident, KnowledgeBaseEntry

def persist_events(session: Session, rows: Iterable[dict[str, Any]], source_type: str, source_ref: str) -> str:
    batch_id = str(uuid.uuid4())
    for row in rows:
        event_id = str(row.get("event_id") or uuid.uuid4())
        if not session.get(CanonicalEvent, event_id): session.add(CanonicalEvent(event_id=event_id, batch_id=batch_id, source_type=source_type, source_ref=source_ref, ingested_at=datetime.now(timezone.utc), raw_fields=dict(row), canonical_fields=dict(row)))
    session.commit(); return batch_id

def persist_incidents(session: Session, rows: Iterable[dict[str, Any]]) -> None:
    for row in rows:
        entity = session.get(Incident, str(row["incident_id"]))
        if entity is None: session.add(Incident(incident_id=str(row["incident_id"]), event_ids=row.get("member_event_ids", []), mitre_techniques=row.get("mitre_techniques", []), risk_score=float(row.get("risk_score", 0)), status=row.get("status", "open")))
    session.commit()

def create_feedback(session: Session, incident_id: str, verdict: str, corrected_label: str | None, notes: str | None) -> AnalystFeedback:
    if not session.get(Incident, incident_id): raise LookupError(incident_id)
    row = AnalystFeedback(incident_id=incident_id, analyst_verdict=verdict, corrected_label=corrected_label, notes=notes); session.add(row); session.commit(); return row

def pending_feedback(session: Session, flag: str, limit: int | None = None) -> list[AnalystFeedback]:
    return list(session.scalars(select(AnalystFeedback).where(getattr(AnalystFeedback, flag).is_(False)).limit(limit)).all())

def add_kb_entry(session: Session, feedback: AnalystFeedback, text: str) -> None:
    if not session.scalar(select(KnowledgeBaseEntry).where(KnowledgeBaseEntry.source_ref_id == feedback.feedback_id)): session.add(KnowledgeBaseEntry(source="analyst_feedback", source_ref_id=feedback.feedback_id, text_chunk=text))
    feedback.applied_to_kb = True; session.commit()
