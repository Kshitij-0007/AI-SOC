"""Portable SQLAlchemy models for AI-SOC operational state."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    """Base class for all tables."""


class CanonicalEvent(Base):
    __tablename__ = "canonical_events"
    event_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    batch_id: Mapped[str] = mapped_column(String(36), index=True)
    source_type: Mapped[str] = mapped_column(String(128), index=True)
    source_ref: Mapped[str] = mapped_column(Text)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    raw_fields: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    canonical_fields: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Prediction(Base):
    __tablename__ = "predictions"
    prediction_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_id: Mapped[str] = mapped_column(ForeignKey("canonical_events.event_id"), index=True)
    model_version: Mapped[str] = mapped_column(String(128), index=True)
    predicted_label: Mapped[str] = mapped_column(String(255))
    confidence: Mapped[float] = mapped_column(Float)
    shap_top_features: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class Incident(Base):
    __tablename__ = "incidents"
    incident_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    risk_score: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(64), default="open", index=True)
    llm_narrative: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"
    feedback_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    incident_id: Mapped[str] = mapped_column(ForeignKey("incidents.incident_id"), index=True)
    analyst_verdict: Mapped[str] = mapped_column(String(64))
    corrected_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    applied_to_kb: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    applied_to_train_queue: Mapped[bool] = mapped_column(Boolean, default=False, index=True)


class KnowledgeBaseEntry(Base):
    __tablename__ = "knowledge_base_entries"
    kb_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source: Mapped[str] = mapped_column(String(128))
    source_ref_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    text_chunk: Mapped[str] = mapped_column(Text)
    embedding_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class ModelRegistryEntry(Base):
    __tablename__ = "model_registry"
    model_version: Mapped[str] = mapped_column(String(128), primary_key=True)
    trained_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    training_row_count: Mapped[int] = mapped_column(Integer)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    triggered_by: Mapped[str] = mapped_column(String(64))
    artifact_path: Mapped[str] = mapped_column(Text)
