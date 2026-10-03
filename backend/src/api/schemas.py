from __future__ import annotations
from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field

class FeedbackIn(BaseModel):
    analyst_verdict: str = Field(pattern="^(confirmed_threat|false_positive|needs_relabel)$")
    corrected_label: str | None = None
    notes: str | None = None

class IncidentOut(BaseModel):
    incident_id: str
    risk_score: float
    risk_tier: str | None = None
    status: str
    dominant_label: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    source_feed: str | None = None
    mitre_techniques: list[str] = []
    event_ids: list[str] = []
    llm_narrative: str | None = None
    created_at: datetime
    updated_at: datetime

class LiveFeedEvent(BaseModel):
    event_id: str
    source_type: str
    source_ref: str | None = None
    ingested_at: datetime
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: Any | None = None
    dst_port: Any | None = None
    protocol: str | None = None
    label: str | None = None
    raw_fields: dict[str, Any] = {}

class LiveFeedStatus(BaseModel):
    is_running: bool
    active_connectors: list[str]
    feed_description: str | None = None
    replay_enabled: bool = True
    total_events: int
    total_incidents: int
    latest_event_ts: datetime | None = None

class SOCStats(BaseModel):
    total_events: int
    total_incidents: int
    critical_incidents: int
    high_incidents: int
    medium_incidents: int
    low_incidents: int
    open_incidents: int
    mitre_distribution: dict[str, int]
    top_threat_labels: dict[str, int]

class UrlSourceIn(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    name: str | None = Field(default=None, max_length=80)
    poll_interval_seconds: int = Field(default=10, ge=2, le=3600)

class UrlSourceOut(BaseModel):
    source_id: str
    name: str
    url: str
    poll_interval_seconds: float
    enabled: bool
    last_success_at: str | None = None
    last_record_count: int = 0
    last_error: str | None = None
