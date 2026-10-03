"""Unified API and Live Feed Service for AI-SOC."""
from __future__ import annotations

import io
import json
import logging
import re
import shutil
import socket
import tempfile
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import requests
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from ..db import create_schema, get_session_factory
from ..db.models import AnalystFeedback, CanonicalEvent, Incident, KnowledgeBaseEntry
from ..db.repositories import create_feedback, persist_events, persist_incidents
from ..correlation.asset_criticality import load_asset_criticality
from ..correlation.correlation_engine import correlate_incidents
from ..correlation.dedup import deduplicate_events
from ..correlation.risk_scorer import score_incidents
from ..live_feeds.replay_simulator import ReplaySimulator
from ..live_feeds.scheduler import _build_connectors, _load_config
from ..tier2_llm.template_fallback import generate_template_summary
from .schemas import FeedbackIn, IncidentOut, LiveFeedEvent, LiveFeedStatus, SOCStats, UrlSourceIn, UrlSourceOut
from ..live_feeds.url_connector import UrlFeedConnector, UrlFeedError

logger = logging.getLogger(__name__)

create_schema()
app = FastAPI(title="AI-SOC API", version="2.0.0")

# Enable CORS for frontend dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    with get_session_factory()() as session:
        yield session

_CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "config.yaml"
_CRIT_PATH = Path(__file__).resolve().parents[2] / "configs" / "asset_criticality.yaml"

# Live feed background controller
class LiveFeedController:
    def __init__(self):
        self.is_running = False
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self.connectors = []
        self._reload_connectors()

    def _reload_connectors(self):
        cfg = _load_config(_CONFIG_PATH)
        self.connectors = _build_connectors(cfg)

    def set_replay_enabled(self, enabled: bool) -> bool:
        with self.lock:
            for c in self.connectors:
                if isinstance(c, ReplaySimulator):
                    c.enabled = enabled
        return enabled

    def is_replay_enabled(self) -> bool:
        for c in self.connectors:
            if isinstance(c, ReplaySimulator):
                return bool(c.enabled)
        return False

    def add_url_source(self, source: UrlSourceIn) -> UrlFeedConnector:
        """Register an operator-configured URL feed for this API process."""
        source_id = uuid.uuid4().hex[:8]
        connector = UrlFeedConnector(source_id, source.url, source.poll_interval_seconds)
        connector.display_name = source.name.strip() if source.name else connector.name
        with self.lock:
            self.connectors.append(connector)
        return connector

    def remove_url_source(self, source_id: str) -> bool:
        with self.lock:
            before = len(self.connectors)
            self.connectors = [c for c in self.connectors if not (isinstance(c, UrlFeedConnector) and c.source_id == source_id)]
            return len(self.connectors) != before

    def start(self):
        with self.lock:
            if self.is_running:
                return
            self.is_running = True
            self._reload_connectors()
            self.thread = threading.Thread(target=self._loop, daemon=True)
            self.thread.start()
            logger.info("Live feed background thread started")

    def stop(self):
        with self.lock:
            self.is_running = False
            logger.info("Live feed background thread stopped")

    def tick_once(self) -> list[dict[str, Any]]:
        """Poll active connectors once, ingest events, and correlate into incidents."""
        all_new_records = []
        with get_session_factory()() as session:
            for connector in self.connectors:
                if not getattr(connector, "enabled", True):
                    continue
                try:
                    records = connector.poll()
                    if records:
                        from ..ingestion.pipeline import on_live_batch
                        canonical_df = on_live_batch(records, source_type=connector.name, source_ref=f"connector:{connector.name}")
                        new_batch = canonical_df.to_dict(orient="records")
                        all_new_records.extend(new_batch)
                        # Label the source feed
                        source_label = (
                            "Replay: CICIDS2017 Dataset" if isinstance(connector, ReplaySimulator)
                            else f"URL Feed: {getattr(connector, 'display_name', connector.name)}" if isinstance(connector, UrlFeedConnector)
                            else f"Feed: {connector.name}"
                        )
                        self._correlate_and_persist(session, new_batch, source_feed=source_label)
                except Exception as exc:
                    if isinstance(connector, UrlFeedConnector):
                        connector._state["last_error"] = str(exc)
                    logger.error("Connector %s failed: %s", connector.name, exc)

        return all_new_records

    def _correlate_and_persist(self, session: Session, records: list[dict[str, Any]], source_feed: str | None = None):
        if not records:
            return
        try:
            cfg = _load_config(_CONFIG_PATH)
            df = pd.DataFrame(records)
            if "label" not in df.columns:
                df["label"] = "UNKNOWN"
            df["predicted_label"] = df["label"].fillna("UNKNOWN").astype(str)

            # Assign realistic confidence based on threat label and explicit confidence
            df["confidence"] = df.apply(_infer_confidence, axis=1)

            deduped = deduplicate_events(df, int(cfg.get("correlation", {}).get("dedup_window_seconds", 60)), ["src_ip", "dst_ip", "dst_port", "predicted_label"])
            correlated = correlate_incidents(deduped, cfg)
            crit_map = load_asset_criticality(_CRIT_PATH)
            scored = score_incidents(correlated, crit_map, cfg)

            for _, row in scored.iterrows():
                inc_id = str(row["incident_id"])
                existing = session.get(Incident, inc_id)
                if not existing:
                    row_dict = row.to_dict()
                    if source_feed:
                        row_dict["source_feed"] = source_feed
                    narrative = generate_template_summary(row_dict)
                    session.add(Incident(
                        incident_id=inc_id,
                        event_ids=row["member_event_ids"],
                        mitre_techniques=row["mitre_techniques"],
                        risk_score=float(row["risk_score"]),
                        status="open",
                        llm_narrative=json.dumps(narrative)
                    ))
            session.commit()
        except Exception as exc:
            logger.error("Error during correlation: %s", exc)

    def _loop(self):
        while self.is_running:
            self.tick_once()
            time.sleep(3.0)

# Confidence baseline by threat label to yield realistic Low, Medium, High, and Critical risk tiers
_LABEL_CONFIDENCE = {
    # Low / Benign (Risk Score 5 - 25 -> Tier: LOW)
    "benign": 0.08,
    "normal": 0.08,
    "clean": 0.05,
    "unknown": 0.20,
    "info": 0.15,
    "icmp": 0.18,
    "ping": 0.18,
    # Medium (Risk Score 35 - 55 -> Tier: MEDIUM)
    "suspicious": 0.50,
    "portscan": 0.52,
    "reconnaissance": 0.50,
    "probe": 0.48,
    "nmap": 0.52,
    "directory_traversal": 0.58,
    "unusual_traffic": 0.45,
    # High (Risk Score 60 - 79 -> Tier: HIGH)
    "malicious": 0.78,
    "bruteforce": 0.75,
    "sqli": 0.80,
    "xss": 0.72,
    "command_injection": 0.82,
    "backdoor": 0.84,
    "unauthorized_access": 0.75,
    # Critical (Risk Score 80 - 100 -> Tier: CRITICAL)
    "ddos": 0.95,
    "botnet": 0.92,
    "ransomware": 0.98,
    "exfiltration": 0.94,
    "zeroday": 0.97,
}

def _infer_confidence(row: pd.Series) -> float:
    c = row.get("confidence")
    if pd.notna(c) and isinstance(c, (int, float)) and 0.0 < float(c) <= 1.0:
        return float(c)
    lbl = str(row.get("label") or "").strip().lower()
    for key, conf in _LABEL_CONFIDENCE.items():
        if key in lbl:
            return conf
    return 0.50

live_controller = LiveFeedController()

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

def _to_incident_out(inc: Incident) -> IncidentOut:
    tier = "critical" if inc.risk_score >= 80 else "high" if inc.risk_score >= 60 else "medium" if inc.risk_score >= 35 else "low"
    dominant_label = "Security Alert"
    src_ip = "Unknown Source"
    dst_ip = "Target Asset"
    source_feed = "Live Telemetry"

    if inc.llm_narrative:
        try:
            n = json.loads(inc.llm_narrative)
            dominant_label = n.get("dominant_label") or dominant_label
            src_ip = n.get("src_ip") or src_ip
            dst_ip = n.get("dst_ip") or dst_ip
            source_feed = n.get("source_feed") or source_feed
        except Exception:
            pass

    return IncidentOut(
        incident_id=inc.incident_id,
        risk_score=inc.risk_score,
        risk_tier=tier,
        status=inc.status,
        dominant_label=dominant_label,
        src_ip=src_ip,
        dst_ip=dst_ip,
        source_feed=source_feed,
        mitre_techniques=inc.mitre_techniques or [],
        event_ids=inc.event_ids or [],
        llm_narrative=inc.llm_narrative,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
    )

@app.get("/incidents", response_model=list[IncidentOut])
def list_incidents(
    status: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    query = select(Incident).order_by(desc(Incident.risk_score), desc(Incident.created_at))
    if status:
        query = query.where(Incident.status == status)
    results = db.scalars(query.offset(offset).limit(min(limit, 200))).all()
    return [_to_incident_out(inc) for inc in results]

@app.get("/incidents/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return _to_incident_out(incident)

@app.post("/incidents/{incident_id}/feedback")
def submit_feedback(incident_id: str, feedback: FeedbackIn, db: Session = Depends(get_db)):
    try:
        row = create_feedback(db, incident_id, feedback.analyst_verdict, feedback.corrected_label, feedback.notes)
        inc = db.get(Incident, incident_id)
        if inc:
            if feedback.analyst_verdict == "confirmed_threat":
                inc.status = "investigating"
            elif feedback.analyst_verdict == "false_positive":
                inc.status = "closed"
            inc.updated_at = datetime.now(timezone.utc)
            db.commit()
        from ..feedback.worker import apply_feedback_to_knowledge_base
        apply_feedback_to_knowledge_base()
    except LookupError:
        raise HTTPException(404, "Incident not found")
    return {"feedback_id": row.feedback_id, "status": "recorded", "incident_status": inc.status if inc else "open"}

def _safe_port(val: Any) -> int | None:
    if val is None or val == "" or pd.isna(val):
        return None
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return None

def _safe_str(val: Any) -> str | None:
    if val is None:
        return None
    try:
        if pd.isna(val):
            return None
    except (TypeError, ValueError):
        pass
    s = str(val).strip()
    return s if s else None

@app.get("/events/live", response_model=list[LiveFeedEvent])
def get_live_events(limit: int = 30, db: Session = Depends(get_db)):
    events = db.scalars(
        select(CanonicalEvent).order_by(desc(CanonicalEvent.ingested_at)).limit(min(limit, 100))
    ).all()
    out = []
    for ev in events:
        c = ev.canonical_fields or {}
        out.append(LiveFeedEvent(
            event_id=ev.event_id,
            source_type=ev.source_type,
            source_ref=ev.source_ref,
            ingested_at=ev.ingested_at,
            src_ip=_safe_str(c.get("src_ip")),
            dst_ip=_safe_str(c.get("dst_ip")),
            src_port=_safe_port(c.get("src_port")),
            dst_port=_safe_port(c.get("dst_port")),
            protocol=_safe_str(c.get("protocol")),
            label=_safe_str(c.get("label")),
            raw_fields=ev.raw_fields or {},
        ))
    return out

@app.get("/live-feed/status", response_model=LiveFeedStatus)
def live_feed_status(db: Session = Depends(get_db)):
    total_events = db.scalar(select(func.count(CanonicalEvent.event_id))) or 0
    total_incidents = db.scalar(select(func.count(Incident.incident_id))) or 0
    latest_event = db.scalar(select(CanonicalEvent).order_by(desc(CanonicalEvent.ingested_at)).limit(1))
    active = [c.name for c in live_controller.connectors if getattr(c, "enabled", True)]
    replay_on = live_controller.is_replay_enabled()

    descriptions = []
    for c in live_controller.connectors:
        if getattr(c, "enabled", True):
            if isinstance(c, ReplaySimulator):
                descriptions.append("Simulated Replay (CICIDS2017 Dataset)")
            elif isinstance(c, UrlFeedConnector):
                descriptions.append(f"Remote URL: {getattr(c, 'display_name', c.name)}")
            else:
                descriptions.append(c.name)
    feed_desc = " · ".join(descriptions) if descriptions else "No background feeds (listening for file uploads & URL scans)"

    return LiveFeedStatus(
        is_running=live_controller.is_running,
        active_connectors=active,
        feed_description=feed_desc,
        replay_enabled=replay_on,
        total_events=total_events,
        total_incidents=total_incidents,
        latest_event_ts=latest_event.ingested_at if latest_event else None,
    )

@app.post("/live-feed/toggle-replay")
def toggle_replay(enabled: bool = Query(...)):
    res = live_controller.set_replay_enabled(enabled)
    return {"status": "ok", "replay_enabled": res}

@app.post("/live-feed/start")
def start_live_feed():
    live_controller.start()
    return {"status": "started", "is_running": live_controller.is_running}

@app.post("/live-feed/stop")
def stop_live_feed():
    live_controller.stop()
    return {"status": "stopped", "is_running": live_controller.is_running}

@app.post("/live-feed/tick")
def trigger_tick():
    records = live_controller.tick_once()
    return {"status": "ok", "ingested_count": len(records)}

def _url_source_out(connector: UrlFeedConnector) -> UrlSourceOut:
    state = connector.get_state()
    return UrlSourceOut(
        source_id=connector.source_id, name=getattr(connector, "display_name", connector.name),
        url=connector.url, poll_interval_seconds=connector.poll_interval_seconds, enabled=connector.enabled,
        last_success_at=state.get("last_success_at"), last_record_count=state.get("last_record_count", 0),
        last_error=state.get("last_error"),
    )

@app.get("/live-feed/sources", response_model=list[UrlSourceOut])
def list_url_sources():
    return [_url_source_out(c) for c in live_controller.connectors if isinstance(c, UrlFeedConnector)]

@app.post("/live-feed/sources", response_model=UrlSourceOut, status_code=201)
def add_url_source(source: UrlSourceIn):
    try:
        return _url_source_out(live_controller.add_url_source(source))
    except UrlFeedError as exc:
        raise HTTPException(422, str(exc)) from exc

@app.post("/ingest/url")
def ingest_url_once(source: UrlSourceIn, db: Session = Depends(get_db)):
    """Fetch a remote CSV/JSON export once and send it through the SOC pipeline."""
    try:
        connector = UrlFeedConnector("one-shot", source.url, source.poll_interval_seconds)
        records = connector.poll()
        from ..ingestion.pipeline import on_live_batch
        canonical = on_live_batch(records, source_type="url_import", source_ref=connector.url)
        live_controller._correlate_and_persist(db, canonical.to_dict(orient="records"))
        return {"status": "ingested", "url": connector.url, "records_ingested": len(canonical)}
    except UrlFeedError as exc:
        raise HTTPException(422, str(exc)) from exc
    except requests.RequestException as exc:
        raise HTTPException(502, "The remote source could not be fetched.") from exc

@app.delete("/live-feed/sources/{source_id}", status_code=204)
def delete_url_source(source_id: str):
    if not live_controller.remove_url_source(source_id):
        raise HTTPException(404, "URL feed source not found")

@app.get("/stats", response_model=SOCStats)
def get_stats(db: Session = Depends(get_db)):
    total_events = db.scalar(select(func.count(CanonicalEvent.event_id))) or 0
    incidents = db.scalars(select(Incident)).all()
    total_inc = len(incidents)
    crit = sum(1 for i in incidents if i.risk_score >= 80)
    high = sum(1 for i in incidents if 60 <= i.risk_score < 80)
    med = sum(1 for i in incidents if 35 <= i.risk_score < 60)
    low = sum(1 for i in incidents if i.risk_score < 35)
    open_inc = sum(1 for i in incidents if i.status in ["open", "investigating"])

    mitre_counter: Counter[str] = Counter()
    for i in incidents:
        for t in i.mitre_techniques or []:
            mitre_counter[t] += 1

    events = db.scalars(select(CanonicalEvent).limit(300)).all()
    label_counter: Counter[str] = Counter()
    for e in events:
        lbl = (e.canonical_fields or {}).get("label")
        if lbl is not None and pd.notna(lbl) and str(lbl).strip() != "":
            label_counter[str(lbl)] += 1

    return SOCStats(
        total_events=total_events,
        total_incidents=total_inc,
        critical_incidents=crit,
        high_incidents=high,
        medium_incidents=med,
        low_incidents=low,
        open_incidents=open_inc,
        mitre_distribution=dict(mitre_counter.most_common(10)),
        top_threat_labels=dict(label_counter.most_common(8)),
    )

@app.get("/kb")
def get_knowledge_base(db: Session = Depends(get_db)):
    rows = db.scalars(select(KnowledgeBaseEntry).order_by(desc(KnowledgeBaseEntry.created_at)).limit(50)).all()
    return [
        {
            "kb_id": r.kb_id,
            "source": r.source,
            "source_ref_id": r.source_ref_id,
            "text_chunk": r.text_chunk,
            "created_at": r.created_at
        } for r in rows
    ]


# ---------------------------------------------------------------------------
# FILE UPLOAD & INGESTION ENDPOINT
# ---------------------------------------------------------------------------

# Allowed extensions and their MIME-like types
_ALLOWED_EXTS = {".csv", ".json", ".log", ".txt", ".md", ".xlsx", ".syslog"}
_UPLOAD_DIR = Path(__file__).resolve().parents[2] / "data" / "uploads"


def _run_ingestion_on_file(file_path: Path, original_name: str, db: Session) -> dict[str, Any]:
    """Run the M1 ingestion pipeline on a single uploaded file and persist to DB."""
    from ..ingestion.pipeline import run_ingestion
    out_dir = _UPLOAD_DIR / "processed" / file_path.stem
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = run_ingestion(file_path.parent, out_dir)
    # After ingestion, read the resulting parquet and persist to DB
    processed = out_dir / "processed.parquet"
    if processed.exists():
        df = pd.read_parquet(processed)
        # Process sample of events (up to 10,000) for instant correlation and responsiveness
        sample_df = df.head(10000)
        source_label = f"Upload: {original_name}"
        live_controller._correlate_and_persist(db, sample_df.to_dict(orient="records"), source_feed=source_label)
    return {
        "source_file": original_name,
        "files_processed": summary.get("files_processed", 0),
        "total_rows": summary.get("total_rows", 0),
        "total_chunks": summary.get("total_chunks", 0),
    }


@app.post("/upload")
async def upload_log_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Upload a log / data file (CSV, JSON, syslog, .log, .txt, .md, .xlsx).
    The file is run through the full M1 ingestion pipeline → M4 correlation → DB.
    """
    suffix = Path(file.filename or "upload.log").suffix.lower()
    if suffix not in _ALLOWED_EXTS:
        raise HTTPException(
            400,
            f"Unsupported file type '{suffix}'. Supported: {', '.join(sorted(_ALLOWED_EXTS))}"
        )

    # Save to a temp directory named after the upload
    upload_id = str(uuid.uuid4())[:8]
    upload_folder = _UPLOAD_DIR / upload_id
    upload_folder.mkdir(parents=True, exist_ok=True)
    dest = upload_folder / (file.filename or f"upload{suffix}")

    try:
        with dest.open("wb") as fh:
            shutil.copyfileobj(file.file, fh)
    finally:
        await file.close()

    try:
        result = _run_ingestion_on_file(dest, file.filename or dest.name, db)
    except Exception as exc:
        logger.error("Ingestion failed for upload %s: %s", file.filename, exc)
        raise HTTPException(500, f"Ingestion failed: {exc}") from exc

    return {
        "status": "ingested",
        "upload_id": upload_id,
        "filename": file.filename,
        **result,
        "message": f"✓ {result['total_rows']} events ingested from {file.filename} and correlated into incidents."
    }


@app.get("/upload/history")
def upload_history():
    """List previously uploaded files with basic metadata."""
    _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for folder in sorted(_UPLOAD_DIR.iterdir(), reverse=True):
        if not folder.is_dir() or folder.name == "processed":
            continue
        for f in folder.iterdir():
            stat = f.stat()
            results.append({
                "upload_id": folder.name,
                "filename": f.name,
                "size_bytes": stat.st_size,
                "uploaded_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            })
    return results[:50]


# ---------------------------------------------------------------------------
# URL / HOST TRACKER ENDPOINT
# ---------------------------------------------------------------------------

_KNOWN_MALICIOUS_ASNS = {"AS208046", "AS206728", "AS397444"}
_RESERVED_SUBNETS = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|localhost)"
)


def _resolve_host(target: str) -> str | None:
    """Resolve hostname to IP; return None on failure."""
    clean = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    try:
        return socket.gethostbyname(clean)
    except socket.gaierror:
        return None


def _scan_target_intel(target: str) -> dict[str, Any]:
    """Perform real-time multi-vector threat intelligence and live HTTP inspection."""
    import os
    clean_target = target.strip()
    is_url = clean_target.startswith(("http://", "https://"))
    url_to_test = clean_target if is_url else f"http://{clean_target}"
    domain = re.sub(r"^https?://", "", clean_target).split("/")[0].split(":")[0]

    ip = None
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        pass

    flags: list[str] = []
    risk_score = 0.0

    # 1. Live HTTP probe if possible
    try:
        t0 = time.time()
        resp = requests.get(url_to_test, timeout=3.5, headers={"User-Agent": "AI-SOC-Scanner/2.0"}, allow_redirects=True)
        latency_ms = int((time.time() - t0) * 1000)
        status_code = resp.status_code
        server_hdr = resp.headers.get("Server", "Web Server")
        flags.append(f"HTTP {status_code} ({latency_ms}ms) · Server: {server_hdr[:30]}")

        # Check security headers
        missing_sec = []
        if "Strict-Transport-Security" not in resp.headers and is_url and clean_target.startswith("https:"):
            missing_sec.append("Missing HSTS")
        if "X-Content-Type-Options" not in resp.headers:
            missing_sec.append("Missing nosniff")
        if missing_sec:
            flags.append(" · ".join(missing_sec))
            risk_score += 10.0
    except requests.exceptions.SSLError:
        flags.append("SSL/TLS Certificate Validation Failed")
        risk_score += 35.0
    except requests.exceptions.ConnectionError:
        flags.append("Connection Refused / Host Unreachable")
        risk_score += 15.0
    except requests.exceptions.Timeout:
        flags.append("Request Timed Out (>3.5s)")
        risk_score += 20.0
    except Exception as exc:
        flags.append(f"Probe: {str(exc)[:40]}")

    # 2. IP & Network Heuristics
    if ip:
        is_private = bool(_RESERVED_SUBNETS.match(ip))
        if is_private:
            flags.append("Private/RFC1918 Subnet")
            risk_score += 5.0
    else:
        flags.append("DNS Resolution Failed")
        risk_score += 25.0

    # 3. Known threat patterns
    lower_t = clean_target.lower()
    if any(kw in lower_t for kw in ["torproject", "onion", "darkweb", "bulletproof", "c2", "botnet", "malware"]):
        risk_score += 65.0
        flags.append("Known Threat Indicator Pattern")
    if re.search(r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}", lower_t):
        risk_score += 15.0
        flags.append("Dynamic IP Hostname Pattern")

    # If AbuseIPDB API key available and public IP
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    source_name = "Heuristic + Live Probe"
    if api_key and ip and not _RESERVED_SUBNETS.match(ip):
        try:
            intel = _abuseipdb_lookup(ip, api_key)
            risk_score = max(risk_score, intel["risk_score"])
            flags.extend(intel.get("flags", []))
            source_name = "AbuseIPDB + Live Probe"
        except Exception:
            pass

    risk_score = min(max(risk_score, 5.0), 98.0)
    label = (
        "BENIGN" if risk_score < 25
        else "Suspicious" if risk_score < 60
        else "Malicious"
    )
    confidence = round(min(max(risk_score / 100.0 + 0.1, 0.40), 0.98), 2)

    return {
        "resolved_ip": ip or "Unresolved",
        "risk_score": round(risk_score, 1),
        "confidence": confidence,
        "label": label,
        "flags": flags,
        "source": source_name,
    }


def _abuseipdb_lookup(ip: str, api_key: str) -> dict[str, Any]:
    """Query AbuseIPDB for reputation data. Returns raw API result."""
    import requests as req_lib
    resp = req_lib.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        timeout=8,
    )
    resp.raise_for_status()
    data = resp.json().get("data", {})
    abuse_score = data.get("abuseConfidenceScore", 0)
    return {
        "resolved_ip": ip,
        "risk_score": round(abuse_score * 0.85, 1),
        "confidence": round(abuse_score / 100, 3),
        "label": "BENIGN" if abuse_score < 10 else "Suspicious" if abuse_score < 50 else "Malicious",
        "flags": [r.get("comment", "")[:80] for r in data.get("reports", [])[:3]],
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "total_reports": data.get("totalReports", 0),
        "last_reported": data.get("lastReportedAt"),
        "source": "AbuseIPDB",
    }


_scan_history: list[dict[str, Any]] = []


@app.post("/scan/url")
def scan_url(payload: dict[str, Any], db: Session = Depends(get_db)):
    """
    Scan a URL, hostname, or raw IP for threat intelligence and live security headers.
    """
    target: str = (payload.get("target") or "").strip()
    if not target:
        raise HTTPException(400, "Field 'target' is required.")

    intel = _scan_target_intel(target)

    scan_record = {
        "scan_id": str(uuid.uuid4())[:8],
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        **intel,
    }
    _scan_history.insert(0, scan_record)
    if len(_scan_history) > 100:
        _scan_history.pop()

    # If the target is suspicious or malicious, create a synthetic event + incident
    if intel["risk_score"] >= 20:
        record = {
            "event_id": str(uuid.uuid4()),
            "source_type": "url_scan",
            "source_ref": target,
            "src_ip": intel["resolved_ip"],
            "dst_ip": "10.0.0.1 (SOC Monitor)",
            "label": intel["label"],
            "protocol": "HTTP/S",
            "confidence": intel["confidence"],
        }
        try:
            from ..ingestion.pipeline import on_live_batch
            canonical_df = on_live_batch([record], source_type="url_scan", source_ref=target)
            live_controller._correlate_and_persist(db, canonical_df.to_dict(orient="records"), source_feed=f"URL Scan: {target}")
        except Exception as exc:
            logger.error("Failed to persist URL scan event: %s", exc)

    return scan_record


@app.get("/scan/history")
def scan_history():
    """Return the last 50 URL/host scans performed in this session."""
    return _scan_history[:50]

