"""Linear-time-per-key rolling alert deduplication."""
from __future__ import annotations

import json
from typing import Any

import pandas as pd


def deduplicate_events(df: pd.DataFrame, window_seconds: int, key_columns: list[str]) -> pd.DataFrame:
    """Collapse equal-key events in rolling windows while retaining every event ID."""
    required = {"event_id", "timestamp", "confidence", *key_columns}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Cannot deduplicate events; missing columns: {sorted(missing)}")
    work = df.copy()
    work["timestamp"] = pd.to_datetime(work["timestamp"], utc=True, errors="coerce")
    work = work.sort_values(key_columns + ["timestamp"], na_position="last")
    rows: list[dict[str, Any]] = []
    for _, group in work.groupby(key_columns, dropna=False, sort=False):
        bucket: list[dict[str, Any]] = []
        last_seen = None
        for record in group.to_dict(orient="records"):
            timestamp = record["timestamp"]
            if bucket and (pd.isna(timestamp) or pd.isna(last_seen) or (timestamp - last_seen).total_seconds() > window_seconds):
                rows.append(_collapse(bucket))
                bucket = []
            bucket.append(record)
            last_seen = timestamp
        if bucket:
            rows.append(_collapse(bucket))
    return pd.DataFrame(rows)


def _collapse(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Produce a loss-aware representative row for one rolling bucket."""
    first = records[0].copy()
    times = [r["timestamp"] for r in records if pd.notna(r["timestamp"])]
    first["first_seen"] = min(times) if times else pd.NaT
    first["last_seen"] = max(times) if times else pd.NaT
    first["occurrence_count"] = len(records)
    first["confidence"] = max(float(r.get("confidence") or 0) for r in records)
    first["member_event_ids"] = json.dumps([str(r["event_id"]) for r in records])
    return first
