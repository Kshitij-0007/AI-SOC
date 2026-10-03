"""Group related deduplicated alerts into incidents."""
from __future__ import annotations

import uuid
import pandas as pd


def correlate_incidents(df: pd.DataFrame, config: dict) -> pd.DataFrame:
    """Assign incident IDs by attacking source IP and bounded time windows."""
    if df.empty:
        return df.assign(incident_id=pd.Series(dtype="object"))
    window = int(config.get("correlation", {}).get("incident_window_seconds", 300))
    work = df.copy()
    work["first_seen"] = pd.to_datetime(work["first_seen"], utc=True, errors="coerce")
    work = work.sort_values(["src_ip", "first_seen"], na_position="last")
    incident_ids: dict[int, str] = {}
    for source_ip, group in work.groupby("src_ip", dropna=False, sort=False):
        previous = None
        current = None
        for index, row in group.iterrows():
            timestamp = row["first_seen"]
            if pd.isna(source_ip) or previous is None or pd.isna(timestamp) or (timestamp - previous).total_seconds() > window:
                current = str(uuid.uuid4())
            incident_ids[index] = current
            previous = timestamp
    work["incident_id"] = work.index.map(incident_ids)
    return work
