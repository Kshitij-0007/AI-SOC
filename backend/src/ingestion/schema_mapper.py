"""
schema_mapper.py — Maps arbitrary DataFrames to the canonical AI-SOC schema.

The canonical schema is defined by ``CANONICAL_COLUMNS``.  Column aliases
cover common column names found in CICIDS2017, NSL-KDD, and UNSW-NB15
benchmark datasets, plus generic networking field names.

Usage::

    from src.ingestion.schema_mapper import map_to_canonical
    canonical_df = map_to_canonical(raw_df, source_format="csv")
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Canonical column list (order matters — output DataFrame uses this order)
# ---------------------------------------------------------------------------

CANONICAL_COLUMNS: list[str] = [
    "event_id",
    "timestamp",
    "source_file",
    "source_format",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "flow_duration",
    "bytes_sent",
    "bytes_received",
    "packet_count",
    "label",
    "raw_text",
    "extracted_entities",
    "extra_fields",
]

# ---------------------------------------------------------------------------
# Alias map — canonical_name → [known alternate names]
# ---------------------------------------------------------------------------

COLUMN_ALIASES: dict[str, list[str]] = {
    "event_id": ["id", "event_id", "uid", "flow_id", "FlowID", "flow id"],
    "timestamp": [
        "timestamp", "Timestamp", "time", "Time", "datetime", "ts",
        "start_time", "StartTime", "flow_start", "Flow Start",
        "stime",          # UNSW-NB15
        "date",
    ],
    "source_file": ["source_file", "SourceFile"],
    "source_format": ["source_format", "SourceFormat", "format"],
    "src_ip": [
        "src_ip", "source_ip", "srcip", "Src IP", "SrcIP",
        "src", "Source IP", "id.orig_h",  # Zeek
        "saddr",          # UNSW-NB15
        "src ip", "client_ip", "origin_ip", "attacker_ip", "source_host", "source",
    ],
    "dst_ip": [
        "dst_ip", "destination_ip", "dstip", "Dst IP", "DstIP",
        "dst", "Destination IP", "id.resp_h",  # Zeek
        "daddr",          # UNSW-NB15
        "dst ip", "dest_ip", "dest", "destination", "target_ip", "target", "server_ip", "dst_host",
    ],
    "src_port": [
        "src_port", "source_port", "Src Port", "SrcPort",
        "sport",          # UNSW-NB15
        "id.orig_p",      # Zeek
        "src port",
    ],
    "dst_port": [
        "dst_port", "destination_port", "Dst Port", "DstPort",
        "dport",          # UNSW-NB15
        "id.resp_p",      # Zeek
        "dst port", "dest_port",
    ],
    "protocol": [
        "protocol", "Protocol", "proto", "Proto",
        "service",        # NSL-KDD
        "proto_name",
    ],
    "flow_duration": [
        "flow_duration", "Flow Duration", "FlowDuration", "duration",
        "dur",            # UNSW-NB15
        "Duration",
    ],
    "bytes_sent": [
        "bytes_sent", "Total Fwd Packets",  # CICIDS2017 (proxy)
        "Fwd Packet Length Sum",
        "sbytes",         # UNSW-NB15
        "src_bytes",      # NSL-KDD
        "Total Length of Fwd Packets",
        "bytes_out",
        "bytes_transferred", "bytes", "size",
    ],
    "bytes_received": [
        "bytes_received",
        "Total Bwd Packets",              # CICIDS2017 (proxy)
        "Bwd Packet Length Sum",
        "dbytes",                         # UNSW-NB15
        "dst_bytes",                      # NSL-KDD
        "Total Length of Bwd Packets",
        "bytes_in",
    ],
    "packet_count": [
        "packet_count", "Packet Count", "num_pkts",
        "total_packets",
        "Total Fwd Packets_count",
        "dpkts",          # UNSW-NB15
        "spkts",          # UNSW-NB15
        "count",          # NSL-KDD
    ],
    "label": [
        "label", "Label", "class", "Class", "attack_type",
        "attack_cat",     # UNSW-NB15
        "Attack", " Label",
        "threat_label", "threat", "threat_type", "alert_type", "verdict",
        "category", "prediction",
    ],
    "raw_text": ["raw_text"],
    "extracted_entities": ["extracted_entities"],
    "extra_fields": ["extra_fields"],
}

# Build a reverse lookup: alias → canonical_name (including normalized lowercase)
_ALIAS_REVERSE: dict[str, str] = {}
for _canonical, _aliases in COLUMN_ALIASES.items():
    for _alias in _aliases:
        _ALIAS_REVERSE[_alias] = _canonical
        _ALIAS_REVERSE[_alias.strip().lower()] = _canonical
        _ALIAS_REVERSE[_alias.strip().lower().replace("_", "")] = _canonical


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_rename_map(df_columns: list[str]) -> dict[str, str]:
    """
    Return a dict of {original_col: canonical_col} for columns that match
    a known alias.  Only the *first* match for each canonical target is used
    to avoid duplicating columns. Supports exact and case-normalized matching.
    """
    rename: dict[str, str] = {}
    used_targets: set[str] = set()
    for col in df_columns:
        # 1. Exact match
        target = _ALIAS_REVERSE.get(col)
        # 2. Normalized lowercase match
        if not target:
            target = _ALIAS_REVERSE.get(col.strip().lower())
        # 3. Cleaned match without spaces/underscores
        if not target:
            target = _ALIAS_REVERSE.get(col.strip().lower().replace("_", "").replace(" ", ""))
        if target and target not in used_targets:
            rename[col] = target
            used_targets.add(target)
    return rename


def _collapse_extra(df: pd.DataFrame, matched_originals: set[str]) -> pd.Series:
    """
    Collapse all columns not in *matched_originals* into a JSON string per row.
    Returns a Series of JSON strings (or empty-dict string for rows with no extras).
    """
    extra_cols = [c for c in df.columns if c not in matched_originals]
    if not extra_cols:
        return pd.Series([json.dumps({})] * len(df), index=df.index)

    def _row_to_json(row: Any) -> str:
        return json.dumps(
            {c: (None if pd.isna(v) else v) for c, v in zip(extra_cols, row)},
            default=str,
        )

    return df[extra_cols].apply(_row_to_json, axis=1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_to_canonical(df: pd.DataFrame, source_format: str) -> pd.DataFrame:
    """
    Rename, fill, and reorder *df* columns to match the canonical schema.

    Steps:

    1. Rename alias columns to their canonical equivalents.
    2. Collapse any remaining unmatched columns into ``extra_fields`` (JSON).
    3. Add any canonical column that is still absent, filled with ``None``.
    4. Return a DataFrame with **exactly** :data:`CANONICAL_COLUMNS` in order.

    Parameters
    ----------
    df:
        Input DataFrame (may have arbitrary column names).
    source_format:
        Value to use for the ``source_format`` column if not already present.

    Returns
    -------
    pd.DataFrame
        Exactly ``CANONICAL_COLUMNS`` columns in canonical order.
    """
    df = df.copy()

    # Ensure provenance columns exist
    if "source_format" not in df.columns:
        df["source_format"] = source_format

    # 1. Build and apply rename map
    rename_map = _build_rename_map(list(df.columns))
    df.rename(columns=rename_map, inplace=True)

    # 2. Track which original columns are now canonical
    canonical_set = set(CANONICAL_COLUMNS)
    matched = set(df.columns) & canonical_set

    # 3. Collapse unmatched into extra_fields
    extra_series = _collapse_extra(df, matched)
    # Merge with any existing extra_fields
    if "extra_fields" in df.columns:
        def _merge(existing: Any, new: str) -> str:
            try:
                base = json.loads(new)
                old = json.loads(existing) if pd.notna(existing) else {}
                base.update(old)
                return json.dumps(base, default=str)
            except Exception:  # noqa: BLE001
                return new
        df["extra_fields"] = [_merge(e, n) for e, n in zip(df["extra_fields"], extra_series)]
    else:
        df["extra_fields"] = extra_series

    # Drop the non-canonical columns (they're now in extra_fields)
    extra_cols = [c for c in df.columns if c not in canonical_set]
    df.drop(columns=extra_cols, inplace=True)

    # 4. Add missing canonical columns as None
    for col in CANONICAL_COLUMNS:
        if col not in df.columns:
            df[col] = None

    logger.debug(
        "map_to_canonical: %d rows, source_format=%s, extra_cols_collapsed=%d",
        len(df),
        source_format,
        len(extra_cols),
    )
    return df[CANONICAL_COLUMNS]


def map_live_record(record: dict[str, Any], source_type: str, source_ref: str) -> dict[str, Any]:
    """Map one connector record to the same canonical contract as a file row.

    Transport metadata intentionally stays outside the canonical table and is
    persisted by the repository as event provenance.
    """
    canonical = map_to_canonical(pd.DataFrame([record]), source_format=source_type)
    result = canonical.iloc[0].where(pd.notna(canonical.iloc[0]), None).to_dict()
    result["source_file"] = result.get("source_file") or source_ref
    result["source_format"] = source_type
    return result
