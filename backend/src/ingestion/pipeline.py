"""
pipeline.py — Top-level ingestion orchestrator.

``run_ingestion`` walks an input directory, dispatches each file to the
correct parser, maps results to the canonical schema, and writes three
output artefacts:

* ``processed.parquet``       — unified canonical table (tabular + log sources)
* ``knowledge_chunks.jsonl``  — text chunks + extracted entities (txt/md sources)
* ``ingestion_log.jsonl``     — one-line-per-file audit log (ok / error)

No file failure ever stops the batch; errors are caught, logged, and
recorded in ``ingestion_log.jsonl``.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd

from .format_detector import FormatType, detect_format
from .parsers.csv_xlsx_parser import parse_tabular
from .parsers.log_parser import parse_log
from .parsers.text_parser import parse_text
from .schema_mapper import CANONICAL_COLUMNS, map_live_record, map_to_canonical

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Output file names
# ---------------------------------------------------------------------------

_PARQUET_OUT = "processed.parquet"
_CHUNKS_OUT = "knowledge_chunks.jsonl"
_LOG_OUT = "ingestion_log.jsonl"

# Formats handled by tabular parser
_TABULAR_FMTS = {FormatType.CSV, FormatType.XLSX}

# Formats handled by log parser
_LOG_FMTS = {FormatType.JSON_LOG, FormatType.SYSLOG, FormatType.LOG}

# Formats handled by text parser
_TEXT_FMTS = {FormatType.TXT, FormatType.MD}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return current UTC time as an ISO 8601 string."""
    return datetime.now(tz=timezone.utc).isoformat()


def _ensure_event_ids(df: pd.DataFrame) -> pd.DataFrame:
    """Fill missing ``event_id`` values with generated UUID4 strings."""
    # Cast to object so string UUIDs can be assigned regardless of inferred dtype
    df["event_id"] = df["event_id"].astype(object)
    mask = df["event_id"].isna() | (df["event_id"].astype(str).str.strip() == "")
    if mask.any():
        df.loc[mask, "event_id"] = [str(uuid.uuid4()) for _ in range(int(mask.sum()))]
    return df


def _coerce_types(df: pd.DataFrame) -> pd.DataFrame:
    """
    Coerce numeric-intent columns to nullable pandas dtypes so pyarrow
    can write them to parquet even when they contain None/NaN alongside ints.
    """
    int_cols = ["src_port", "dst_port", "packet_count"]
    float_cols = ["flow_duration", "bytes_sent", "bytes_received"]
    for col in int_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").astype("Int64")
    for col in float_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").astype("Float64")
    return df


def _append_log(log_path: Path, record: dict[str, Any]) -> None:
    """Append a single JSON record to the audit log file."""
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, default=str) + "\n")


def _append_chunk(chunks_path: Path, source_file: str, chunk: str, entities: dict) -> None:
    """Append a single knowledge chunk to the JSONL chunks file."""
    with chunks_path.open("a", encoding="utf-8") as fh:
        obj = {"source_file": source_file, "chunk_text": chunk, "entities": entities}
        fh.write(json.dumps(obj, default=str) + "\n")


def _persist_file_batch(df: pd.DataFrame, source_type: str, source_ref: str) -> None:
    """Write a canonical file batch to the system of record in one transaction.

    Attempts database persistence; if db/sqla is not available, silently
    falls back to no-op so the pipeline never crashes due to a missing
    database dependency.
    """
    try:
        from ..db import create_schema, get_session_factory
        from ..db.repositories import persist_events

        create_schema()
        with get_session_factory()() as session:
            persist_events(session, df.to_dict(orient="records"), source_type, source_ref)
    except Exception:  # noqa: BLE001
        # Database not configured / sqlalchemy not installed —
        # pipeline continues with file-only outputs.
        logger.debug(
            "Database persistence skipped for %s (db not available)", source_ref,
        )


def on_live_batch(records: list[dict[str, Any]], source_type: str, source_ref: str) -> pd.DataFrame:
    """Map and persist a live batch through the exact same canonical contract."""
    if not records:
        return pd.DataFrame(columns=CANONICAL_COLUMNS)
    mapped = [map_live_record(record, source_type, source_ref) for record in records]
    canonical = _coerce_types(_ensure_event_ids(pd.DataFrame(mapped)[CANONICAL_COLUMNS]))
    _persist_file_batch(canonical, source_type, source_ref)
    return canonical


# ---------------------------------------------------------------------------
# Per-format handlers
# ---------------------------------------------------------------------------

def _handle_tabular(file_path: Path, fmt: FormatType) -> pd.DataFrame:
    """Parse a tabular file and return a canonical-mapped DataFrame."""
    raw_df = parse_tabular(file_path)
    return map_to_canonical(raw_df, source_format=fmt.value)


def _handle_log(file_path: Path, fmt: FormatType) -> pd.DataFrame:
    """Parse a log file, convert records to DataFrame, and map to canonical."""
    records = parse_log(file_path, fmt)
    if not records:
        return pd.DataFrame(columns=CANONICAL_COLUMNS)
    raw_df = pd.DataFrame(records)
    return map_to_canonical(raw_df, source_format=fmt.value)


def _handle_text(
    file_path: Path,
    fmt: FormatType,
    chunks_path: Path,
) -> tuple[pd.DataFrame, int]:
    """
    Parse a text/markdown file, write chunks to JSONL, and return a
    one-row canonical DataFrame summarising the file plus chunk count.
    """
    entities, chunks = parse_text(file_path, fmt)
    src = str(file_path)

    for chunk in chunks:
        _append_chunk(chunks_path, src, chunk, entities)

    # Build a single summary row for the canonical table
    row: dict[str, Any] = {c: None for c in CANONICAL_COLUMNS}
    row["event_id"] = str(uuid.uuid4())
    row["timestamp"] = _utc_now()
    row["source_file"] = src
    row["source_format"] = fmt.value
    row["raw_text"] = " ".join(chunks)[:4000]  # truncated for parquet
    row["extracted_entities"] = json.dumps(entities)
    row["extra_fields"] = json.dumps({})

    return pd.DataFrame([row])[CANONICAL_COLUMNS], len(chunks)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_ingestion(input_dir: Path, output_dir: Path) -> dict[str, int]:
    """
    Walk *input_dir* recursively, parse every recognised file, and write
    three output artefacts to *output_dir*.

    Parameters
    ----------
    input_dir:
        Directory containing raw input files (searched recursively).
    output_dir:
        Directory where ``processed.parquet``, ``knowledge_chunks.jsonl``,
        and ``ingestion_log.jsonl`` will be written.

    Returns
    -------
    dict
        Summary: ``files_processed``, ``files_failed``, ``total_rows``,
        ``total_chunks``.
    """
    input_dir = Path(input_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    log_path = output_dir / _LOG_OUT
    chunks_path = output_dir / _CHUNKS_OUT

    all_frames: list[pd.DataFrame] = []
    files_processed = 0
    files_failed = 0
    total_chunks = 0

    for file_path in sorted(input_dir.rglob("*")):
        if not file_path.is_file():
            continue

        fmt = detect_format(file_path)
        if fmt == FormatType.UNKNOWN:
            logger.warning("Skipping unknown format: %s", file_path)
            _append_log(log_path, {
                "source_file": str(file_path),
                "detected_format": fmt.value,
                "status": "skipped",
                "rows_extracted": 0,
                "error_message": "unknown format",
            })
            continue

        try:
            if fmt in _TABULAR_FMTS:
                df = _handle_tabular(file_path, fmt)
                chunks_n = 0
            elif fmt in _LOG_FMTS:
                df = _handle_log(file_path, fmt)
                chunks_n = 0
            else:  # TEXT / MD
                df, chunks_n = _handle_text(file_path, fmt, chunks_path)
                total_chunks += chunks_n

            df = _ensure_event_ids(df)
            _persist_file_batch(df, "file", str(file_path))
            all_frames.append(df)
            rows = len(df)
            files_processed += 1

            _append_log(log_path, {
                "source_file": str(file_path),
                "source_type": "file",
                "detected_format": fmt.value,
                "status": "ok",
                "rows_extracted": rows,
                "error_message": None,
            })
            logger.info("✓ %s [%s] → %d rows, %d chunks", file_path.name, fmt.value, rows, chunks_n)

        except Exception as exc:  # noqa: BLE001
            files_failed += 1
            logger.error("✗ %s failed: %s", file_path, exc, exc_info=True)
            _append_log(log_path, {
                "source_file": str(file_path),
                "source_type": "file",
                "detected_format": fmt.value,
                "status": "error",
                "rows_extracted": 0,
                "error_message": str(exc),
            })

    # Write consolidated parquet
    if all_frames:
        final_df = pd.concat(all_frames, ignore_index=True)
        final_df = final_df[CANONICAL_COLUMNS]
    else:
        final_df = pd.DataFrame(columns=CANONICAL_COLUMNS)

    final_df = _coerce_types(final_df)
    parquet_path = output_dir / _PARQUET_OUT
    final_df.to_parquet(parquet_path, index=False)
    total_rows = len(final_df)

    summary = {
        "files_processed": files_processed,
        "files_failed": files_failed,
        "total_rows": total_rows,
        "total_chunks": total_chunks,
    }
    logger.info("Ingestion complete: %s", summary)
    print(f"\n{'='*50}\nIngestion Summary\n{'='*50}")
    for k, v in summary.items():
        print(f"  {k:<20}: {v}")
    print(f"  output_dir        : {output_dir}")
    print(f"{'='*50}\n")
    return summary


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    ap = argparse.ArgumentParser(description="AI-SOC Ingestion Pipeline")
    ap.add_argument(
        "--input-dir",
        default="tests/fixtures/ingestion",
        help="Directory of raw input files (default: tests/fixtures/ingestion)",
    )
    ap.add_argument(
        "--output-dir",
        default="data/processed",
        help="Directory for output artefacts (default: data/processed)",
    )
    args = ap.parse_args()

    run_ingestion(Path(args.input_dir), Path(args.output_dir))
