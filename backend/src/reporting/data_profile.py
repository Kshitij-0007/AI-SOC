"""
data_profile.py — Pull "Input" section numbers straight from the manifest.

Does NOT re-scan raw files — the manifest already has this information
from prepare_real_dataset / generate_dummy_dataset.  Adds only a
human-readable format_description string built from the first raw file's
header row.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict

import pandas as pd

logger = logging.getLogger(__name__)


def summarize_input(manifest_entry: dict, raw_dir: Path) -> dict[str, Any]:
    """
    Return the "Input" section dict for a dataset run.

    Parameters
    ----------
    manifest_entry : dict
        The manifest entry for this dataset (real_* or dummy), expected to
        contain keys from prepare_real_dataset / generate_dummy_dataset
        return values: ``"files_found"``, ``"total_rows"``, ``"class_distribution"``.
    raw_dir : Path
        Path to the raw input directory.  Used only to read the first file's
        header row for the ``format_description`` add-on.

    Returns
    -------
    dict
        Keys: ``"rows"``, ``"columns"``, ``"format_description"``,
        ``"class_distribution"``, plus any other keys the manifest entry
        already provided.
    """
    files_found = manifest_entry.get("files_found", [])
    total_rows = manifest_entry.get("total_rows", 0)
    class_dist = manifest_entry.get("class_distribution", {})

    # Read first raw file header for format description
    format_description: str = ""
    if raw_dir.is_dir():
        for child in sorted(raw_dir.rglob("*")):
            if child.is_file() and child.suffix.lower() in (".csv", ".txt", ".jsonl"):
                try:
                    header_line = child.read_text(errors="replace").splitlines()[0]
                    format_description = (
                        f"CSV, {len(header_line.split(','))} columns: {header_line[:80]}"
                        if header_line.strip()
                        else "Raw file found, header unreadable"
                    )
                    break
                except Exception:
                    format_description = "Raw file found, could not read header"
                    continue
    if not format_description:
        format_description = "No raw files found"

    return {
        "rows": total_rows,
        "columns": None,  # will be filled after ingestion
        "format_description": format_description,
        "class_distribution": class_dist,
    }