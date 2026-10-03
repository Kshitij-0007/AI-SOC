"""
format_detector.py — Detects the format of an incoming file.

Detection order:
1. File extension (.csv, .xlsx, .log, .txt, .md)
2. For .log / extension-less files: peek at first non-empty line
   - Valid JSON  → JSON_LOG
   - Syslog-style pattern → SYSLOG
   - Otherwise   → LOG
3. Nothing matches → UNKNOWN (logged, never raised)
"""

from __future__ import annotations

import logging
import re
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

# Syslog pattern: e.g. "Sep 14 12:34:56"
_SYSLOG_RE = re.compile(r"^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}")


class FormatType(str, Enum):
    """Supported source-file format types."""

    CSV = "csv"
    XLSX = "xlsx"
    LOG = "log"
    SYSLOG = "syslog"
    JSON_LOG = "json_log"
    TXT = "txt"
    MD = "md"
    UNKNOWN = "unknown"


# Extension → FormatType fast-path
_EXT_MAP: dict[str, FormatType] = {
    ".csv": FormatType.CSV,
    ".xlsx": FormatType.XLSX,
    ".xls": FormatType.XLSX,
    ".txt": FormatType.TXT,
    ".md": FormatType.MD,
}


def _sniff_first_line(file_path: Path) -> str | None:
    """Return the first non-empty line of a text file, or None on failure."""
    try:
        with file_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped:
                    return stripped
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not read %s for sniffing: %s", file_path, exc)
    return None


def _detect_by_content(file_path: Path) -> FormatType:
    """Sniff content to distinguish JSON_LOG / SYSLOG / LOG."""
    import json  # lazy import — stdlib only

    first = _sniff_first_line(file_path)
    if first is None:
        return FormatType.UNKNOWN

    # JSON object on the first line → JSON_LOG
    if first.startswith("{"):
        try:
            json.loads(first)
            return FormatType.JSON_LOG
        except json.JSONDecodeError:
            pass

    # Syslog-style timestamp at line start
    if _SYSLOG_RE.match(first):
        return FormatType.SYSLOG

    return FormatType.LOG


def detect_format(file_path: Path) -> FormatType:
    """
    Detect the format of *file_path* and return the appropriate
    :class:`FormatType`.

    Parameters
    ----------
    file_path:
        Absolute or relative path to the file to inspect.

    Returns
    -------
    FormatType
        Never raises — returns ``FormatType.UNKNOWN`` on any failure.
    """
    path = Path(file_path)
    ext = path.suffix.lower()

    # Fast-path via extension
    if ext in _EXT_MAP:
        return _EXT_MAP[ext]

    # .log or no extension → content sniff
    if ext in (".log", ".jsonl", "") :
        return _detect_by_content(path)

    # .json extension could be JSON_LOG or a plain JSON; treat as JSON_LOG
    if ext == ".json":
        return FormatType.JSON_LOG

    logger.warning("Unknown extension '%s' for file %s — returning UNKNOWN", ext, path)
    return FormatType.UNKNOWN
