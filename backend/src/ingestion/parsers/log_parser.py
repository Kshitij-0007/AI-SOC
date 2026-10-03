"""
log_parser.py — Parses log files into lists of dicts.

Supported formats (via ``FormatType``):

* ``JSON_LOG``  — one JSON object per line (jsonlines-style).
* ``SYSLOG``    — RFC3164-style syslog with timestamp, host, process, message.
* ``LOG``       — generic; tries Apache/Nginx combined format, then key=value
                  pairs, then falls back to ``{"raw_line": "..."}`` in
                  ``extra_fields`` — no line is ever dropped.

All formats add ``source_file`` and ``source_format`` to every record.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from ..format_detector import FormatType

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# RFC3164 syslog  (permissive; handles optional PID)
_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# Apache/Nginx combined log format
_APACHE_RE = re.compile(
    r'^(?P<src_ip>\S+)\s+'          # client IP
    r'\S+\s+\S+\s+'                 # ident, user
    r'\[(?P<timestamp>[^\]]+)\]\s+' # timestamp
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol_ver>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes_sent>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)")?'
    r'(?:\s+"(?P<user_agent>[^"]*)")?'
)

# Generic key=value pairs (e.g. CEF syslog payloads, key="val", key=val)
_KV_RE = re.compile(r'(\w[\w.\-]*)=(?:"([^"]*)"|([\S]*))')


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_json_log(file_path: Path) -> list[dict[str, Any]]:
    """Parse a JSON-lines file; skip malformed lines with a warning."""
    records: list[dict] = []
    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    obj = {"value": obj}
                records.append(obj)
            except json.JSONDecodeError as exc:
                logger.warning("Skipping malformed JSON at %s:%d — %s", file_path.name, lineno, exc)
    return records


def _parse_syslog(file_path: Path) -> list[dict[str, Any]]:
    """Parse syslog-formatted lines; unmatched lines go into extra_fields."""
    records: list[dict] = []
    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            m = _SYSLOG_RE.match(line)
            if m:
                rec = m.groupdict()
                rec["extra_fields"] = json.dumps({"raw_line": line})
            else:
                rec = {"extra_fields": json.dumps({"raw_line": line})}
            records.append(rec)
    return records


def _try_apache(line: str) -> dict[str, Any] | None:
    """Attempt Apache/Nginx combined-log parsing; return dict or None."""
    m = _APACHE_RE.match(line)
    if not m:
        return None
    rec = m.groupdict()
    # bytes_sent may be "-" in some entries
    try:
        rec["bytes_sent"] = float(rec["bytes_sent"])
    except (TypeError, ValueError):
        rec["bytes_sent"] = None
    try:
        rec["dst_port"] = int(rec.get("dst_port") or 0) or None
    except (TypeError, ValueError):
        rec["dst_port"] = None
    return rec


def _try_kv(line: str) -> dict[str, Any] | None:
    """Extract key=value pairs; return None if fewer than 2 pairs found."""
    pairs = {k: (v1 if v1 is not None else v2) for k, v1, v2 in _KV_RE.findall(line)}
    return pairs if len(pairs) >= 2 else None  # type: ignore[return-value]


def _parse_generic_log(file_path: Path) -> list[dict[str, Any]]:
    """Parse generic log lines: Apache → key=value → raw fallback."""
    records: list[dict] = []
    with file_path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            rec = _try_apache(line) or _try_kv(line)
            if rec is None:
                rec = {"extra_fields": json.dumps({"raw_line": line})}
            elif "extra_fields" not in rec:
                rec["extra_fields"] = json.dumps({"raw_line": line})
            records.append(rec)
    return records


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_log(file_path: Path, fmt: FormatType) -> list[dict[str, Any]]:
    """
    Parse a log file and return a list of record dicts.

    Each dict includes ``source_file`` and ``source_format``.  Unknown
    or unparseable lines are never dropped — they are captured in
    ``extra_fields`` as ``{"raw_line": "..."}``.

    Parameters
    ----------
    file_path:
        Path to the log file.
    fmt:
        One of :attr:`FormatType.JSON_LOG`, :attr:`FormatType.SYSLOG`,
        or :attr:`FormatType.LOG`.

    Returns
    -------
    list[dict]
        One dict per log line/record.
    """
    path = Path(file_path)
    dispatch = {
        FormatType.JSON_LOG: _parse_json_log,
        FormatType.SYSLOG: _parse_syslog,
        FormatType.LOG: _parse_generic_log,
    }
    parser_fn = dispatch.get(fmt, _parse_generic_log)
    records = parser_fn(path)

    src = str(path)
    fmt_str = fmt.value
    for rec in records:
        rec.setdefault("source_file", src)
        rec.setdefault("source_format", fmt_str)

    logger.info("Parsed %s (%s) → %d records", path.name, fmt_str, len(records))
    return records
