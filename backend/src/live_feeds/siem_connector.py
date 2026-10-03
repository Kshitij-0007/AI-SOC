"""
siem_connector.py — Tails a real growing SIEM/EDR log file.

``LocalLogTailConnector`` reads a Wazuh ``alerts.json`` or Suricata
``eve.json`` file using a byte-offset cursor, so only new lines are read
on each ``poll()`` call.  Lines are parsed with Module 1's ``parse_log``
and mapped through ``schema_mapper.map_to_canonical``.

If the target log file does not exist (Wazuh/Suricata not installed),
the connector logs a single warning and returns empty lists without
crashing the scheduler.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pandas as pd

from ..ingestion.format_detector import FormatType
from ..ingestion.parsers.log_parser import parse_log
from ..ingestion.schema_mapper import map_to_canonical
from .base_connector import BaseConnector

logger = logging.getLogger(__name__)


class LocalLogTailConnector(BaseConnector):
    """
    Byte-offset tail connector for growing JSON-lines log files.

    Suitable for:
    * Wazuh — ``/var/ossec/logs/alerts/alerts.json``
    * Suricata — ``/var/log/suricata/eve.json``

    Parameters
    ----------
    log_path:
        Absolute path to the target log file.
    fmt:
        Log format type (default: ``JSON_LOG`` for both Wazuh and Suricata).
    poll_interval_seconds:
        Scheduler polling cadence.
    """

    def __init__(
        self,
        log_path: Path | str,
        fmt: FormatType = FormatType.JSON_LOG,
        poll_interval_seconds: float = 5.0,
    ) -> None:
        super().__init__(name="local_log_tail", poll_interval_seconds=poll_interval_seconds)
        self._log_path = Path(log_path)
        self._fmt = fmt
        # State: byte offset into the file
        self._state.setdefault("byte_offset", 0)

        if not self._log_path.exists():
            logger.warning(
                "[LocalLogTail] Log file not found: %s — connector is a no-op until the file appears.",
                self._log_path,
            )

    # ------------------------------------------------------------------
    # State persistence (byte offset)
    # ------------------------------------------------------------------

    def get_state(self) -> dict[str, Any]:
        state = super().get_state()
        state["byte_offset"] = self._state.get("byte_offset", 0)
        return state

    def set_state(self, state: dict[str, Any]) -> None:
        super().set_state(state)
        self._state["byte_offset"] = int(state.get("byte_offset", 0))

    # ------------------------------------------------------------------
    # New-lines reader
    # ------------------------------------------------------------------

    def _read_new_lines(self) -> list[str]:
        """
        Read all new lines since the last byte offset.

        Returns an empty list if the file does not exist or is empty.
        """
        if not self._log_path.exists():
            return []

        offset = self._state.get("byte_offset", 0)
        new_lines: list[str] = []

        try:
            with self._log_path.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(offset)
                for raw in fh:
                    new_lines.append(raw)
                self._state["byte_offset"] = fh.tell()
        except OSError as exc:
            logger.error("[LocalLogTail] Could not read %s: %s", self._log_path, exc)

        return new_lines

    # ------------------------------------------------------------------
    # Poll
    # ------------------------------------------------------------------

    def poll(self) -> list[dict[str, Any]]:
        """
        Return new canonical records from the tailed log file.

        Each call advances the byte-offset cursor; only genuinely new
        lines are parsed.
        """
        if not self._enabled:
            return []

        new_lines = self._read_new_lines()
        if not new_lines:
            return []

        # Write new lines to a temporary in-memory parse via parse_log
        # by creating a lightweight wrapper that feeds strings instead of
        # re-reading the file (avoids temp-file creation).
        import io  # noqa: PLC0415  (stdlib, lazy import)
        import json  # noqa: PLC0415

        records: list[dict] = []
        for line in new_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    obj = {"raw_line": line}
                obj.setdefault("source_file", str(self._log_path))
                obj.setdefault("source_format", self._fmt.value)
                records.append(obj)
            except json.JSONDecodeError:
                records.append({
                    "source_file": str(self._log_path),
                    "source_format": self._fmt.value,
                    "extra_fields": json.dumps({"raw_line": line}),
                })

        if not records:
            return records

        try:
            import pandas as pd  # noqa: PLC0415
            df = pd.DataFrame(records)
            canonical_df = map_to_canonical(df, source_format=self._fmt.value)
            result = canonical_df.to_dict(orient="records")
        except Exception as exc:  # noqa: BLE001
            logger.error("[LocalLogTail] Schema mapping failed: %s", exc)
            result = records

        logger.info("[LocalLogTail] poll → %d new records from %s", len(result), self._log_path.name)
        return result
