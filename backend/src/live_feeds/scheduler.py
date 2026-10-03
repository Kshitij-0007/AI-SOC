"""
scheduler.py — Simple polling loop for all live-feed connectors.

Architecture decision: this project does NOT use Celery, APScheduler, or
any heavy task queue.  A plain ``while True`` loop is appropriate for a
final-year AI-SOC project of this scale — it is easy to understand,
debug, and demonstrate.

Each connector's poll interval is read from ``configs/config.yaml``.
New records are canonicalized and persisted through the ingestion pipeline;
the parquet inbox is retained solely as a convenient derived export.

Usage::

    # Run with replay simulator only (no API keys needed)
    python -m src.live_feeds.scheduler

    # Or import and run programmatically
    from src.live_feeds.scheduler import run_scheduler
    run_scheduler(max_iterations=5)  # useful in tests
"""

from __future__ import annotations

import logging
import signal
import sys
import time
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from .base_connector import BaseConnector
from .replay_simulator import ReplaySimulator
from .siem_connector import LocalLogTailConnector
from .threat_intel_connectors import AbuseIPDBConnector, OTXConnector, VirusTotalConnector

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "configs" / "config.yaml"
_LIVE_INBOX = Path(__file__).resolve().parents[2] / "data" / "processed" / "live_inbox.parquet"


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def _load_config(config_path: Path) -> dict[str, Any]:
    """Load and return the YAML config dict (empty dict on failure)."""
    try:
        with config_path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except FileNotFoundError:
        logger.warning("Config not found at %s — using defaults.", config_path)
        return {}
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load config: %s", exc)
        return {}


def _get(cfg: dict, *keys: str, default: Any = None) -> Any:
    """Safely navigate nested config dict."""
    cur = cfg
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k, default)
    return cur


# ---------------------------------------------------------------------------
# Connector factory
# ---------------------------------------------------------------------------

def _build_connectors(cfg: dict) -> list[BaseConnector]:
    """
    Instantiate all configured connectors.

    Connectors that are disabled in config or whose API keys are absent
    will self-disable with a log warning — they are still returned in the
    list so the scheduler can report their status.
    """
    lf = cfg.get("live_feeds", {})
    connectors: list[BaseConnector] = []

    # --- Replay Simulator (always included, no network needed) ---
    rs_cfg = lf.get("replay_simulator", {})
    if rs_cfg.get("enabled", True):
        dataset = Path(rs_cfg.get("dataset_path", "data/raw/cicids2017_sample.csv"))
        sim = ReplaySimulator(
            dataset_path=dataset,
            batch_size=int(rs_cfg.get("emit_batch_size", 10)),
            interval_seconds=float(rs_cfg.get("interval_seconds", 2.0)),
            speed_multiplier=int(rs_cfg.get("speed_multiplier", 1)),
            loop=True,
        )
        connectors.append(sim)
        logger.info("ReplaySimulator enabled — dataset: %s", dataset)

    # --- Threat Intel ---
    ti_cfg = lf.get("threat_intel", {})

    abuse_cfg = ti_cfg.get("abuseipdb", {})
    if abuse_cfg.get("enabled", False):
        connectors.append(
            AbuseIPDBConnector(
                api_key_env=abuse_cfg.get("api_key_env", "ABUSEIPDB_API_KEY"),
            )
        )

    vt_cfg = ti_cfg.get("virustotal", {})
    if vt_cfg.get("enabled", False):
        connectors.append(
            VirusTotalConnector(
                api_key_env=vt_cfg.get("api_key_env", "VIRUSTOTAL_API_KEY"),
                requests_per_minute=int(vt_cfg.get("requests_per_minute", 4)),
            )
        )

    otx_cfg = ti_cfg.get("otx", {})
    if otx_cfg.get("enabled", False):
        connectors.append(
            OTXConnector(api_key_env=otx_cfg.get("api_key_env", "OTX_API_KEY"))
        )

    # --- SIEM / EDR log tail ---
    siem_cfg = lf.get("siem", {})
    if siem_cfg.get("enabled", False):
        wazuh_path = siem_cfg.get("wazuh_alerts_path", "")
        if wazuh_path:
            connectors.append(LocalLogTailConnector(log_path=Path(wazuh_path)))

    return connectors


# ---------------------------------------------------------------------------
# Record handler
# ---------------------------------------------------------------------------

def handle_new_records(records: list[dict[str, Any]], inbox_path: Path,
                       source_type: str = "live", source_ref: str = "connector") -> None:
    """
    Map *records* through the shared ingestion entry point and append a
    derived parquet export. Database persistence is the source of truth.
    """
    if not records:
        return

    try:
        from ..ingestion.pipeline import on_live_batch  # noqa: PLC0415
        canonical = on_live_batch(records, source_type=source_type, source_ref=source_ref)
    except Exception as exc:  # noqa: BLE001
        logger.error("Shared live ingestion failed: %s", exc)
        raise

    inbox_path.parent.mkdir(parents=True, exist_ok=True)

    if inbox_path.exists():
        existing = pd.read_parquet(inbox_path)
        combined = pd.concat([existing, canonical], ignore_index=True)
    else:
        combined = canonical

    combined.to_parquet(inbox_path, index=False)
    logger.debug("live_inbox.parquet updated — %d total rows", len(combined))


# ---------------------------------------------------------------------------
# Shutdown handler
# ---------------------------------------------------------------------------

_shutdown = False


def _signal_handler(sig: int, frame: Any) -> None:  # noqa: ARG001
    global _shutdown  # noqa: PLW0603
    _shutdown = True
    print("\n[scheduler] Shutdown signal received — stopping after current tick.")


# ---------------------------------------------------------------------------
# Main scheduler loop
# ---------------------------------------------------------------------------

def run_scheduler(
    config_path: Path = _DEFAULT_CONFIG,
    inbox_path: Path = _LIVE_INBOX,
    poll_interval_seconds: float | None = None,
    max_iterations: int | None = None,
) -> None:
    """
    Start the polling loop.

    Parameters
    ----------
    config_path:
        Path to ``configs/config.yaml``.
    inbox_path:
        Path to the live inbox parquet file.
    poll_interval_seconds:
        Override global poll interval (seconds).  Defaults to the minimum
        interval across all active connectors.
    max_iterations:
        Stop after this many ticks (``None`` = run forever).  Useful in
        tests and demos.
    """
    global _shutdown  # noqa: PLW0603
    _shutdown = False

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    signal.signal(signal.SIGINT, _signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _signal_handler)

    cfg = _load_config(config_path)
    connectors = _build_connectors(cfg)

    if not connectors:
        logger.warning("No connectors configured — scheduler has nothing to do.")
        return

    enabled = [c for c in connectors if c.enabled]
    logger.info(
        "Scheduler starting with %d connector(s): %s",
        len(enabled),
        [c.name for c in enabled],
    )

    # Determine sleep interval
    interval = poll_interval_seconds
    if interval is None and enabled:
        interval = min(c.poll_interval_seconds for c in enabled)
    interval = interval or 5.0

    iteration = 0
    total_records = 0

    while not _shutdown:
        if max_iterations is not None and iteration >= max_iterations:
            logger.info("Reached max_iterations=%d — stopping.", max_iterations)
            break

        for connector in connectors:
            if not connector.enabled or _shutdown:
                continue
            try:
                records = connector.poll()
                if records:
                    handle_new_records(records, inbox_path, source_type=connector.name,
                                       source_ref=f"connector:{connector.name}:{connector.get_state()}")
                    total_records += len(records)
                    logger.info(
                        "[%s] +%d records (total=%d)",
                        connector.name, len(records), total_records,
                    )
            except Exception as exc:  # noqa: BLE001
                logger.error("[%s] poll failed: %s", connector.name, exc)

        iteration += 1
        if not _shutdown:
            time.sleep(interval)

    logger.info("Scheduler stopped after %d iterations, %d total records.", iteration, total_records)


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="AI-SOC Live Feed Scheduler")
    ap.add_argument("--config", default=str(_DEFAULT_CONFIG), help="Path to config.yaml")
    ap.add_argument("--inbox", default=str(_LIVE_INBOX), help="Path to live_inbox.parquet")
    ap.add_argument("--interval", type=float, default=None, help="Override poll interval (seconds)")
    ap.add_argument("--max-iter", type=int, default=None, help="Stop after N iterations (default: forever)")
    args = ap.parse_args()

    run_scheduler(
        config_path=Path(args.config),
        inbox_path=Path(args.inbox),
        poll_interval_seconds=args.interval,
        max_iterations=args.max_iter,
    )
