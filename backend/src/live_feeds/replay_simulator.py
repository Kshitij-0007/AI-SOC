"""
replay_simulator.py — Emits rows from a static dataset as if they were live.

This is the primary demo path for the AI-SOC project.  It reads a
processed parquet file (or raw CICIDS2017/NSL-KDD CSV) and emits rows
in batches on each ``poll()`` call.  The scheduler decides timing; this
class only tracks a cursor position.

Usage::

    sim = ReplaySimulator(
        dataset_path=Path("data/raw/cicids2017_sample.csv"),
        batch_size=10,
        speed_multiplier=10,
        loop=True,
    )
    while True:
        records = sim.poll()
        # handle records ...
        time.sleep(sim.poll_interval_seconds)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pandas as pd

from .base_connector import BaseConnector

logger = logging.getLogger(__name__)


class ReplaySimulator(BaseConnector):
    """
    Replay a static dataset row-by-row to simulate a live data stream.

    Parameters
    ----------
    dataset_path:
        Path to a ``.parquet`` or ``.csv`` file.
    batch_size:
        Number of rows returned per ``poll()`` call.
    interval_seconds:
        Suggested polling interval for the scheduler (seconds).
    speed_multiplier:
        Logical multiplier — the cursor advances ``batch_size *
        speed_multiplier`` rows per poll, allowing a full dataset to be
        replayed faster than real-time.
    loop:
        If ``True``, wrap around to the start when the dataset is exhausted.
    shuffle:
        If ``True``, shuffle the dataset on each loop iteration.
    """

    def __init__(
        self,
        dataset_path: Path,
        batch_size: int = 10,
        interval_seconds: float = 2.0,
        speed_multiplier: int = 1,
        loop: bool = True,
        shuffle: bool = False,
    ) -> None:
        super().__init__(name="replay_simulator", poll_interval_seconds=interval_seconds)
        self._dataset_path = Path(dataset_path)
        self._batch_size = batch_size
        self._speed_multiplier = max(1, speed_multiplier)
        self._loop = loop
        self._shuffle = shuffle
        self._df: pd.DataFrame | None = None
        self._cursor: int = 0

    # ------------------------------------------------------------------
    # Dataset loading (lazy, once)
    # ------------------------------------------------------------------

    def _load_dataset(self) -> pd.DataFrame:
        """Load the dataset from disk (parquet or CSV)."""
        path = self._dataset_path
        if not path.exists():
            raise FileNotFoundError(f"ReplaySimulator dataset not found: {path}")

        ext = path.suffix.lower()
        if ext == ".parquet":
            df = pd.read_parquet(path)
        elif ext == ".csv":
            df = pd.read_csv(path, low_memory=False)
        else:
            raise ValueError(f"Unsupported dataset extension '{ext}' for replay simulator.")

        logger.info("ReplaySimulator loaded %d rows from %s", len(df), path.name)
        return df

    def _ensure_loaded(self) -> None:
        """Load dataset on first use; apply optional shuffle."""
        if self._df is None:
            self._df = self._load_dataset()
            if self._shuffle:
                self._df = self._df.sample(frac=1).reset_index(drop=True)

    # ------------------------------------------------------------------
    # State persistence (cursor position)
    # ------------------------------------------------------------------

    def get_state(self) -> dict[str, Any]:
        state = super().get_state()
        state["cursor"] = self._cursor
        return state

    def set_state(self, state: dict[str, Any]) -> None:
        super().set_state(state)
        self._cursor = int(state.get("cursor", 0))

    # ------------------------------------------------------------------
    # Poll
    # ------------------------------------------------------------------

    def poll(self) -> list[dict[str, Any]]:
        """
        Return the next batch of rows from the dataset.

        Returns an empty list when the dataset is exhausted and
        ``loop=False``.  With ``loop=True``, wraps around to row 0.
        """
        self._ensure_loaded()
        df = self._df  # type: ignore[assignment]
        total = len(df)

        if total == 0:
            return []

        # How many rows to advance this tick
        advance = self._batch_size * self._speed_multiplier

        if self._cursor >= total:
            if not self._loop:
                logger.info("ReplaySimulator: dataset exhausted (loop=False).")
                return []
            # Wrap around
            self._cursor = 0
            if self._shuffle:
                self._df = df.sample(frac=1).reset_index(drop=True)
                df = self._df

        end = min(self._cursor + advance, total)
        batch = df.iloc[self._cursor:end]
        self._cursor = end

        records = batch.to_dict(orient="records")
        logger.debug(
            "ReplaySimulator: emitted rows %d–%d (%d records)",
            self._cursor - len(records),
            self._cursor - 1,
            len(records),
        )
        return records

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def cursor(self) -> int:
        """Current row index into the dataset."""
        return self._cursor

    @property
    def dataset_size(self) -> int:
        """Total number of rows in the loaded dataset (0 if not yet loaded)."""
        self._ensure_loaded()
        return len(self._df) if self._df is not None else 0
