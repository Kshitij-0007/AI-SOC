"""
feature_store_io.py — I/O only: save/load feature tables and encoders.

Thin file — no transformation logic.  All transformation happens in
``feature_engineering.py`` and ``smote_balancer.py``.
"""

from __future__ import annotations

import joblib
import logging
import numpy as np
from pathlib import Path
from typing import Any, Optional, Tuple

import pandas as pd

logger = logging.getLogger(__name__)


def save_feature_table(
    X: pd.DataFrame,
    y: pd.Series | None,
    path: Path,
) -> None:
    """
    Write a single parquet with features + a ``label`` column.

    The ``label`` column may be all‑null (for inference‑time saves).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # Add label column (may be all-null)
    df_out = X.copy()
    if y is not None:
        df_out["label"] = y.values
    else:
        df_out["label"] = np.nan
    df_out.to_parquet(path, index=False)
    logger.info("Feature table saved to %s (rows=%d)", path, len(df_out))


def load_feature_table(path: Path) -> Tuple[pd.DataFrame, pd.Series | None]:
    """
    Load a feature table parquet.

    Returns ``(X, y)`` where ``y`` is the ``label`` column as a Series
    (or ``None`` if the column is entirely null).
    """
    df = pd.read_parquet(path)
    if "label" not in df.columns:
        logger.warning("No 'label' column in %s — returning X with y=None", path)
        return df, None

    y_series = df["label"]
    # If all values are NaN, treat as None (live inference case)
    if y_series.notna().sum() == 0:
        y_series = None

    X = df.drop(columns=["label"], errors="ignore")
    # Remove rows where all feature columns are NaN? No — keep as-is.
    logger.info("Feature table loaded from %s (rows=%d, y_has_data=%s)", path, len(X), y_series is not None)
    return X, y_series
