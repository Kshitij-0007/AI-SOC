"""
smote_balancer.py — Class-balancing via SMOTE, training-time only.

Only ever called when ``mode="train"`` — this file has no concept of
inference mode, don't add one.

Use ``imblearn.over_sampling.SMOTE``; guard the edge cases:
- if ``y.nunique() < 2`` → log a warning, return ``X, y`` unchanged
  (can't balance one class)
- if the smallest class has fewer than ``k_neighbors + 1`` samples →
  reduce ``k_neighbors`` automatically or skip balancing for that run
  with a clear warning.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd

from imblearn.over_sampling import SMOTE

logger = logging.getLogger(__name__)


def balance_classes(
    X: pd.DataFrame,
    y: pd.Series,
    config: Dict[str, Any],
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Apply SMOTE to balance class distribution.

    Parameters
    ----------
    X : pd.DataFrame
        Feature matrix (already encoded, imputed).
    y : pd.Series
        Target labels (``label`` column).
    config : dict
        Configuration dict with at least ``k_neighbors`` (default 5) and
        optionally ``enabled`` (default True).

    Returns
    -------
    X_balanced : pd.DataFrame
        Feature matrix after SMOTE (or unchanged if balancing skipped).
    y_balanced : pd.Series
        Target labels after SMOTE (or unchanged).
    """
    enabled: bool = config.get("enabled", True)
    if not enabled:
        logger.info("SMOTE disabled via config — returning X, y unchanged.")
        return X, y

    k_neighbors: int = config.get("k_neighbors", 5)

    # Guard: need at least 2 classes
    if y.nunique() < 2:
        logger.warning(
            "Cannot apply SMOTE: only %d class found in y (need ≥ 2). "
            "Returning X, y unchanged.", y.nunique(),
        )
        return X, y

    # Guard: smallest class must have at least k_neighbors + 1 samples
    class_counts: Dict[Any, int] = y.value_counts().to_dict()
    min_class_count: int = min(class_counts.values())

    if min_class_count <= k_neighbors:
        # Reduce k_neighbors to min_class_count - 1, or skip entirely
        suggested_k = max(1, min_class_count - 1)
        if suggested_k < k_neighbors:
            logger.warning(
                "Smallest class has %d samples, which is ≤ default k_neighbors=%d. "
                "Reducing k_neighbors to %d for SMOTE.",
                min_class_count,
                k_neighbors,
                suggested_k,
            )
            k_neighbors = suggested_k

    if min_class_count <= k_neighbors:
        # Even with reduced k_neighbors, can't apply SMOTE
        logger.warning(
            "Smallest class has %d samples after k_neighbor adjustment, "
            "which is ≤ k_neighbors=%d. Skipping SMOTE balancing.",
            min_class_count,
            k_neighbors,
        )
        return X, y

    # Apply SMOTE
    try:
        smote = SMOTE(
            k_neighbors=k_neighbors,
            random_state=42,
            sampling_strategy="auto",
        )
        X_array = X.values if hasattr(X, "values") else np.array(X)
        y_array = y.values if hasattr(y, "values") else np.array(y)

        X_resampled, y_resampled = smote.fit_resample(X_array, y_array)

        X_balanced = pd.DataFrame(
            X_resampled,
            columns=X.columns if hasattr(X, "columns") else list(range(X_resampled.shape[1])),
            index=X.index[: len(y_resampled)] if hasattr(X, "index") else None,
        )
        y_balanced = pd.Series(y_resampled, name=y.name, index=X.index[: len(y_resampled)] if hasattr(X, "index") else None)

        logger.info(
            "SMOTE applied: %d → %d rows (k_neighbors=%d)",
            len(X),
            len(y_balanced),
            k_neighbors,
        )
        return X_balanced, y_balanced

    except Exception as exc:  # noqa: BLE001
        logger.error("SMOTE failed with error: %s — returning X, y unchanged.", exc)
        return X, y