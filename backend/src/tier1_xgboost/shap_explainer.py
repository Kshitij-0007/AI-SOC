"""
shap_explainer.py — SHAP explainability for XGBoost predictions.

Use ``shap.TreeExplainer(model)`` — the correct, exact, fast explainer
for tree ensembles (do not use ``KernelExplainer``, it's needlessly slow
for this model type).

For each row, return the top-N features by absolute SHAP value.
Return one such list per input row, aligned by index with ``X``.

Note on scale: SHAP on the full live stream can be slow — add an
optional ``X_subset`` calling pattern (the caller decides which rows
need explaining, e.g. only rows above a risk threshold from Module 4 —
this file does not decide that itself, it just explains whatever rows
it's given).
"""

from __future__ import annotations

import logging
from typing import Any, List, Dict

import numpy as np
import pandas as pd
import shap

import xgboost as xgb

logger = logging.getLogger(__name__)


def explain_predictions(
    model: xgb.XGBClassifier,
    X: pd.DataFrame,
    top_n: int = 5,
) -> List[Dict[str, Any]]:
    """
    Explain predictions using SHAP TreeExplainer.

    For each row, return the top-N features by absolute SHAP value:
    ``[{"feature": "...", "shap_value": ..., "feature_value": ...}, ...]``

    Parameters
    ----------
    model : xgb.XGBClassifier
        Trained XGBoost model.
    X : pd.DataFrame
        Feature matrix (must have columns matching the model's expectations).
    top_n : int
        Number of top features to return per row.

    Returns
    -------
    explanations : list[dict]
        One entry per input row, each containing ``top_n`` feature
        attributions.  Aligned by index with ``X``.
    """
    # Create TreeExplainer (background data = training data would be ideal,
    # but we use X itself as a simple approximation for the demo)
    explainer = shap.TreeExplainer(model, X, feature_perturbation="interventional")

    # Compute SHAP values
    shap_values = explainer.shap_values(X)

    # Handle binary vs multiclass output shape
    if isinstance(shap_values, list):
        # Multiclass case — take the first class's SHAP values
        shap_values = shap_values[0]
    elif shap_values.ndim == 3:
        # Multiclass with shape (n_classes, n_samples, n_features)
        shap_values = shap_values[:, 0, :]  # first class

    # Ensure we have the right shape
    if shap_values.ndim != 2:
        logger.warning("Unexpected SHAP values shape: %s", shap_values.shape)
        return [{} for _ in range(len(X))]

    n_samples, n_features = shap_values.shape

    explanations: List[Dict[str, Any]] = []
    for i in range(min(n_samples, len(X))):
        # Get feature names in order
        feature_names = list(X.columns)

        # Pair each feature with its SHAP value
        feature_shap_pairs = [
            {
                "feature": feature_names[j] if j < len(feature_names) else f"feature_{j}",
                "shap_value": float(shap_values[i, j]),
                "feature_value": float(X.iloc[i, j]) if j < len(X.columns) else None,
            }
            for j in range(min(n_features, len(feature_names)))
        ]

        # Sort by absolute SHAP value and take top_n
        feature_shap_pairs.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
        top_pairs = feature_shap_pairs[:top_n]

        explanations.append({"row_index": i, "features": top_pairs})

    logger.info(
        "SHAP explanations generated for %d rows (top_n=%d)", len(explanations), top_n,
    )
    return explanations