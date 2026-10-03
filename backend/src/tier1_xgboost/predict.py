"""
predict.py — Score events with the active XGBoost model.

Loads the active model and its matching FeatureEncoder from the version
registry and uses them to produce predictions.  Validates that the feature
columns in ``X`` exactly match the encoder's ``feature_column_order`` —
raises a clear, specific error if they don't match (this is the
train/inference-parity guard).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import xgboost as xgb

from ..features.feature_encoder import FeatureEncoder

logger = logging.getLogger(__name__)


def load_active_model(base: Path = None) -> Tuple[xgb.XGBClassifier, FeatureEncoder]:
    """
    Load the active XGBoost model and its matching FeatureEncoder.

    Reads ``model_registry.get_active_version()``, loads the XGBoost model
    from its ``path`` and the ``FeatureEncoder`` from Module 2 via its
    ``encoder_path`` — **both must come from the same registered version**,
    never mix a model with a different version's encoder.

    Returns
    -------
    model : xgb.XGBClassifier
        The loaded XGBoost classifier.
    encoder : FeatureEncoder
        The matching fitted encoder.
    """
    from .model_registry import register_new_version, set_active_version, get_active_version  # lazy

    base = Path(base) if base else Path(".")
    registry = get_active_version(base)
    if registry is None:
        raise RuntimeError(
            "No active XGBoost model version found. "
            "Train and register a model first, or set an active version."
        )

    model_path = registry["path"]
    encoder_path = registry["encoder_path"]

    # Load XGBoost model
    model = xgb.XGBClassifier()
    model.load_model(str(model_path))
    logger.info("XGBoost model loaded from %s", model_path)

    # Load FeatureEncoder
    encoder = FeatureEncoder.load(Path(encoder_path))
    logger.info("FeatureEncoder loaded from %s", encoder_path)

    # Crucial: verify that model and encoder are from the same version
    # by checking that the encoder's feature_column_order is compatible
    # with what the model expects.  We validate here explicitly.
    expected_cols = encoder.feature_column_order
    actual_cols = list(model.feature_names if hasattr(model, "feature_names") else [])

    if expected_cols != actual_cols:
        raise ValueError(
            f"Feature column mismatch: encoder expects columns {expected_cols[:5]}..."
            f"but model was trained on {actual_cols[:5]}... "
            f"Ensure the same FeatureEncoder (version {encoder.encoder_type}) "
            f"was used for both training and scoring."
        )

    return model, encoder


def score_events(
    model: xgb.XGBClassifier,
    X: pd.DataFrame,
    encoder: FeatureEncoder,
) -> pd.DataFrame:
    """
    Run ``model.predict()`` and ``model.predict_proba()`` on *X*.

    Validates that ``X.columns`` exactly match the encoder's
    ``feature_column_order`` before predicting.

    Returns a DataFrame with columns:
    - ``predicted_label``: the predicted class label
    - ``class_probabilities``: JSON string of ``{class: prob}``
    - ``confidence``: max probability across classes
    """
    # --- Column-mismatch guard (the single most important check) ---
    expected_cols = encoder.feature_column_order
    actual_cols = list(X.columns)

    if expected_cols != actual_cols:
        raise ValueError(
            f"Column mismatch for scoring:\n"
            f"  Expected (from encoder): {expected_cols}\n"
            f"  Actual (input X):        {actual_cols}\n"
            f"Re-engineer the input features with the same encoder before scoring."
        )

    # Predict
    predicted_labels = model.predict(X)
    predicted_probs = model.predict_proba(X)

    # Build probability dict per row
    class_names = [str(c) for c in model.classes_]
    prob_strings: List[str] = []
    confidences: List[float] = []

    for i in range(len(X)):
        prob_dict = {
            cls: float(prob)
            for cls, prob in zip(class_names, predicted_probs[i])
        }
        prob_strings.append(json.dumps(prob_dict))
        confidences.append(float(max(predicted_probs[i])))

    result = pd.DataFrame({
        "predicted_label": predicted_labels,
        "class_probabilities": prob_strings,
        "confidence": confidences,
    }, index=X.index)

    logger.info(
        "Scored %d events: %s distribution", len(result),
        result["predicted_label"].value_counts().to_dict(),
    )
    return result