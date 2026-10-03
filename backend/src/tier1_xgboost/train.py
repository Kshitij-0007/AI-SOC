"""
train.py — Train and save an XGBoost classifier.

Consumes feature tables produced by Module 2's ``feature_store_io.py``
and the ``FeatureEncoder`` it saved.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
import xgboost as xgb

logger = logging.getLogger(__name__)


def _detect_objective(y: pd.Series) -> str:
    """Auto-detect binary vs multiclass objective from ``y.nunique()``."""
    n_classes = y.nunique()
    if n_classes == 2:
        return "binary:logistic"
    return "multi:softprob"


def train_model(
    X: pd.DataFrame,
    y: pd.Series,
    config: Dict[str, Any],
) -> Tuple[xgb.XGBClassifier, dict]:
    """
    Train an XGBoost classifier on the provided data.

    Parameters
    ----------
    X : pd.DataFrame
        Numeric feature matrix (already encoded, imputed).
    y : pd.Series
        Target labels (``label`` column).
    config : dict
        Hyperparameters from ``configs/config.yaml`` under
        ``feature_engineering`` / ``xgboost``, plus
        ``train_test_split_ratio`` and ``random_state``.

    Returns
    -------
    model : xgb.XGBClassifier
        Fitted XGBoost classifier.
    split_info : dict
        Contains ``{"train_index", "test_index"}`` so ``evaluate.py`` can
        be called separately without re-splitting.
    """
    # Detect objective
    objective = _detect_objective(y)
    logger.info("Detected %s objective (n_classes=%d)", objective, y.nunique())

    # Hyperparameters with defaults
    xgb_cfg: Dict[str, Any] = config.get("xgboost", {})
    n_estimators: int = xgb_cfg.get("n_estimators", 200)
    max_depth: int = xgb_cfg.get("max_depth", 6)
    learning_rate: float = xgb_cfg.get("learning_rate", 0.1)
    tree_method: str = xgb_cfg.get("tree_method", "hist")
    random_state: int = xgb_cfg.get("random_state", 42)
    test_size: float = xgb_cfg.get("train_test_split_ratio", 0.2)

    # Stratified train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )

    # Train XGBoost model
    model = xgb.XGBClassifier(
        objective=objective,
        n_estimators=n_estimators,
        max_depth=max_depth,
        learning_rate=learning_rate,
        tree_method=tree_method,
        random_state=random_state,
        eval_metric="mlogloss" if objective == "multi:softprob" else "logloss",
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    split_info = {
        "train_index": X_train.index.tolist(),
        "test_index": X_test.index.tolist(),
    }

    logger.info(
        "XGBoost trained: %d train / %d test samples, objective=%s",
        len(X_train), len(X_test), objective,
    )
    return model, split_info


def save_trained_model(
    model: xgb.XGBClassifier,
    output_dir: Path,
) -> Path:
    """
    Save the trained model via XGBoost's native JSON format.

    Creates the output directory if it doesn't exist.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    model_path = output_dir / "model.json"
    model.save_model(str(model_path))
    logger.info("Model saved to %s", model_path)
    return model_path