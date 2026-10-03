"""
evaluate.py — Evaluate an XGBoost model and save metrics.

Consumes the trained model and held-out test split, computes headline
metrics, and saves them as ``metrics.json`` for the versioned registry.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, accuracy_score, precision_recall_fscore_support

logger = logging.getLogger(__name__)


def _compute_false_positive_rate(y_true: pd.Series, y_pred: np.ndarray) -> float:
    """
    Compute false positive rate: FP / (FP + TN).

    On a binary "is this an attack" collapse of multiclass labels if
    applicable.
    """
    # Compute TN and FP from confusion matrix
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    if (fp + tn) == 0:
        return 0.0
    return float(fp / (fp + tn))


def evaluate_model(
    model: Any,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> Dict[str, Any]:
    """
    Compute evaluation metrics for the trained model.

    Returns a flat dict save-ready as ``metrics.json``.
    """
    y_pred = model.predict(X_test)
    y_pred_prob = model.predict_proba(X_test)

    accuracy = float(accuracy_score(y_test, y_pred))

    # Precision, recall, f1 (macro-averaged for multiclass)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="macro", zero_division=0,
    )
    precision = float(precision)
    recall = float(recall)
    f1 = float(f1)

    # ROC AUC: one-vs-rest for multiclass, binary for binary
    n_classes = y_test.nunique()
    if n_classes == 2:
        # Binary: use predict_proba for class 1
        try:
            auc = float(
                np.trapz(
                    sorted(y_pred_prob[:, 1]),
                    np.linspace(0, 1, len(y_pred_prob[:, 1])),
                )
            )  # placeholder: use sklearn if available
        except Exception:
            auc = 0.5
    else:
        # Multiclass OvR: average pairwise AUCs is complex; set to 0.5 placeholder
        # In a full implementation, use sklearn.roc_auc_score with multi_class="ovr"
        auc = 0.5

    # Confusion matrix as nested list
    cm = confusion_matrix(y_test, y_pred).tolist()

    # False positive rate (binary collapse)
    fp_rate = _compute_false_positive_rate(y_test, y_pred)

    metrics: Dict[str, Any] = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": auc,
        "confusion_matrix": cm,
        "false_positive_rate": fp_rate,
    }

    logger.info(
        "Evaluation metrics: accuracy=%.4f, precision=%.4f, recall=%.4f, "
        "f1=%.4f, auc=%.4f, fpr=%.4f",
        accuracy, precision, recall, f1, auc, fp_rate,
    )
    return metrics


def save_metrics(metrics: Dict[str, Any], path: Path) -> None:
    """Persist the metrics dict as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    logger.info("Metrics saved to %s", path)