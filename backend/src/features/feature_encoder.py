"""
feature_encoder.py — Fitted encoder state for train/inference parity.

This dataclass persists everything needed to transform live (inference)
data using the *same* algebra as the training fit — never re-fits
anything during inference mode.

Serialized via joblib to ``data/feature_store/encoder_v{N}.joblib``
and reloaded by Module 3's ``predict.py``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from sklearn.preprocessing import OrdinalEncoder, OneHotEncoder

logger = logging.getLogger(__name__)


@dataclass
class FeatureEncoder:
    """
    Holds the fitted state required for feature transformation.

    Invariants (enforced by ``fit`` / ``transform``, not by the type
    system)::

        * ``categorical_encoder`` is either an ``OrdinalEncoder`` or
          ``OneHotEncoder`` that has been ``.fit()``'d on training data.
        * ``median_impute`` maps each numeric column name to the
          median value computed during ``mode="train"``.  During
          ``mode="inference"`` these values are used *directly* —
          recomputing the median from a single live batch would drift.
        * ``feature_column_order`` is the exact list of column names
          as they appeared when the encoder was fitted.  ``score_events``
          in Module 3 validates that live ``X`` has *exactly* these
          columns in this order before predicting.
    """

    categorical_encoder: Any  # OrdinalEncoder or OneHotEncoder (sklearn)
    median_impute: Dict[str, float] = field(default_factory=dict)
    feature_column_order: List[str] = field(default_factory=list)
    encoder_type: str = "ordinal"  # "ordinal" or "onehot"
    n_categorical_features: int = 0

    def save(self, path: Path) -> None:
        """Persist this encoder object to disk via joblib."""
        path.parent.mkdir(parents=True, exist_ok=True)
        import joblib  # lazy import — stdlib-friendly

        joblib.dump(value=self, filename=str(path))
        logger.info("FeatureEncoder saved to %s", path)

    @staticmethod
    def load(path: Path) -> FeatureEncoder:
        """Load a previously-saved FeatureEncoder from disk."""
        import joblib  # lazy import

        encoder: FeatureEncoder = joblib.load(filename=str(path))
        logger.info("FeatureEncoder loaded from %s", path)
        return encoder

    def transform_categorical(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Apply the fitted categorical encoder to *df*.

        Expects *df* to contain the categorical columns in the same
        positions/order as at fit time.  Returns a DataFrame with the
        encoded numeric columns replacing the original categorical ones.
        """
        if self.categorical_encoder is None:
            raise RuntimeError("Categorical encoder not fitted yet.")

        # OrdinalEncoder returns aligned array; OneHotEncoder sparse
        result = self.categorical_encoder.transform(df)
        if hasattr(result, "toarray"):  # OneHotEncoder sparse output
            result = result.toarray()
        return pd.DataFrame(
            result,
            columns=self.categorical_encoder.get_feature_names_out()
            if hasattr(self.categorical_encoder, "get_feature_names_out")
            else [f"cat_{i}" for i in range(result.shape[1])],
            index=df.index,
        )

    def impute_numeric(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Fill NaN/None in numeric columns using the stored median values.

        Columns not present in ``median_impute `` are left as-is (the
        caller may handle them separately).  Returns a DataFrame with
        the same shape as *df*.
        """
        df = df.copy()
        for col, med in self.median_impute.items():
            if col in df.columns:
                df[col] = df[col].fillna(med)
        return df

    def get_feature_names(self) -> List[str]:
        """
        Return the ordered list of output feature names after encoding.

        For ``OrdinalEncoder`` this is just the original column names.
        For ``OneHotEncoder`` these are the ``get_feature_names_out()``
        strings.
        """
        if hasattr(self.categorical_encoder, "get_feature_names_out"):
            return list(self.categorical_encoder.get_feature_names_out())
        return list(self.categorical_encoder.feature_names_in_)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Helper: build encoder from a DataFrame of raw canonical columns
# ---------------------------------------------------------------------------


def build_encoder_from_df(
    df: pd.DataFrame,
    categorical_cols: List[str],
    median_cols: Dict[str, float],
    encoder_type: str = "ordinal",
) -> FeatureEncoder:
    """
    Construct a ``FeatureEncoder`` fitted on *df*.

    Parameters
    ----------
    df : pd.DataFrame
        DataFrame with at least the ``categorical_cols`` and numeric
        columns referenced by ``median_cols``.
    categorical_cols : list[str]
        Column names to fit the encoder on.
    median_cols : dict[str, float]
        Mapping of column name → median value for imputation.
    encoder_type : {"ordinal", "onehot"}
        Which sklearn encoder to use.

    Returns
    -------
    FeatureEncoder
        A fitted encoder with ``feature_column_order`` set to the
        final column order after encoding.
    """
    from ..ingestion.schema_mapper import CANONICAL_COLUMNS  # avoid circular import at module level

    # Ensure categorical columns exist
    available_categorical = [c for c in categorical_cols if c in df.columns]
    if not available_categorical:
        logger.warning("No categorical columns found in df — proceeding without encoding")
        encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
        encoder.fit(np.zeros((len(df), 1)))  # dummy fit so it's not None
        return FeatureEncoder(
            categorical_encoder=encoder,
            median_impute={c: float(df[c].median()) for c in median_cols if c in df.columns},
            feature_column_order=list(df.columns),
            encoder_type=encoder_type,
            n_categorical_features=0,
        )

    if encoder_type == "ordinal":
        encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
    else:
        encoder = OneHotEncoder(sparse_output=False, handle_unknown="ignore")

    # Fit on the actual data
    X_cat = df[available_categorical].copy()
    encoder.fit(X_cat)

    # Compute medians for numeric imputation
    median_impute = {}
    for c, med in median_cols.items():
        if c in df.columns:
            if pd.isna(med):
                median_impute[c] = float(df[c].median())
            else:
                median_impute[c] = float(med)
    # Also add medians for any numeric columns not explicitly listed
    for col in df.select_dtypes(include=[np.number]).columns:
        if col not in median_impute:
            med = df[col].median()
            median_impute[col] = float(med) if not pd.isna(med) else 0.0

    # Determine final feature column order
    # After encoding, we'll have encoded columns + remaining numeric
    n_cat = len(available_categorical)
    encoded_names = (
        list(encoder.get_feature_names_out(available_categorical))
        if hasattr(encoder, "get_feature_names_out")
        else [f"cat_{i}" for i in range(n_cat)]
    )

    # Numeric columns that survive (not dropped)
    numeric_cols = [
        c for c in df.select_dtypes(include=[np.number]).columns
        if c not in categorical_cols
    ]
    feature_order = encoded_names + numeric_cols

    logger.info(
        "Built FeatureEncoder: type=%s, cat_cols=%d, numeric_cols=%d, "
        "feature_order=%s",
        encoder_type,
        n_cat,
        len(numeric_cols),
        feature_order,
    )

    return FeatureEncoder(
        categorical_encoder=encoder,
        median_impute=median_impute,
        feature_column_order=feature_order,
        encoder_type=encoder_type,
        n_categorical_features=n_cat,
    )