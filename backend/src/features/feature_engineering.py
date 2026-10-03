"""
feature_engineering.py — Turn canonical rows into a numeric feature matrix.

This module runs in two modes: ``mode="train"`` fits encoders/scalers and
applies SMOTE; ``mode="inference"`` loads the already-fitted encoder and
only transforms (never re-fits), and **never applies SMOTE** (SMOTE is a
training-time class-balancing technique).

Train/inference parity is the single most important rule in this module —
get it wrong and Module 3 will silently produce garbage predictions on live
data even though training looked fine.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.preprocessing import OrdinalEncoder, OneHotEncoder

from .feature_encoder import FeatureEncoder, build_encoder_from_df

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _derive_timestamp_features(df: pd.DataFrame) -> pd.DataFrame:
    """Derive hour_of_day, day_of_week, is_weekend from ``timestamp``."""
    df = df.copy()
    if "timestamp" not in df.columns:
        return df
    # Ensure datetime
    ts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["hour_of_day"] = ts.dt.hour
    df["day_of_week"] = ts.dt.dayofweek  # Mon=0 .. Sun=6
    df["is_weekend"] = df["day_of_week"].isin([5, 6]).astype(int)
    return df


def _derive_flow_ratio_features(df: pd.DataFrame) -> pd.DataFrame:
    """Derive bytes_per_packet and send_receive_ratio where possible."""
    df = df.copy()
# bytes_per_packet: guard divide-by-zero
    if {"bytes_sent", "packet_count"}.issubset(df.columns):
        bytes_sent = df["bytes_sent"].fillna(0)
        packet_count = df["packet_count"].fillna(0)
        df["bytes_per_packet"] = np.where(
            packet_count != 0,
            bytes_sent / packet_count,
            0,
        )
    else:
        df["bytes_per_packet"] = 0

    # send_receive_ratio: bytes_sent / (bytes_received + 1)
    if {"bytes_sent", "bytes_received"}.issubset(df.columns):
        df["send_receive_ratio"] = df["bytes_sent"].fillna(0) / (df["bytes_received"].fillna(0) + 1)
    else:
        df["send_receive_ratio"] = 0.0
    return df


# ---------------------------------------------------------------------------
# Engineer features (core logic)
# ---------------------------------------------------------------------------


def engineer_features(
    df: pd.DataFrame,
    encoder: FeatureEncoder | None,
    mode: str = "train",
) -> Tuple[pd.DataFrame, Optional[pd.Series], FeatureEncoder]:
    """
    Convert a canonical DataFrame into numeric feature matrix X, target y,
    and the (possibly newly-fitted) encoder.

    Steps, in order:

    1. Drop columns that are never model features, returning
       ``event_id`` and ``extracted_entities`` as a side-output the caller
       can re-attach after scoring.
    2. Derive timestamp features: ``hour_of_day``, ``day_of_week``,
       ``is_weekend`` from ``timestamp``.
    3. Derive simple flow-ratio features where the source columns exist:
       ``bytes_per_packet = bytes_sent / packet_count`` (guard divide-by-zero
       → 0), ``send_receive_ratio = bytes_sent / (bytes_received + 1)``.
    4. Categorical encoding for ``protocol``, ``source_format``:
       - ``mode="train"``: fit a new ``OrdinalEncoder`` (or ``OneHotEncoder``)
         with ``handle_unknown`` set so an unseen category at inference time
         doesn't crash.
       - ``mode="inference"``: use the already-fitted encoder from ``encoder``.
    5. Missing-value handling: numeric columns → median-impute using the
       statistics captured at train time and stored in ``encoder``.
       (Never recompute the median from a single live batch — that would
       drift from training statistics.)
    6. ``label`` column: if present and non-null, this is ``y`` (returned
       separately); if entirely missing/null (as it will be for live
       inference data), return ``y=None``.
    7. Return the final numeric feature DataFrame ``X``, ``y``, and the
       (possibly newly-fitted) ``encoder`` object.

    Parameters
    ----------
    df : pd.DataFrame
        DataFrame in the canonical schema (output of ``map_to_canonical``).
    encoder : FeatureEncoder | None
        Fitted encoder from a previous ``mode="train`` run.  Required in
        ``mode="inference"``; may be ``None`` in ``mode="train"``.
    mode : {"train", "inference"}
        Whether this is a training run or an inference run.

    Returns
    -------
    X : pd.DataFrame
        Final numeric feature DataFrame with ``feature_column_order`` columns.
    y : pd.Series | None
        Target variable (``label`` column) if present, else ``None``.
    encoder : FeatureEncoder
        The (possibly newly-fitted) encoder object for use in subsequent
        inference calls.
    """
    if mode not in ("train", "inference"):
        raise ValueError(f"Invalid mode '{mode}'. Must be 'train' or 'inference'.")

    # ------------------------------------------------------------------
    # 1. Drop non-feature columns, keep side-outputs
    # ------------------------------------------------------------------
    drop_cols = ["event_id", "source_file", "raw_text", "extracted_entities"]
    existing_drop = [c for c in drop_cols if c in df.columns]
    df_remaining = df.drop(columns=existing_drop, errors="ignore")

    # Side-output: event_id and extracted_entities for later re-attachment
    event_ids: Optional[pd.Series] = None
    extracted_entities: Optional[pd.Series] = None
    for c in ["event_id", "extracted_entities"]:
        if c in df.columns:
            if c == "event_id":
                event_ids = df[c]
            elif c == "extracted_entities":
                extracted_entities = df[c]

    # ------------------------------------------------------------------
    # 2. Derive timestamp features
    # ------------------------------------------------------------------
    df_remaining = _derive_timestamp_features(df_remaining)

    # ------------------------------------------------------------------
    # 3. Derive flow-ratio features
    # ------------------------------------------------------------------
    df_remaining = _derive_flow_ratio_features(df_remaining)

    # ------------------------------------------------------------------
    # 4. Categorical encoding
    # ------------------------------------------------------------------
    # Identify categorical columns (object dtype or known names)
    categorical_cols: List[str] = []
    for col in df_remaining.columns:
        if df_remaining[col].dtype == object or col in {"protocol", "source_format"}:
            categorical_cols.append(col)

    if mode == "train":
        # Fit a new encoder
        if categorical_cols:
            # Prefer ordinal encoding for simplicity; switch to onehot if
            # cardinality is very low (your call, but be consistent).
            # Here we use OrdinalEncoder with handle_unknown="use_encoded_value"
            encoder = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
            # Fit only on columns that exist
            available_cat = [c for c in categorical_cols if c in df_remaining.columns]
            if available_cat:
                X_cat = df_remaining[available_cat].copy()
                # Ensure all values are strings for OrdinalEncoder
                X_cat = X_cat.astype(str)
                encoder.fit(X_cat)
        else:
            encoder = FeatureEncoder(
                categorical_encoder=None,
                feature_column_order=list(df_remaining.columns),
            )

        # Build the full encoder with feature order
        encoder = build_encoder_from_df(df_remaining, categorical_cols, {}, encoder_type="ordinal")

    elif mode == "inference":
        if encoder is None:
            raise RuntimeError(
                "Inference mode requires a fitted encoder. "
                "Train a model first (mode='train') or load an encoder from disk."
            )
        # No fitting — use the already-fitted encoder's stats

    # ------------------------------------------------------------------
    # 4 (inference path): Apply the encoder's transform/impute
    # ------------------------------------------------------------------
    if mode == "inference" and encoder is not None:
        # Apply ordinal encoding if available
        if encoder.categorical_encoder is not None and encoder.feature_column_order:
            # Select only the categorical columns that the encoder expects
            available_cat = [c for c in encoder.feature_column_order
                            if c in df_remaining.columns and df_remaining[c].dtype == object]
            if available_cat:
                X_cat = df_remaining[available_cat].copy()
                X_cat = X_cat.astype(str)
                try:
                    encoded_arr = encoder.categorical_encoder.transform(X_cat)
                    if hasattr(encoded_arr, "toarray"):
                        encoded_arr = encoded_arr.toarray()
                    encoded_df = pd.DataFrame(
                        encoded_arr,
                        columns=encoder.get_feature_names(),
                        index=df_remaining.index,
                    )
                except Exception as exc:
                    logger.warning("Categorical encoding failed in inference: %s", exc)
                    encoded_df = pd.DataFrame(index=df_remaining.index)
            else:
                encoded_df = pd.DataFrame(index=df_remaining.index)
        else:
            encoded_df = pd.DataFrame(index=df_remaining.index)

        # Impute numeric medians
        df_imputed = encoder.impute_numeric(df_remaining)
        # Combine encoded categoricals with imputed numerics
        # Drop columns already in encoded_df to avoid double-counting
        remaining_numeric = df_imputed.drop(columns=encoded_df.columns, errors="ignore")
        X = pd.concat([encoded_df, remaining_numeric], axis=1)
    else:
        # Train path: build from df_remaining using build_encoder_from_df
        # This re-creates the encoder with proper feature_column_order
        available_cat = [c for c in categorical_cols if c in df_remaining.columns]
        encoder = build_encoder_from_df(df_remaining, available_cat, {}, encoder_type="ordinal")
        # After encoding, we need to construct X with the right columns
        # Use the encoder's feature_column_order
        X = pd.DataFrame(index=df_remaining.index)
        # Apply imputation first
        df_imputed = encoder.impute_numeric(df_remaining)
        # Then align to feature_column_order
        for col in encoder.feature_column_order:
            if col in df_imputed.columns:
                X[col] = df_imputed[col]
            else:
                X[col] = np.nan

    # ------------------------------------------------------------------
    # 5. Missing-value handling already done via median impute above
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # 6. Target (label) handling
    # ------------------------------------------------------------------
    y: Optional[pd.Series] = None
    if "label" in df.columns:
        # Keep only non-null labels
        label_series = df["label"]
        if label_series.notna().any():
            y = label_series.copy()
            # Remove label from X if it somehow got included
            X = X.drop(columns=["label"], errors="ignore")

    # ------------------------------------------------------------------
    # 7. Return
    # ------------------------------------------------------------------
    # Ensure X has exactly the feature_column_order columns in order
    if hasattr(encoder, "feature_column_order") and encoder.feature_column_order:
        # Reorder X to match
        missing = set(encoder.feature_column_order) - set(X.columns)
        for m in missing:
            X[m] = np.nan
        extra = set(X.columns) - set(encoder.feature_column_order)
        for e in extra:
            X = X.drop(columns=[e], errors="ignore")
        X = X[encoder.feature_column_order]

    logger.info(
        "engineer_features: mode=%s, n_features=%d, y=None=%s",
        mode,
        len(X.columns) if hasattr(encoder, "feature_column_order") else "?",
        y is None,
    )
    return X, y, encoder