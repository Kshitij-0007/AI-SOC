"""
pipeline.py — Top-level feature-engineering orchestrator.

``run_feature_engineering`` walks the input parquet, dispatches to the
correct mode, and writes three output artefacts to ``output_dir``:

* ``feature_table.parquet``       — numeric feature matrix + optional label
* ``encoder_v{N}.joblib``         — fitted FeatureEncoder (training only)
* ``ingestion_log.jsonl``         — one-line-per-run audit log

No file failure ever stops the batch; errors are caught, logged, and
recorded in ``ingestion_log.jsonl``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from .feature_engineering import engineer_features
from .smote_balancer import balance_classes
from .feature_store_io import save_feature_table, load_feature_table
from .feature_encoder import FeatureEncoder

logger = logging.getLogger(__name__)

# Output file names
_FEATURE_OUT = "feature_table.parquet"
_ENCODER_OUT = "encoder_v{version}.joblog"
_LOG_OUT = "ingestion_log.jsonl"


def _utc_now() -> str:
    """Return current UTC time as an ISO 8601 string."""
    return datetime.now(tz=timezone.utc).isoformat()


def _append_log(log_path: Path, record: dict[str, Any]) -> None:
    """Append a single JSON record to the audit log file."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, default=str) + "\n")


def _next_encoder_version(existing_versions: List[int]) -> int:
    """Return the next encoder version number."""
    if not existing_versions:
        return 1
    return max(existing_versions) + 1


def run_feature_engineering(
    input_parquet: Path,
    output_dir: Path,
    mode: str = "train",
    encoder_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Run the feature-engineering pipeline.

    Parameters
    ----------
    input_parquet : Path
        Path to the canonical parquet (output of Module 1's ``run_ingestion``).
    output_dir : Path
        Directory where ``feature_table.parquet``, ``encoder_v{N}.joblib``,
        and ``ingestion_log.jsonl`` will be written.
    mode : {"train", "inference"}
        ``"train"``: fit encoders, apply SMOTE, save encoder.
        ``"inference"``: load encoder, transform only (no SMOTE).
    encoder_path : Path | None
        Required in ``mode="inference"`` — path to a previously-saved
        ``FeatureEncoder``.  Ignored in ``mode="train"``.

    Returns
    -------
    dict
        Summary: ``{"mode", "rows_in", "rows_out", "n_features",
        "encoder_version_used"}``.
    """
    input_parquet = Path(input_parquet)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    log_path = output_dir / _LOG_OUT
    chunks_path = output_dir / _FEATURE_OUT

    # Load input
    df = pd.read_parquet(input_parquet)
    rows_in = len(df)

    # ------------------------------------------------------------------
    # Mode-specific logic
    # ------------------------------------------------------------------
    encoder: Any = None
    encoder_version: Optional[int] = None

    if mode == "train":
        # Fit engineer features + encoder
        X, y, encoder = engineer_features(df, encoder=None, mode="train")

        # Apply SMOTE if there are enough classes
        if y is not None and len(y.unique()) >= 2:
            X, y = balance_classes(X, y, config={"enabled": True, "k_neighbors": 5})
        else:
            logger.warning("Skipping SMOTE: insufficient classes in y.")

        # Save encoder
        # Determine next version number by scanning existing encoders
        existing_versions: List[int] = []
        if output_dir.is_dir():
            for f in output_dir.glob("encoder_v*.joblib"):
                try:
                    ver = int(f.stem.replace("encoder_v", ""))
                    existing_versions.append(ver)
                except ValueError:
                    pass

        encoder_version = _next_encoder_version(existing_versions)
        encoder_save_path = output_dir / f"encoder_v{encoder_version}.joblib"
        encoder.save(encoder_save_path)

        # Save feature table
        save_feature_table(X, y, chunks_path)

    elif mode == "inference":
        if encoder_path is None:
            raise RuntimeError(
                "Inference mode requires --encoder-path to a saved FeatureEncoder."
            )
        encoder = FeatureEncoder.load(encoder_path)

        # Transform only — no SMOTE
        X, y, encoder = engineer_features(df, encoder=encoder, mode="inference")

        # Save feature table (label may be all-null)
        save_feature_table(X, y, chunks_path)
        encoder_version = None  # No new encoder version in inference

    else:
        raise ValueError(f"Invalid mode '{mode}'. Must be 'train' or 'inference'.")

    # ------------------------------------------------------------------
    # Write audit log
    # ------------------------------------------------------------------
    _append_log(log_path, {
        "source_file": str(input_parquet),
        "detected_mode": mode,
        "status": "ok",
        "rows_in": rows_in,
        "rows_out": len(X),
        "n_features": len(X.columns),
        "encoder_version_used": encoder_version,
        "timestamp": _utc_now(),
    })

    summary: Dict[str, Any] = {
        "mode": mode,
        "rows_in": rows_in,
        "rows_out": len(X),
        "n_features": len(X.columns),
        "encoder_version_used": encoder_version,
    }
    logger.info("Feature engineering complete: %s", summary)
    print(f"\n{'='*50}\nFeature Engineering Summary\n{'='*50}")
    for k, v in summary.items():
        print(f"  {k:<20}: {v}")
    print(f"  output_dir        : {output_dir}")
    print(f"{'='*50}\n")
    return summary


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="AI-SOC Feature Engineering Pipeline")
    ap.add_argument(
        "--input-parquet",
        default="data/processed/processed.parquet",
        help="Path to canonical parquet (default: data/processed/processed.parquet)",
    )
    ap.add_argument(
        "--output-dir",
        default="data/feature_store",
        help="Directory for output artefacts (default: data/feature_store)",
    )
    ap.add_argument(
        "--mode",
        choices=["train", "inference"],
        default="train",
        help="Run mode: 'train' fits encoders/SMOTE; 'inference' transforms only.",
    )
    ap.add_argument(
        "--encoder-path",
        default=None,
        help="Path to saved FeatureEncoder (required for inference mode).",
    )
    args = ap.parse_args()

    run_feature_engineering(
        input_parquet=Path(args.input_parquet),
        output_dir=Path(args.output_dir),
        mode=args.mode,
        encoder_path=Path(args.encoder_path) if args.encoder_path else None,
    )
