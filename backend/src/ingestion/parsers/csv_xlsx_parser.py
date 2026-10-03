"""
csv_xlsx_parser.py — Parses CSV and XLSX files into raw DataFrames.

Column mapping to the canonical schema is NOT done here; that is the
responsibility of schema_mapper.py. This parser only ensures the data
can be loaded and adds the two provenance columns: ``source_file`` and
``source_format``.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)

_CSV_ENCODINGS = ("utf-8", "utf-8-sig", "latin-1", "cp1252")


def _read_csv(file_path: Path) -> pd.DataFrame:
    """Attempt CSV parse with multiple encodings, returning first success."""
    size_mb = file_path.stat().st_size / (1024 * 1024)
    # If file is larger than 20 MB, sample the first 50,000 rows for responsive ingestion
    nrows = 50000 if size_mb > 20 else None
    for enc in _CSV_ENCODINGS:
        try:
            df = pd.read_csv(file_path, encoding=enc, low_memory=False, nrows=nrows)
            logger.info("Parsed %s (%0.1f MB, %d rows loaded) with encoding %s", file_path.name, size_mb, len(df), enc)
            return df
        except UnicodeDecodeError:
            continue
        except Exception as exc:  # noqa: BLE001
            logger.warning("CSV parse error (%s) for %s: %s", enc, file_path, exc)
            raise
    raise ValueError(f"Could not decode {file_path} with any known encoding.")


def _read_xlsx(file_path: Path) -> pd.DataFrame:
    """Parse Excel file using openpyxl engine."""
    return pd.read_excel(file_path, engine="openpyxl")


def parse_tabular(file_path: Path) -> pd.DataFrame:
    """
    Parse a CSV or XLSX file and return a raw :class:`pandas.DataFrame`.

    Two extra columns are appended before returning:

    * ``source_file``   — the original file path as a string.
    * ``source_format`` — ``"csv"`` or ``"xlsx"``.

    No column renaming or schema enforcement is performed here.

    Parameters
    ----------
    file_path:
        Path to the ``.csv`` or ``.xlsx`` file.

    Returns
    -------
    pd.DataFrame
        Raw DataFrame with ``source_file`` and ``source_format`` columns.

    Raises
    ------
    ValueError
        If the file extension is not recognised as tabular.
    """
    path = Path(file_path)
    ext = path.suffix.lower()

    if ext == ".csv":
        df = _read_csv(path)
        fmt = "csv"
    elif ext in (".xlsx", ".xls"):
        df = _read_xlsx(path)
        fmt = "xlsx"
    else:
        raise ValueError(f"parse_tabular received unsupported extension '{ext}' for {path}")

    df["source_file"] = str(path)
    df["source_format"] = fmt
    logger.info("Parsed tabular file %s → %d rows, %d cols", path.name, len(df), len(df.columns))
    return df
