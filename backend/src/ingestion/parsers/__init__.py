"""
Parsers sub-package — one module per input format family.
"""

from .csv_xlsx_parser import parse_tabular  # noqa: F401
from .log_parser import parse_log  # noqa: F401
from .text_parser import parse_text  # noqa: F401

__all__ = ["parse_tabular", "parse_log", "parse_text"]
