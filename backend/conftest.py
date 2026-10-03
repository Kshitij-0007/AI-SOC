"""
conftest.py — Shared pytest configuration for the AI-SOC backend test suite.

Adds the backend directory to sys.path so all tests can import
``src.*`` without needing an installed package.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Insert backend root so `import src.ingestion...` works from any test
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
