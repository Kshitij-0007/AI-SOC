"""
model_registry.py — Manages versioned XGBoost models and metadata.

Registry JSON stored at ``models/xgboost/registry.json``.
Append-only: never delete a previous version's entry, even after a newer
one becomes active — old versions stay loadable for comparison/rollback.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_REGISTRY_FILE = "models/xgboost/registry.json"


def _ensure_registry_dir(base: Path) -> Path:
    """Ensure the models/xgboost directory exists and return it."""
    registry_dir = base / "xgboost"
    registry_dir.mkdir(parents=True, exist_ok=True)
    return registry_dir


def _load_registry(base: Path) -> dict:
    """Load the registry JSON, or return a fresh one if missing."""
    registry_path = _ensure_registry_dir(base) / _REGISTRY_FILE
    if registry_path.exists():
        with open(registry_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"active_version": "v1", "versions": {}}


def _save_registry(base: Path, registry: dict) -> None:
    """Persist the registry JSON to disk."""
    registry_path = _ensure_registry_dir(base) / _REGISTRY_FILE
    with open(registry_path, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2)
    logger.info("Registry saved to %s", registry_path)


def register_new_version(
    base: Path,
    model_path: Path,
    metrics_path: Path,
    encoder_path: Path,
) -> str:
    """
    Create the next ``vN`` folder under ``models/xgboost/`` and record
    paths into the registry.

    Does **not** automatically make it active — promotion to active is a
    separate explicit call (never silently swap the live model).

    Returns the new version ID string (e.g. ``"v2"``).
    """
    registry_dir = _ensure_registry_dir(base)
    registry = _load_registry(base)

    # Determine next version number
    existing_versions: List[str] = list(registry.get("versions", {}).keys())
    # Extract numeric part
    numeric_versions: List[int] = []
    for v in existing_versions:
        try:
            numeric_versions.append(int(v.lstrip("v")))
        except ValueError:
            pass
    next_num = max(numeric_versions) + 1 if numeric_versions else 1
    new_version = f"v{next_num}"

    # Copy/save paths into version-specific locations
    version_dir = registry_dir / new_version
    version_dir.mkdir(parents=True, exist_ok=True)

    # The model and metrics paths are referenced by their original paths;
    # the registry just records them.  In practice the caller copies the
    # the model paths are referenced by their original paths; the registry just records them. In practice the caller copies the files, but for this module we just record the references.
    registry["versions"][new_version] = {
        "path": str(model_path),
        "metrics_path": str(metrics_path),
        "encoder_path": str(encoder_path),
        "created_at": datetime.now(tz=timezone.utc).isoformat(),
    }

    # Preserve previous active version's status if it exists
    if registry.get("active_version") is None:
        # First version becomes active by default
        registry["active_version"] = new_version

    _save_registry(base, registry)

    logger.info("Registered new XGBoost version: %s", new_version)
    return new_version


def set_active_version(base: Path, version_id: str) -> None:
    """
    Promote *version_id* to active.

    Never silently swap the live model — this is an explicit call.
    """
    registry_dir = _ensure_registry_dir(base)
    registry = _load_registry(base)

    if version_id not in registry.get("versions", {}):
        raise ValueError(f"Version '{version_id}' not found in registry.")

    old_active = registry.get("active_version")
    registry["active_version"] = version_id
    _save_registry(base, registry)

    logger.info("Active version set to %s (previously was %s)",
                version_id, old_active)


def get_active_version(base: Path) -> Optional[dict]:
    """
    Return the registry entry for the active version:

    ``{"path", "metrics_path", "encoder_path"}`` for whichever version
    is active.
    """
    registry = _load_registry(base)
    active = registry.get("active_version")
    if active is None or active not in registry.get("versions", {}):
        return None
    return registry["versions"][active]
