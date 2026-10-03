"""Network asset criticality configuration and CIDR matching."""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


def load_asset_criticality(path: Path) -> dict[str, float]:
    """Load, or safely initialize, CIDR-to-criticality weights."""
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("default: 0.3\n", encoding="utf-8")
        logger.info("Created default asset criticality config at %s", path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {str(key): float(value) for key, value in data.items()}


def get_criticality(ip: str | None, criticality_map: dict[str, float]) -> float:
    """Return the matching CIDR weight, falling back safely for bad input."""
    fallback = float(criticality_map.get("default", 0.3))
    try:
        address = ipaddress.ip_address(str(ip))
        for network, weight in criticality_map.items():
            if network != "default" and address in ipaddress.ip_network(network, strict=False):
                return float(weight)
    except ValueError:
        pass
    return fallback
