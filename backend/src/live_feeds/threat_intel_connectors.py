"""
threat_intel_connectors.py — Live threat-intelligence feed connectors.

One class per source, all implementing BaseConnector:

* ``AbuseIPDBConnector``   — on-demand IP reputation checks (free tier ~1000/day)
* ``VirusTotalConnector``  — hash/domain lookups (hard 4 req/min rate limiter)
* ``MISPConnector``        — local/remote MISP REST API, timestamp-cursor poll
* ``OTXConnector``         — AlienVault OTX pulse pull by modified timestamp

All API keys are read from environment variables; if a key is missing the
connector disables itself cleanly — it never crashes the scheduler.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import time
from datetime import datetime, timezone
from typing import Any

import requests

from .base_connector import BaseConnector, _with_retry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _get_env_key(env_var: str, connector_name: str) -> str | None:
    """
    Return the value of *env_var* from the environment, or log a warning
    and return ``None`` if it is not set.
    """
    val = os.getenv(env_var)
    if not val:
        logger.warning(
            "[%s] API key env var '%s' is not set — connector will be disabled.",
            connector_name,
            env_var,
        )
    return val or None


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

class AbuseIPDBConnector(BaseConnector):
    """
    On-demand AbuseIPDB IP reputation connector.

    ``poll()`` is a no-op (or drains a small IP queue).  The real
    entrypoint is ``check_ip(ip)`` which makes a single API call.

    Parameters
    ----------
    api_key_env:
        Name of the environment variable holding the AbuseIPDB API key.
    ip_queue_maxsize:
        Maximum number of IPs to hold in the pending-check queue.
    """

    _BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(
        self,
        api_key_env: str = "ABUSEIPDB_API_KEY",
        ip_queue_maxsize: int = 100,
        poll_interval_seconds: float = 300.0,
    ) -> None:
        super().__init__(name="abuseipdb", poll_interval_seconds=poll_interval_seconds)
        key = _get_env_key(api_key_env, "AbuseIPDB")
        if key is None:
            self.disable("API key not configured")
        self._api_key = key
        self._pending: queue.Queue[str] = queue.Queue(maxsize=ip_queue_maxsize)

    def enqueue_ip(self, ip: str) -> None:
        """Add an IP address to the pending-check queue (non-blocking)."""
        try:
            self._pending.put_nowait(ip)
        except queue.Full:
            logger.warning("[AbuseIPDB] IP queue full — dropping %s", ip)

    @_with_retry
    def check_ip(self, ip: str) -> dict[str, Any]:
        """
        Query AbuseIPDB for *ip* and return the parsed response dict.

        Raises on HTTP errors after retries are exhausted.
        """
        if not self._enabled or not self._api_key:
            return {"error": "connector disabled"}
        resp = requests.get(
            self._BASE_URL,
            headers={"Key": self._api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("data", {})

    def poll(self) -> list[dict[str, Any]]:
        """Drain the pending IP queue; return enrichment records."""
        if not self._enabled:
            return []
        results: list[dict] = []
        while not self._pending.empty():
            try:
                ip = self._pending.get_nowait()
                data = self.check_ip(ip)
                data["source_format"] = "abuseipdb"
                data["source_file"] = "live:abuseipdb"
                results.append(data)
            except Exception as exc:  # noqa: BLE001
                logger.error("[AbuseIPDB] poll error: %s", exc)
        return results


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

class VirusTotalConnector(BaseConnector):
    """
    VirusTotal hash / domain lookup connector.

    Enforces the free-tier rate limit of 4 requests per minute using a
    token-bucket counter — not just a comment.

    Parameters
    ----------
    api_key_env:
        Name of the environment variable holding the VT API key.
    requests_per_minute:
        Hard rate limit (default: 4 for free tier).
    """

    _BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key_env: str = "VIRUSTOTAL_API_KEY",
        requests_per_minute: int = 4,
        poll_interval_seconds: float = 60.0,
    ) -> None:
        super().__init__(name="virustotal", poll_interval_seconds=poll_interval_seconds)
        key = _get_env_key(api_key_env, "VirusTotal")
        if key is None:
            self.disable("API key not configured")
        self._api_key = key
        self._rpm = requests_per_minute
        # Token bucket state
        self._tokens = float(requests_per_minute)
        self._last_refill = time.monotonic()

    def _consume_token(self) -> bool:
        """
        Attempt to consume one rate-limit token.

        Refills the bucket pro-rata based on elapsed time.  Returns
        ``False`` (and logs a skip) if no tokens are available.
        """
        now = time.monotonic()
        elapsed = now - self._last_refill
        # Refill at rpm tokens-per-60s
        self._tokens = min(
            float(self._rpm),
            self._tokens + elapsed * (self._rpm / 60.0),
        )
        self._last_refill = now

        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        logger.warning("[VirusTotal] Rate limit reached — skipping request.")
        return False

    def _vt_get(self, endpoint: str) -> dict[str, Any]:
        """Make a rate-limited GET request to the VT v3 API."""
        if not self._consume_token():
            return {"error": "rate_limited"}
        resp = requests.get(
            f"{self._BASE_URL}/{endpoint}",
            headers={"x-apikey": self._api_key},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    @_with_retry
    def check_hash(self, file_hash: str) -> dict[str, Any]:
        """Query VirusTotal for a file hash (MD5/SHA1/SHA256)."""
        if not self._enabled or not self._api_key:
            return {"error": "connector disabled"}
        return self._vt_get(f"files/{file_hash}")

    @_with_retry
    def check_domain(self, domain: str) -> dict[str, Any]:
        """Query VirusTotal for a domain name."""
        if not self._enabled or not self._api_key:
            return {"error": "connector disabled"}
        return self._vt_get(f"domains/{domain}")

    def poll(self) -> list[dict[str, Any]]:
        """VirusTotal is on-demand only; ``poll()`` is intentionally a no-op."""
        return []


# ---------------------------------------------------------------------------
# MISP
# ---------------------------------------------------------------------------

class MISPConnector(BaseConnector):
    """
    MISP REST API connector — polls for new attributes since last timestamp.

    Parameters
    ----------
    base_url_env:
        Env var name for the MISP instance URL (e.g. ``https://localhost``).
    api_key_env:
        Env var name for the MISP API key.
    verify_ssl:
        Set to ``False`` for local self-signed MISP instances.
    """

    def __init__(
        self,
        base_url_env: str = "MISP_BASE_URL",
        api_key_env: str = "MISP_API_KEY",
        verify_ssl: bool = True,
        poll_interval_seconds: float = 300.0,
    ) -> None:
        super().__init__(name="misp", poll_interval_seconds=poll_interval_seconds)
        self._base_url = os.getenv(base_url_env, "").rstrip("/")
        key = _get_env_key(api_key_env, "MISP")
        if not key or not self._base_url:
            self.disable("API key or base URL not configured")
        self._api_key = key
        self._verify_ssl = verify_ssl
        # State: last-seen timestamp (ISO string)
        self._state.setdefault("last_seen_ts", "1970-01-01T00:00:00+00:00")

    @_with_retry
    def poll(self) -> list[dict[str, Any]]:
        """Return MISP attributes added since the last poll timestamp."""
        if not self._enabled or not self._api_key:
            return []

        last_ts = self._state.get("last_seen_ts", "1970-01-01T00:00:00+00:00")
        payload = {"timestamp": last_ts, "returnFormat": "json"}

        resp = requests.post(
            f"{self._base_url}/attributes/restSearch",
            headers={
                "Authorization": self._api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            data=json.dumps(payload),
            verify=self._verify_ssl,
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        attributes = data.get("response", {}).get("Attribute", [])

        records = [
            {
                "source_file": "live:misp",
                "source_format": "misp",
                "raw_text": json.dumps(attr),
                "timestamp": attr.get("timestamp"),
                **attr,
            }
            for attr in attributes
        ]

        if attributes:
            self._state["last_seen_ts"] = _utc_now_iso()

        logger.info("[MISP] poll → %d new attributes", len(records))
        return records


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------

class OTXConnector(BaseConnector):
    """
    AlienVault OTX pulse connector — pulls pulses modified since last poll.

    Parameters
    ----------
    api_key_env:
        Env var name for the OTX API key.
    """

    _BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(
        self,
        api_key_env: str = "OTX_API_KEY",
        poll_interval_seconds: float = 600.0,
    ) -> None:
        super().__init__(name="otx", poll_interval_seconds=poll_interval_seconds)
        key = _get_env_key(api_key_env, "OTX")
        if key is None:
            self.disable("API key not configured")
        self._api_key = key
        self._state.setdefault("modified_since", "1970-01-01T00:00:00")

    @_with_retry
    def poll(self) -> list[dict[str, Any]]:
        """Return OTX pulses modified since the last successful poll."""
        if not self._enabled or not self._api_key:
            return []

        modified_since = self._state.get("modified_since", "1970-01-01T00:00:00")
        resp = requests.get(
            f"{self._BASE_URL}/pulses/subscribed",
            headers={"X-OTX-API-KEY": self._api_key},
            params={"modified_since": modified_since, "limit": 50},
            timeout=20,
        )
        resp.raise_for_status()
        pulses = resp.json().get("results", [])

        records = [
            {
                "source_file": "live:otx",
                "source_format": "otx",
                "raw_text": json.dumps(pulse),
                "timestamp": pulse.get("modified"),
                "label": pulse.get("name"),
            }
            for pulse in pulses
        ]

        if pulses:
            self._state["modified_since"] = _utc_now_iso()

        logger.info("[OTX] poll → %d pulses", len(records))
        return records
