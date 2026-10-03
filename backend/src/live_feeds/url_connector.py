"""Safe HTTP(S) polling connector for operator-configured telemetry feeds."""
from __future__ import annotations

import csv
import ipaddress
import json
import socket
from io import StringIO
from typing import Any
from urllib.parse import urlparse

import requests

from .base_connector import BaseConnector, _with_retry

MAX_RESPONSE_BYTES = 5 * 1024 * 1024


class UrlFeedError(ValueError):
    """Raised when a URL feed cannot be safely configured or decoded."""


def validate_public_feed_url(url: str) -> str:
    """Validate a public HTTP(S) source and reject SSRF-prone destinations."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UrlFeedError("Provide an absolute HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise UrlFeedError("URLs containing credentials are not supported.")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, None)}
    except socket.gaierror as exc:
        raise UrlFeedError("The source host could not be resolved.") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise UrlFeedError("Private, loopback, or reserved feed hosts are not allowed.")
    return url.strip()


def _records_from_payload(payload: str, content_type: str) -> list[dict[str, Any]]:
    """Decode common telemetry exports into dict records without schema assumptions."""
    content_type = content_type.lower()
    trimmed = payload.lstrip()
    if "text/html" in content_type or trimmed.lower().startswith(("<!doctype", "<html", "<head", "<body")):
        raise UrlFeedError("This URL returned an HTML webpage, not a structured telemetry feed. To scan a website for threats, use the 'URL / Host Threat Scanner'. To stream live telemetry, provide a URL returning JSON or CSV.")

    if "json" in content_type or trimmed.startswith(("{", "[")):
        try:
            value = json.loads(payload)
        except json.JSONDecodeError:
            # NDJSON is commonly served as text/plain.
            value = [json.loads(line) for line in payload.splitlines() if line.strip()]
        if isinstance(value, dict):
            value = value.get("events", value.get("data", [value]))
        if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
            raise UrlFeedError("JSON feeds must contain an object or an array of objects.")
        return value
    try:
        reader = csv.DictReader(StringIO(payload))
        rows = [dict(row) for row in reader]
        if not rows or len(rows[0]) <= 1 and any("<" in k for k in rows[0].keys()):
            raise UrlFeedError("The remote feed did not contain valid CSV or JSON columns.")
        return rows
    except csv.Error as exc:
        raise UrlFeedError("The feed could not be decoded as CSV or JSON.") from exc


class UrlFeedConnector(BaseConnector):
    """Poll a public JSON, NDJSON, or CSV URL and emit source records."""

    def __init__(self, source_id: str, url: str, poll_interval_seconds: float = 10.0) -> None:
        super().__init__(name=f"url:{source_id}", poll_interval_seconds=poll_interval_seconds)
        self.source_id = source_id
        self.url = validate_public_feed_url(url)
        self._state["last_success_at"] = None
        self._state["last_record_count"] = 0
        self._state["last_error"] = None

    @_with_retry
    def poll(self) -> list[dict[str, Any]]:
        response = requests.get(
            self.url,
            timeout=(4, 12),
            allow_redirects=False,
            headers={"Accept": "application/json, application/x-ndjson, text/csv, text/plain"},
        )
        response.raise_for_status()
        declared_size = int(response.headers.get("Content-Length", "0") or 0)
        if declared_size > MAX_RESPONSE_BYTES or len(response.content) > MAX_RESPONSE_BYTES:
            raise UrlFeedError(f"Feed exceeds the {MAX_RESPONSE_BYTES // 1024 // 1024} MB limit.")
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0]
        records = _records_from_payload(response.text, content_type)
        self._state.update(last_success_at=response.headers.get("Date"), last_record_count=len(records), last_error=None)
        return records
