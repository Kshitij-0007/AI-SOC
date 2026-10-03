"""
base_connector.py — Abstract base class for all live-feed connectors.

Every connector must:
* Implement ``poll()`` to return new canonical-ish records since the last call.
* Use ``get_state()`` / ``set_state()`` to persist a cursor across restarts.
* Use the ``_with_retry`` decorator for any network call so that transient
  failures never crash the scheduler loop.

Exponential backoff: 3 retries, delays of 1 s, 2 s, 4 s.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from functools import wraps
from typing import Any, Callable, TypeVar

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])

_MAX_RETRIES = 3
_BASE_DELAY_S = 1.0


# ---------------------------------------------------------------------------
# Retry decorator
# ---------------------------------------------------------------------------

def _with_retry(fn: F) -> F:
    """
    Exponential-backoff retry decorator (max 3 retries, base delay 1 s).

    On every failure the exception is logged; after exhausting retries the
    last exception is re-raised so the caller (scheduler) can catch it and
    continue with the next connector.
    """
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        delay = _BASE_DELAY_S
        last_exc: Exception | None = None
        for attempt in range(1, _MAX_RETRIES + 2):  # +1 for initial try
            try:
                return fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt <= _MAX_RETRIES:
                    logger.warning(
                        "Attempt %d/%d failed for %s: %s — retrying in %.1fs",
                        attempt, _MAX_RETRIES + 1, fn.__qualname__, exc, delay,
                    )
                    time.sleep(delay)
                    delay *= 2
                else:
                    logger.error(
                        "All %d attempts failed for %s: %s",
                        _MAX_RETRIES + 1, fn.__qualname__, exc,
                    )
        raise last_exc  # type: ignore[misc]
    return wrapper  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class BaseConnector(ABC):
    """
    Abstract base for all AI-SOC live-feed connectors.

    Subclasses must implement :meth:`poll`.  They may optionally override
    :meth:`get_state` / :meth:`set_state` if they need persistent cursor
    storage (file offset, last-seen timestamp, etc.).

    Parameters
    ----------
    name:
        Human-readable connector identifier (used in log messages).
    poll_interval_seconds:
        Suggested polling cadence in seconds.  The scheduler reads this
        value; individual connectors do **not** sleep internally.
    """

    def __init__(self, name: str, poll_interval_seconds: float = 60.0) -> None:
        self.name = name
        self.poll_interval_seconds = poll_interval_seconds
        self._state: dict[str, Any] = {}
        self._enabled: bool = True
        self.logger = logging.getLogger(f"{__name__}.{name}")

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    def get_state(self) -> dict[str, Any]:
        """
        Return the connector's persistent state dict.

        The state is used to resume from where the last poll ended (e.g.
        file byte offset, last-seen timestamp).
        """
        return self._state.copy()

    def set_state(self, state: dict[str, Any]) -> None:
        """Replace the connector's internal state with *state*."""
        self._state = state

    # ------------------------------------------------------------------
    # Enable / disable
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Whether this connector is active."""
        return self._enabled

    def disable(self, reason: str = "") -> None:
        """Disable this connector and log the reason."""
        self._enabled = False
        self.logger.warning("Connector '%s' disabled: %s", self.name, reason)

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def poll(self) -> list[dict[str, Any]]:
        """
        Fetch new records since the last call.

        Returns
        -------
        list[dict]
            Zero or more canonical-ish record dicts.  An empty list means
            no new data is available.  Never raises — exceptions should be
            caught internally or by the ``_with_retry`` decorator.
        """

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"name={self.name!r}, "
            f"enabled={self._enabled}, "
            f"interval={self.poll_interval_seconds}s)"
        )
