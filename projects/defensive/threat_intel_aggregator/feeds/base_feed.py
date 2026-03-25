"""Abstract base class for all threat intelligence feed providers."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from models.indicator import Indicator

logger = logging.getLogger(__name__)


@dataclass
class FeedHealth:
    """Health / status snapshot for a feed provider."""

    name: str
    available: bool = False
    last_fetch: datetime | None = None
    last_error: str | None = None
    indicators_fetched: int = 0
    avg_response_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "available": self.available,
            "last_fetch": self.last_fetch.isoformat() if self.last_fetch else None,
            "last_error": self.last_error,
            "indicators_fetched": self.indicators_fetched,
            "avg_response_ms": round(self.avg_response_ms, 1),
        }


class RateLimiter:
    """Simple token-bucket rate limiter."""

    def __init__(self, max_calls: int, period_seconds: float) -> None:
        self.max_calls = max_calls
        self.period = period_seconds
        self._timestamps: list[float] = []

    def acquire(self) -> None:
        """Block until a request slot is available."""
        now = time.monotonic()
        self._timestamps = [
            t for t in self._timestamps if now - t < self.period
        ]
        if len(self._timestamps) >= self.max_calls:
            sleep_for = self.period - (now - self._timestamps[0])
            if sleep_for > 0:
                logger.debug("Rate limiter sleeping %.2fs", sleep_for)
                time.sleep(sleep_for)
        self._timestamps.append(time.monotonic())


class FeedCache:
    """In-memory cache with TTL for feed responses."""

    def __init__(self, ttl_seconds: int = 300) -> None:
        self.ttl = ttl_seconds
        self._store: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        ts, value = entry
        if time.monotonic() - ts > self.ttl:
            del self._store[key]
            return None
        return value

    def put(self, key: str, value: Any) -> None:
        self._store[key] = (time.monotonic(), value)

    def clear(self) -> None:
        self._store.clear()


class BaseFeed(ABC):
    """Abstract base class that every feed provider must implement.

    Subclasses should override ``fetch_indicators`` and ``check_indicator``.
    """

    name: str = "base"
    _rate_limiter: RateLimiter
    _cache: FeedCache
    _health: FeedHealth
    _response_times: list[float]

    def __init__(
        self,
        api_key: str | None = None,
        *,
        rate_limit: int = 30,
        rate_period: float = 60.0,
        cache_ttl: int = 300,
        demo_mode: bool = False,
    ) -> None:
        self.api_key = api_key
        self.demo_mode = demo_mode
        self._rate_limiter = RateLimiter(rate_limit, rate_period)
        self._cache = FeedCache(ttl_seconds=cache_ttl)
        self._health = FeedHealth(name=self.name)
        self._response_times: list[float] = []

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @abstractmethod
    def fetch_indicators(self, limit: int = 100) -> list[Indicator]:
        """Pull recent indicators from the feed.

        Args:
            limit: Maximum number of indicators to return.

        Returns:
            A list of :class:`Indicator` instances.
        """
        ...

    @abstractmethod
    def check_indicator(self, value: str) -> Indicator | None:
        """Look up a single value against this feed.

        Args:
            value: An IP, domain, URL, or hash string.

        Returns:
            An :class:`Indicator` if the value is known-bad, else ``None``.
        """
        ...

    # ------------------------------------------------------------------
    # Helpers available to subclasses
    # ------------------------------------------------------------------

    def _record_fetch(
        self,
        count: int,
        elapsed_ms: float,
        error: str | None = None,
    ) -> None:
        """Update health metrics after a fetch attempt."""
        self._health.last_fetch = datetime.now(timezone.utc)
        self._health.indicators_fetched += count
        self._response_times.append(elapsed_ms)
        if error:
            self._health.available = False
            self._health.last_error = error
        else:
            self._health.available = True
            self._health.last_error = None
        # Rolling average of last 20 response times
        recent = self._response_times[-20:]
        self._health.avg_response_ms = sum(recent) / len(recent)

    @property
    def health(self) -> FeedHealth:
        return self._health

    def __repr__(self) -> str:
        mode = "demo" if self.demo_mode else "live"
        return f"<{self.__class__.__name__} mode={mode}>"
