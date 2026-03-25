"""URLhaus feed integration -- recent malicious URLs, payloads, and tags."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import requests

from models.indicator import Indicator, IndicatorType

from .base_feed import BaseFeed

logger = logging.getLogger(__name__)


class URLhausFeed(BaseFeed):
    """Integration with the abuse.ch URLhaus API.

    Supports:
      - ``fetch_indicators``: download recent malicious URLs.
      - ``check_indicator``: query a URL or host against URLhaus.
    """

    name = "urlhaus"
    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        demo_mode: bool = False,
    ) -> None:
        # URLhaus is free / no key required, but we still accept one for consistency
        super().__init__(
            api_key=api_key,
            rate_limit=10,
            rate_period=60.0,
            cache_ttl=300,
            demo_mode=demo_mode,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_indicators(self, limit: int = 100) -> list[Indicator]:
        """Fetch the most recent malicious URLs from URLhaus."""
        if self.demo_mode:
            return self._demo_recent(limit)

        cached = self._cache.get("recent")
        if cached is not None:
            return cached[:limit]

        self._rate_limiter.acquire()
        start = time.monotonic()
        try:
            resp = requests.post(
                f"{self.BASE_URL}/urls/recent/",
                data={"limit": limit},
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json()
            urls = data.get("urls", [])
            indicators = [self._parse_url_entry(u) for u in urls]
            elapsed = (time.monotonic() - start) * 1000
            self._record_fetch(len(indicators), elapsed)
            self._cache.put("recent", indicators)
            return indicators[:limit]
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            self._record_fetch(0, elapsed, error=str(exc))
            logger.warning("URLhaus recent fetch failed: %s", exc)
            return []

    def check_indicator(self, value: str) -> Indicator | None:
        """Look up a URL or host against URLhaus."""
        if self.demo_mode:
            return self._demo_check(value)

        ioc_type = IndicatorType.detect(value)
        if ioc_type == IndicatorType.URL:
            endpoint = f"{self.BASE_URL}/url/"
            payload: dict[str, str] = {"url": value}
        elif ioc_type in (IndicatorType.IP, IndicatorType.DOMAIN):
            endpoint = f"{self.BASE_URL}/host/"
            payload = {"host": value}
        else:
            return None

        cache_key = f"check:{value}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        self._rate_limiter.acquire()
        start = time.monotonic()
        try:
            resp = requests.post(endpoint, data=payload, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            elapsed = (time.monotonic() - start) * 1000

            indicator: Indicator | None = None
            if ioc_type == IndicatorType.URL:
                indicator = self._parse_url_lookup(data)
            else:
                indicator = self._parse_host_lookup(value, data)

            self._record_fetch(1 if indicator else 0, elapsed)
            self._cache.put(cache_key, indicator)
            return indicator
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            self._record_fetch(0, elapsed, error=str(exc))
            logger.warning("URLhaus check failed for %s: %s", value, exc)
            return None

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_url_entry(self, entry: dict[str, Any]) -> Indicator:
        tags = entry.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        threat = entry.get("threat", "")
        if threat and threat not in tags:
            tags.append(threat)
        date_added = entry.get("date_added", "")
        try:
            first_seen = datetime.strptime(date_added, "%Y-%m-%d %H:%M:%S")
            first_seen = first_seen.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            first_seen = datetime.now(timezone.utc)
        status = entry.get("url_status", "")
        confidence = 0.8 if status == "online" else 0.5
        return Indicator(
            value=entry.get("url", ""),
            ioc_type=IndicatorType.URL,
            source=self.name,
            first_seen=first_seen,
            confidence=confidence,
            tags=tags,
            raw_context=entry,
        )

    def _parse_url_lookup(self, data: dict[str, Any]) -> Indicator | None:
        if data.get("query_status") != "ok":
            return None
        return self._parse_url_entry(data)

    def _parse_host_lookup(
        self, value: str, data: dict[str, Any]
    ) -> Indicator | None:
        url_count = data.get("url_count", 0) or data.get("urls_online", 0)
        if not url_count:
            return None
        ioc_type = IndicatorType.detect(value)
        confidence = min(url_count / 20, 1.0)
        tags: list[str] = []
        for u in (data.get("urls", []) or [])[:10]:
            for t in (u.get("tags") or []):
                if t and t not in tags:
                    tags.append(t)
        return Indicator(
            value=value,
            ioc_type=ioc_type,
            source=self.name,
            confidence=round(confidence, 2),
            tags=tags[:15],
            raw_context={"url_count": url_count},
        )

    # ------------------------------------------------------------------
    # Demo helpers
    # ------------------------------------------------------------------

    def _demo_recent(self, limit: int) -> list[Indicator]:
        from demo.mock_feeds import MOCK_URLHAUS_RECENT

        indicators = [self._parse_url_entry(e) for e in MOCK_URLHAUS_RECENT]
        self._record_fetch(len(indicators), 55.0)
        return indicators[:limit]

    def _demo_check(self, value: str) -> Indicator | None:
        from demo.mock_feeds import MOCK_URLHAUS_HOST_LOOKUP

        data = MOCK_URLHAUS_HOST_LOOKUP.get(value)
        if data is None:
            self._record_fetch(0, 6.0)
            return None
        ioc_type = IndicatorType.detect(value)
        if ioc_type == IndicatorType.URL:
            indicator = self._parse_url_lookup(data)
        else:
            indicator = self._parse_host_lookup(value, data)
        self._record_fetch(1 if indicator else 0, 6.0)
        return indicator
