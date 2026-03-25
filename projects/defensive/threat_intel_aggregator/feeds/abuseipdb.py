"""AbuseIPDB feed integration -- IP reputation and abuse category lookup."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import requests

from models.indicator import Indicator, IndicatorType

from .base_feed import BaseFeed

logger = logging.getLogger(__name__)

# AbuseIPDB category mapping (subset)
ABUSE_CATEGORIES: dict[int, str] = {
    1: "dns_compromise",
    2: "dns_poisoning",
    3: "fraud_orders",
    4: "ddos_attack",
    5: "ftp_brute_force",
    7: "ping_of_death",
    8: "phishing",
    9: "fraud_voip",
    10: "open_proxy",
    11: "web_spam",
    14: "port_scan",
    15: "hacking",
    18: "brute_force",
    19: "bad_web_bot",
    20: "exploited_host",
    21: "web_app_attack",
    22: "ssh_brute_force",
    23: "iot_targeted",
}


class AbuseIPDBFeed(BaseFeed):
    """Integration with the AbuseIPDB v2 API.

    Supports:
      - ``check_indicator``: look up a single IP for its abuse confidence score.
      - ``fetch_indicators``: retrieve the AbuseIPDB blacklist (requires paid key,
        falls back to demo data).
    """

    name = "abuseipdb"
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        demo_mode: bool = False,
    ) -> None:
        super().__init__(
            api_key=api_key,
            rate_limit=5,
            rate_period=60.0,
            cache_ttl=600,
            demo_mode=demo_mode,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_indicators(self, limit: int = 100) -> list[Indicator]:
        """Fetch the AbuseIPDB blacklist (top reported IPs)."""
        if self.demo_mode:
            return self._demo_blacklist(limit)

        cached = self._cache.get("blacklist")
        if cached is not None:
            return cached[:limit]

        self._rate_limiter.acquire()
        start = time.monotonic()
        try:
            resp = requests.get(
                f"{self.BASE_URL}/blacklist",
                headers={
                    "Key": self.api_key or "",
                    "Accept": "application/json",
                },
                params={"confidenceMinimum": 75, "limit": limit},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json().get("data", [])
            indicators = [self._parse_blacklist_entry(entry) for entry in data]
            elapsed = (time.monotonic() - start) * 1000
            self._record_fetch(len(indicators), elapsed)
            self._cache.put("blacklist", indicators)
            return indicators[:limit]
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            self._record_fetch(0, elapsed, error=str(exc))
            logger.warning("AbuseIPDB blacklist fetch failed: %s", exc)
            return []

    def check_indicator(self, value: str) -> Indicator | None:
        """Check a single IP against AbuseIPDB."""
        if self.demo_mode:
            return self._demo_check(value)

        cache_key = f"check:{value}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        self._rate_limiter.acquire()
        start = time.monotonic()
        try:
            resp = requests.get(
                f"{self.BASE_URL}/check",
                headers={
                    "Key": self.api_key or "",
                    "Accept": "application/json",
                },
                params={"ipAddress": value, "maxAgeInDays": 90},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            elapsed = (time.monotonic() - start) * 1000
            indicator = self._parse_check_response(data)
            self._record_fetch(1 if indicator else 0, elapsed)
            self._cache.put(cache_key, indicator)
            return indicator
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            self._record_fetch(0, elapsed, error=str(exc))
            logger.warning("AbuseIPDB check failed for %s: %s", value, exc)
            return None

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_blacklist_entry(self, entry: dict[str, Any]) -> Indicator:
        confidence = entry.get("abuseConfidenceScore", 50) / 100.0
        categories = entry.get("categories", [])
        tags = [ABUSE_CATEGORIES.get(c, f"cat_{c}") for c in categories]
        return Indicator(
            value=entry["ipAddress"],
            ioc_type=IndicatorType.IP,
            source=self.name,
            confidence=confidence,
            tags=tags,
            raw_context=entry,
        )

    def _parse_check_response(self, data: dict[str, Any]) -> Indicator | None:
        score = data.get("abuseConfidenceScore", 0)
        if score < 5:
            return None
        categories = data.get("categories", [])
        tags = [ABUSE_CATEGORIES.get(c, f"cat_{c}") for c in categories]
        return Indicator(
            value=data.get("ipAddress", ""),
            ioc_type=IndicatorType.IP,
            source=self.name,
            confidence=score / 100.0,
            tags=tags,
            raw_context=data,
        )

    # ------------------------------------------------------------------
    # Demo helpers
    # ------------------------------------------------------------------

    def _demo_blacklist(self, limit: int) -> list[Indicator]:
        from demo.mock_feeds import MOCK_ABUSEIPDB_BLACKLIST

        indicators = [self._parse_blacklist_entry(e) for e in MOCK_ABUSEIPDB_BLACKLIST]
        self._record_fetch(len(indicators), 42.0)
        return indicators[:limit]

    def _demo_check(self, value: str) -> Indicator | None:
        from demo.mock_feeds import MOCK_ABUSEIPDB_CHECKS

        data = MOCK_ABUSEIPDB_CHECKS.get(value)
        if data is None:
            self._record_fetch(0, 5.0)
            return None
        indicator = self._parse_check_response(data)
        self._record_fetch(1 if indicator else 0, 5.0)
        return indicator
