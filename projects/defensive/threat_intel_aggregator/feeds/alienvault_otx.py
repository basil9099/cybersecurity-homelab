"""AlienVault OTX feed integration -- pulse subscriptions and IOC retrieval."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import requests

from models.indicator import Indicator, IndicatorType

from .base_feed import BaseFeed

logger = logging.getLogger(__name__)

# OTX indicator type -> our IndicatorType
_OTX_TYPE_MAP: dict[str, IndicatorType] = {
    "IPv4": IndicatorType.IP,
    "IPv6": IndicatorType.IP,
    "domain": IndicatorType.DOMAIN,
    "hostname": IndicatorType.DOMAIN,
    "URL": IndicatorType.URL,
    "FileHash-MD5": IndicatorType.HASH_MD5,
    "FileHash-SHA1": IndicatorType.HASH_SHA1,
    "FileHash-SHA256": IndicatorType.HASH_SHA256,
    "email": IndicatorType.EMAIL,
}


class AlienVaultOTXFeed(BaseFeed):
    """Integration with the AlienVault OTX DirectConnect v2 API.

    Supports:
      - ``fetch_indicators``: pull IOCs from subscribed pulses.
      - ``check_indicator``: query the OTX general endpoint for an IP / domain.
    """

    name = "alienvault_otx"
    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(
        self,
        api_key: str | None = None,
        *,
        demo_mode: bool = False,
    ) -> None:
        super().__init__(
            api_key=api_key,
            rate_limit=10,
            rate_period=60.0,
            cache_ttl=600,
            demo_mode=demo_mode,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_indicators(self, limit: int = 100) -> list[Indicator]:
        """Retrieve IOCs from the user's subscribed pulses."""
        if self.demo_mode:
            return self._demo_pulses(limit)

        cached = self._cache.get("pulses")
        if cached is not None:
            return cached[:limit]

        self._rate_limiter.acquire()
        start = time.monotonic()
        try:
            resp = requests.get(
                f"{self.BASE_URL}/pulses/subscribed",
                headers={"X-OTX-API-KEY": self.api_key or ""},
                params={"limit": 10, "modified_since": ""},
                timeout=20,
            )
            resp.raise_for_status()
            pulses = resp.json().get("results", [])
            indicators: list[Indicator] = []
            for pulse in pulses:
                indicators.extend(self._parse_pulse(pulse))
                if len(indicators) >= limit:
                    break
            elapsed = (time.monotonic() - start) * 1000
            self._record_fetch(len(indicators), elapsed)
            self._cache.put("pulses", indicators)
            return indicators[:limit]
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            self._record_fetch(0, elapsed, error=str(exc))
            logger.warning("OTX pulse fetch failed: %s", exc)
            return []

    def check_indicator(self, value: str) -> Indicator | None:
        """Look up a single IP or domain against OTX general reputation."""
        if self.demo_mode:
            return self._demo_check(value)

        ioc_type = IndicatorType.detect(value)
        if ioc_type == IndicatorType.IP:
            section = "IPv4"
        elif ioc_type == IndicatorType.DOMAIN:
            section = "domain"
        else:
            return None

        cache_key = f"check:{value}"
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        self._rate_limiter.acquire()
        start = time.monotonic()
        try:
            resp = requests.get(
                f"{self.BASE_URL}/indicators/{section}/{value}/general",
                headers={"X-OTX-API-KEY": self.api_key or ""},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            elapsed = (time.monotonic() - start) * 1000
            indicator = self._parse_general(value, ioc_type, data)
            self._record_fetch(1 if indicator else 0, elapsed)
            self._cache.put(cache_key, indicator)
            return indicator
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            self._record_fetch(0, elapsed, error=str(exc))
            logger.warning("OTX check failed for %s: %s", value, exc)
            return None

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_pulse(self, pulse: dict[str, Any]) -> list[Indicator]:
        """Extract indicators from a single OTX pulse."""
        pulse_name = pulse.get("name", "unknown_pulse")
        tags = pulse.get("tags", [])
        results: list[Indicator] = []
        for ioc in pulse.get("indicators", []):
            otx_type = ioc.get("type", "")
            our_type = _OTX_TYPE_MAP.get(otx_type, IndicatorType.UNKNOWN)
            if our_type == IndicatorType.UNKNOWN:
                continue
            created = ioc.get("created", "")
            try:
                first_seen = datetime.fromisoformat(created.replace("T", " ").rstrip("Z"))
                first_seen = first_seen.replace(tzinfo=timezone.utc)
            except (ValueError, AttributeError):
                first_seen = datetime.now(timezone.utc)
            results.append(
                Indicator(
                    value=ioc.get("indicator", ""),
                    ioc_type=our_type,
                    source=self.name,
                    first_seen=first_seen,
                    confidence=0.6,
                    tags=tags[:10],
                    raw_context={"pulse": pulse_name, "otx_type": otx_type},
                )
            )
        return results

    def _parse_general(
        self,
        value: str,
        ioc_type: IndicatorType,
        data: dict[str, Any],
    ) -> Indicator | None:
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        if pulse_count == 0:
            return None
        confidence = min(pulse_count / 10, 1.0)
        tags: list[str] = []
        for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]:
            tags.extend(pulse.get("tags", []))
        tags = list(dict.fromkeys(tags))[:15]  # deduplicate, cap
        return Indicator(
            value=value,
            ioc_type=ioc_type,
            source=self.name,
            confidence=round(confidence, 2),
            tags=tags,
            raw_context={"pulse_count": pulse_count},
        )

    # ------------------------------------------------------------------
    # Demo helpers
    # ------------------------------------------------------------------

    def _demo_pulses(self, limit: int) -> list[Indicator]:
        from demo.mock_feeds import MOCK_OTX_PULSES

        indicators: list[Indicator] = []
        for pulse in MOCK_OTX_PULSES:
            indicators.extend(self._parse_pulse(pulse))
        self._record_fetch(len(indicators), 85.0)
        return indicators[:limit]

    def _demo_check(self, value: str) -> Indicator | None:
        from demo.mock_feeds import MOCK_OTX_GENERAL

        data = MOCK_OTX_GENERAL.get(value)
        if data is None:
            self._record_fetch(0, 8.0)
            return None
        ioc_type = IndicatorType.detect(value)
        indicator = self._parse_general(value, ioc_type, data)
        self._record_fetch(1 if indicator else 0, 8.0)
        return indicator
