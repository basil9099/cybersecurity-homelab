"""Emerging Threats open ruleset -- IP blocklist parsing."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import requests

from models.indicator import Indicator, IndicatorType

from .base_feed import BaseFeed

logger = logging.getLogger(__name__)


class EmergingThreatsFeed(BaseFeed):
    """Integration with the Emerging Threats (Proofpoint) open IP blocklist.

    The compromised IP list is a plain-text file with one IP per line.

    Supports:
      - ``fetch_indicators``: download and parse the compromised-IPs blocklist.
      - ``check_indicator``: test whether an IP appears in the cached blocklist.
    """

    name = "emerging_threats"
    COMPROMISED_IPS_URL = (
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
    )

    def __init__(
        self,
        api_key: str | None = None,
        *,
        demo_mode: bool = False,
    ) -> None:
        super().__init__(
            api_key=api_key,
            rate_limit=5,
            rate_period=300.0,  # very conservative -- file rarely changes
            cache_ttl=1800,
            demo_mode=demo_mode,
        )
        self._blocklist_set: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_indicators(self, limit: int = 100) -> list[Indicator]:
        """Download and parse the ET compromised-IPs list."""
        if self.demo_mode:
            return self._demo_blocklist(limit)

        cached = self._cache.get("blocklist")
        if cached is not None:
            return cached[:limit]

        self._rate_limiter.acquire()
        start = time.monotonic()
        try:
            resp = requests.get(self.COMPROMISED_IPS_URL, timeout=30)
            resp.raise_for_status()
            indicators = self._parse_blocklist(resp.text)
            elapsed = (time.monotonic() - start) * 1000
            self._record_fetch(len(indicators), elapsed)
            self._cache.put("blocklist", indicators)
            self._blocklist_set = {ind.value for ind in indicators}
            return indicators[:limit]
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            self._record_fetch(0, elapsed, error=str(exc))
            logger.warning("ET blocklist fetch failed: %s", exc)
            return []

    def check_indicator(self, value: str) -> Indicator | None:
        """Check whether *value* (an IP) appears in the ET compromised list."""
        if self.demo_mode:
            return self._demo_check(value)

        # Ensure blocklist is loaded
        if not self._blocklist_set:
            self.fetch_indicators(limit=50_000)

        if value not in self._blocklist_set:
            return None

        return Indicator(
            value=value,
            ioc_type=IndicatorType.IP,
            source=self.name,
            confidence=0.65,
            tags=["compromised", "blocklist"],
            raw_context={"list": "compromised-ips"},
        )

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_blocklist(self, text: str) -> list[Indicator]:
        """Parse the plain-text IP list (one IP per line, # comments)."""
        indicators: list[Indicator] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Validate it looks like an IP
            if IndicatorType.detect(line) != IndicatorType.IP:
                continue
            indicators.append(
                Indicator(
                    value=line,
                    ioc_type=IndicatorType.IP,
                    source=self.name,
                    confidence=0.65,
                    tags=["compromised", "blocklist"],
                    raw_context={"list": "compromised-ips"},
                )
            )
        return indicators

    # ------------------------------------------------------------------
    # Demo helpers
    # ------------------------------------------------------------------

    def _demo_blocklist(self, limit: int) -> list[Indicator]:
        from demo.mock_feeds import MOCK_ET_BLOCKLIST_IPS

        indicators = self._parse_blocklist("\n".join(MOCK_ET_BLOCKLIST_IPS))
        self._blocklist_set = {ind.value for ind in indicators}
        self._record_fetch(len(indicators), 120.0)
        return indicators[:limit]

    def _demo_check(self, value: str) -> Indicator | None:
        if not self._blocklist_set:
            self._demo_blocklist(50_000)
        if value not in self._blocklist_set:
            return None
        return Indicator(
            value=value,
            ioc_type=IndicatorType.IP,
            source=self.name,
            confidence=0.65,
            tags=["compromised", "blocklist"],
            raw_context={"list": "compromised-ips"},
        )
