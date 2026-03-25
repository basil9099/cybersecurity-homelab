"""Feed manager -- orchestrates all feeds with parallel fetching, caching, and rate limiting."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from models.indicator import Indicator

from .abuseipdb import AbuseIPDBFeed
from .alienvault_otx import AlienVaultOTXFeed
from .base_feed import BaseFeed, FeedHealth
from .emerging_threats import EmergingThreatsFeed
from .urlhaus import URLhausFeed

logger = logging.getLogger(__name__)


class FeedManager:
    """Orchestrates multiple threat intelligence feeds.

    Handles parallel fetching, de-duplication of indicators across feeds,
    and aggregation of feed health status.
    """

    def __init__(
        self,
        api_keys: dict[str, str] | None = None,
        *,
        demo_mode: bool = False,
        max_workers: int = 4,
    ) -> None:
        keys = api_keys or {}
        self.demo_mode = demo_mode
        self.max_workers = max_workers

        self.feeds: list[BaseFeed] = [
            AbuseIPDBFeed(
                api_key=keys.get("abuseipdb"),
                demo_mode=demo_mode,
            ),
            AlienVaultOTXFeed(
                api_key=keys.get("alienvault_otx"),
                demo_mode=demo_mode,
            ),
            URLhausFeed(
                api_key=keys.get("urlhaus"),
                demo_mode=demo_mode,
            ),
            EmergingThreatsFeed(
                api_key=keys.get("emerging_threats"),
                demo_mode=demo_mode,
            ),
        ]

    # ------------------------------------------------------------------
    # Bulk fetch
    # ------------------------------------------------------------------

    def fetch_all(self, limit_per_feed: int = 100) -> list[Indicator]:
        """Fetch indicators from all feeds in parallel.

        Returns:
            A deduplicated, sorted list of :class:`Indicator` instances.
        """
        all_indicators: list[Indicator] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(feed.fetch_indicators, limit_per_feed): feed
                for feed in self.feeds
            }
            for future in as_completed(futures):
                feed = futures[future]
                try:
                    result = future.result()
                    logger.info(
                        "Feed %s returned %d indicators", feed.name, len(result)
                    )
                    all_indicators.extend(result)
                except Exception as exc:
                    logger.error("Feed %s raised: %s", feed.name, exc)

        return self._deduplicate(all_indicators)

    # ------------------------------------------------------------------
    # Single-value check across all feeds
    # ------------------------------------------------------------------

    def check_all(self, value: str) -> list[Indicator]:
        """Check a single IOC value against every feed.

        Returns:
            All non-None Indicator results.
        """
        results: list[Indicator] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(feed.check_indicator, value): feed
                for feed in self.feeds
            }
            for future in as_completed(futures):
                feed = futures[future]
                try:
                    indicator = future.result()
                    if indicator is not None:
                        results.append(indicator)
                except Exception as exc:
                    logger.error(
                        "Feed %s check failed for %s: %s", feed.name, value, exc
                    )

        return results

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health_report(self) -> list[FeedHealth]:
        """Return health status for every registered feed."""
        return [feed.health for feed in self.feeds]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate(indicators: list[Indicator]) -> list[Indicator]:
        """Remove duplicate indicators, keeping the one with highest confidence."""
        best: dict[str, Indicator] = {}
        for ind in indicators:
            key = f"{ind.value}|{ind.ioc_type.value}"
            existing = best.get(key)
            if existing is None or ind.confidence > existing.confidence:
                best[key] = ind
        # Sort by confidence descending
        return sorted(best.values(), key=lambda i: i.confidence, reverse=True)

    def get_feed(self, name: str) -> BaseFeed | None:
        """Look up a feed by name."""
        for feed in self.feeds:
            if feed.name == name:
                return feed
        return None

    def __repr__(self) -> str:
        mode = "demo" if self.demo_mode else "live"
        return f"<FeedManager feeds={len(self.feeds)} mode={mode}>"
