"""Base collector ABC with health tracking."""

from __future__ import annotations

import abc
import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from backend.config import Settings
    from backend.database import Database

logger = logging.getLogger("mts.collectors")


class BaseCollector(abc.ABC):
    """Abstract base for every data collector.

    Subclasses must set ``name`` and implement :meth:`fetch`.
    """

    name: str = "base"

    def __init__(self, settings: Settings, db: Database) -> None:
        self.settings = settings
        self.db = db
        self.demo_mode = settings.demo_mode

    @abc.abstractmethod
    async def fetch(self) -> int:
        """Fetch data, store in DB, return count of records collected."""
        ...

    async def safe_fetch(self) -> int:
        """Run fetch with error handling and health tracking."""
        start = time.monotonic()
        try:
            count = await self.fetch()
            elapsed = (time.monotonic() - start) * 1000
            self._record_success(count, elapsed)
            logger.info("%s: collected %d records in %.0fms", self.name, count, elapsed)
            return count
        except Exception as e:
            logger.error("%s: fetch failed: %s", self.name, e)
            self._record_error(str(e))
            return 0

    def _record_success(self, count: int, latency_ms: float = 0.0) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.db.upsert(
            "collector_health",
            {
                "collector_name": self.name,
                "status": "ok",
                "last_run": now,
                "last_success": now,
                "last_error": None,
                "items_collected": count,
                "avg_latency_ms": round(latency_ms, 1),
            },
            conflict_col="collector_name",
        )

    def _record_error(self, error_msg: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.db.upsert(
            "collector_health",
            {
                "collector_name": self.name,
                "status": "error",
                "last_run": now,
                "last_error": error_msg[:500],
            },
            conflict_col="collector_name",
        )


def get_all_collectors(settings: "Settings", db: "Database") -> list[BaseCollector]:
    """Instantiate all available collectors."""
    from backend.collectors.nvd import NVDCollector
    from backend.collectors.greynoise import GreyNoiseCollector
    from backend.collectors.abuseipdb import AbuseIPDBCollector
    from backend.collectors.otx import OTXCollector
    from backend.collectors.github_exploits import GitHubExploitCollector
    from backend.collectors.exploitdb import ExploitDBCollector
    from backend.collectors.rss_feeds import RSSFeedCollector
    from backend.collectors.mastodon import MastodonCollector
    from backend.collectors.mitre_attack import MITREAttackCollector

    return [
        NVDCollector(settings, db),
        GreyNoiseCollector(settings, db),
        AbuseIPDBCollector(settings, db),
        OTXCollector(settings, db),
        GitHubExploitCollector(settings, db),
        ExploitDBCollector(settings, db),
        RSSFeedCollector(settings, db),
        MastodonCollector(settings, db),
        MITREAttackCollector(settings, db),
    ]


async def run_all_collectors(settings: "Settings", db: "Database") -> None:
    """One-shot fetch from all sources."""
    collectors = get_all_collectors(settings, db)
    await asyncio.gather(*(c.safe_fetch() for c in collectors))
