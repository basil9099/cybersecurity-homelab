"""APScheduler integration -- registers collector jobs at configured intervals."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from apscheduler.schedulers.asyncio import AsyncIOScheduler

if TYPE_CHECKING:
    from backend.config import Settings
    from backend.database import Database

logger = logging.getLogger("mts.scheduler")


def setup_scheduler(
    settings: "Settings",
    db: "Database",
    ws_hub: object | None = None,
) -> AsyncIOScheduler | None:
    """Create an AsyncIOScheduler with all collector jobs registered."""
    scheduler = AsyncIOScheduler()

    if settings.demo_mode:
        intervals = {
            "cve": settings.demo_interval_cve,
            "threat_feeds": settings.demo_interval_threat_feeds,
            "exploits": settings.demo_interval_exploits,
            "social": settings.demo_interval_social,
            "mitre": settings.demo_interval_mitre,
        }
    else:
        intervals = {
            "cve": settings.interval_cve,
            "threat_feeds": settings.interval_threat_feeds,
            "exploits": settings.interval_exploits,
            "social": settings.interval_social,
            "mitre": settings.interval_mitre,
        }

    jobs_added = 0

    if intervals["cve"] > 0:
        scheduler.add_job(
            _run_cve_job, "interval", seconds=intervals["cve"],
            args=[settings, db, ws_hub], id="cve_collector",
            name="CVE Collector", misfire_grace_time=60,
        )
        jobs_added += 1

    if intervals["threat_feeds"] > 0:
        scheduler.add_job(
            _run_threat_feeds_job, "interval", seconds=intervals["threat_feeds"],
            args=[settings, db, ws_hub], id="threat_feeds_collector",
            name="Threat Feeds Collector", misfire_grace_time=60,
        )
        jobs_added += 1

    if intervals["exploits"] > 0:
        scheduler.add_job(
            _run_exploits_job, "interval", seconds=intervals["exploits"],
            args=[settings, db, ws_hub], id="exploits_collector",
            name="Exploits Collector", misfire_grace_time=60,
        )
        jobs_added += 1

    if intervals["social"] > 0:
        scheduler.add_job(
            _run_social_job, "interval", seconds=intervals["social"],
            args=[settings, db, ws_hub], id="social_collector",
            name="Social Collector", misfire_grace_time=60,
        )
        jobs_added += 1

    if intervals["mitre"] > 0:
        scheduler.add_job(
            _run_mitre_job, "interval", seconds=intervals["mitre"],
            args=[settings, db, ws_hub], id="mitre_collector",
            name="MITRE ATT&CK Collector", misfire_grace_time=120,
        )
        jobs_added += 1
    else:
        # Run once at startup
        scheduler.add_job(
            _run_mitre_job, "date", args=[settings, db, ws_hub],
            id="mitre_collector_startup", name="MITRE ATT&CK Startup",
        )
        jobs_added += 1

    if jobs_added == 0:
        return None
    return scheduler


async def _broadcast(ws_hub: object | None, channel: str, data: dict) -> None:
    if ws_hub is not None and hasattr(ws_hub, "broadcast"):
        try:
            await ws_hub.broadcast(channel, data)
        except Exception:
            logger.debug("WebSocket broadcast failed for %s", channel)


async def _run_cve_job(settings: "Settings", db: "Database", ws_hub: object | None) -> None:
    from backend.collectors.nvd import NVDCollector
    collector = NVDCollector(settings=settings, db=db)
    count = await collector.safe_fetch()
    if count > 0:
        await _broadcast(ws_hub, "cves", {"type": "update", "collector": "nvd", "count": count})


async def _run_threat_feeds_job(settings: "Settings", db: "Database", ws_hub: object | None) -> None:
    from backend.collectors.greynoise import GreyNoiseCollector
    from backend.collectors.abuseipdb import AbuseIPDBCollector
    from backend.collectors.otx import OTXCollector

    total = 0
    for cls in (GreyNoiseCollector, AbuseIPDBCollector, OTXCollector):
        collector = cls(settings=settings, db=db)
        total += await collector.safe_fetch()
    if total > 0:
        await _broadcast(ws_hub, "threat_map", {"type": "update", "count": total})


async def _run_exploits_job(settings: "Settings", db: "Database", ws_hub: object | None) -> None:
    from backend.collectors.github_exploits import GitHubExploitCollector
    from backend.collectors.exploitdb import ExploitDBCollector

    total = 0
    for cls in (GitHubExploitCollector, ExploitDBCollector):
        collector = cls(settings=settings, db=db)
        total += await collector.safe_fetch()
    if total > 0:
        await _broadcast(ws_hub, "exploits", {"type": "update", "count": total})


async def _run_social_job(settings: "Settings", db: "Database", ws_hub: object | None) -> None:
    from backend.collectors.rss_feeds import RSSFeedCollector
    from backend.collectors.mastodon import MastodonCollector

    total = 0
    for cls in (RSSFeedCollector, MastodonCollector):
        collector = cls(settings=settings, db=db)
        total += await collector.safe_fetch()
    if total > 0:
        await _broadcast(ws_hub, "social", {"type": "update", "count": total})


async def _run_mitre_job(settings: "Settings", db: "Database", ws_hub: object | None) -> None:
    from backend.collectors.mitre_attack import MITREAttackCollector
    collector = MITREAttackCollector(settings=settings, db=db)
    count = await collector.safe_fetch()
    if count > 0:
        await _broadcast(ws_hub, "actors", {"type": "update", "count": count})
