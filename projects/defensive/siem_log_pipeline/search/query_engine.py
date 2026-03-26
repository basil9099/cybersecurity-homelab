"""
search.query_engine — Flexible event query engine.

Supports filtering by minimum severity threshold, source name, keyword,
time range (e.g. ``"1h"``, ``"24h"``, ``"7d"``), and result limit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from ingestion.normalizer import NormalizedEvent
from storage.database import EventDatabase

# Severity hierarchy — lower index = more severe.
SEVERITY_LEVELS: list[str] = ["critical", "high", "medium", "low", "info"]


@dataclass
class SearchQuery:
    """Describes a search against the event store."""

    severity: str | None = None
    source: str | None = None
    keyword: str | None = None
    time_range: str | None = None
    limit: int = 50


class QueryEngine:
    """Execute *SearchQuery* instances against the event database."""

    def __init__(self, db: EventDatabase) -> None:
        self._db = db

    def search(self, query: SearchQuery) -> list[NormalizedEvent]:
        """Run *query* and return matching events."""
        severity_list: list[str] | None = None
        if query.severity:
            severity_list = self._severity_at_or_above(query.severity)

        since: str | None = None
        if query.time_range:
            delta = self._parse_time_range(query.time_range)
            if delta is not None:
                since = (datetime.now(timezone.utc) - delta).isoformat()

        return self._db.search(
            severity_list=severity_list,
            source=query.source,
            keyword=query.keyword,
            since=since,
            limit=query.limit,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_at_or_above(minimum: str) -> list[str]:
        """Return all severity levels at or above *minimum*."""
        minimum = minimum.lower()
        if minimum not in SEVERITY_LEVELS:
            return SEVERITY_LEVELS
        idx = SEVERITY_LEVELS.index(minimum)
        return SEVERITY_LEVELS[: idx + 1]

    @staticmethod
    def _parse_time_range(spec: str) -> timedelta | None:
        """Parse shorthand like ``'1h'``, ``'24h'``, ``'7d'`` into a timedelta."""
        match = re.fullmatch(r"(\d+)\s*([hHdDmM])", spec.strip())
        if not match:
            return None
        value = int(match.group(1))
        unit = match.group(2).lower()
        if unit == "h":
            return timedelta(hours=value)
        if unit == "d":
            return timedelta(days=value)
        if unit == "m":
            return timedelta(minutes=value)
        return None
