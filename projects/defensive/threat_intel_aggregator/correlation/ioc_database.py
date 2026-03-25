"""SQLite-backed IOC storage with deduplication, staleness tracking, and confidence scoring."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from models.indicator import Indicator, IndicatorType

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    uid          TEXT PRIMARY KEY,
    value        TEXT NOT NULL,
    ioc_type     TEXT NOT NULL,
    source       TEXT NOT NULL,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    confidence   REAL NOT NULL DEFAULT 0.5,
    tags         TEXT NOT NULL DEFAULT '[]',
    raw_context  TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_value ON indicators(value);
CREATE INDEX IF NOT EXISTS idx_ioc_type ON indicators(ioc_type);
CREATE INDEX IF NOT EXISTS idx_source ON indicators(source);
CREATE INDEX IF NOT EXISTS idx_confidence ON indicators(confidence);
CREATE INDEX IF NOT EXISTS idx_last_seen ON indicators(last_seen);
"""


class IOCDatabase:
    """Persistent IOC storage backed by SQLite.

    Features:
      - Upsert semantics: re-inserting an indicator updates ``last_seen``
        and keeps the higher confidence value.
      - Staleness queries: find indicators not refreshed in *N* days.
      - Full-text value search and type / source filtering.
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def upsert(self, indicator: Indicator) -> None:
        """Insert or update an indicator (deduplication by uid)."""
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """
            INSERT INTO indicators
                (uid, value, ioc_type, source, first_seen, last_seen,
                 confidence, tags, raw_context, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(uid) DO UPDATE SET
                last_seen  = excluded.last_seen,
                confidence = MAX(indicators.confidence, excluded.confidence),
                tags       = excluded.tags,
                raw_context = excluded.raw_context,
                updated_at = excluded.updated_at
            """,
            (
                indicator.uid,
                indicator.value,
                indicator.ioc_type.value,
                indicator.source,
                indicator.first_seen.isoformat(),
                indicator.last_seen.isoformat(),
                indicator.confidence,
                json.dumps(indicator.tags),
                json.dumps(indicator.raw_context),
                now,
                now,
            ),
        )
        self._conn.commit()

    def upsert_many(self, indicators: list[Indicator]) -> int:
        """Bulk upsert. Returns the number of rows affected."""
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                ind.uid,
                ind.value,
                ind.ioc_type.value,
                ind.source,
                ind.first_seen.isoformat(),
                ind.last_seen.isoformat(),
                ind.confidence,
                json.dumps(ind.tags),
                json.dumps(ind.raw_context),
                now,
                now,
            )
            for ind in indicators
        ]
        self._conn.executemany(
            """
            INSERT INTO indicators
                (uid, value, ioc_type, source, first_seen, last_seen,
                 confidence, tags, raw_context, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(uid) DO UPDATE SET
                last_seen  = excluded.last_seen,
                confidence = MAX(indicators.confidence, excluded.confidence),
                tags       = excluded.tags,
                raw_context = excluded.raw_context,
                updated_at = excluded.updated_at
            """,
            rows,
        )
        self._conn.commit()
        return len(rows)

    def lookup(self, value: str) -> list[Indicator]:
        """Find all indicator records matching *value* (exact match)."""
        cursor = self._conn.execute(
            "SELECT * FROM indicators WHERE value = ?", (value,)
        )
        return [self._row_to_indicator(row) for row in cursor.fetchall()]

    def search(
        self,
        *,
        ioc_type: IndicatorType | None = None,
        source: str | None = None,
        min_confidence: float = 0.0,
        limit: int = 100,
    ) -> list[Indicator]:
        """Search indicators with optional filters."""
        clauses: list[str] = ["1=1"]
        params: list[Any] = []

        if ioc_type is not None:
            clauses.append("ioc_type = ?")
            params.append(ioc_type.value)
        if source is not None:
            clauses.append("source = ?")
            params.append(source)
        if min_confidence > 0:
            clauses.append("confidence >= ?")
            params.append(min_confidence)

        where = " AND ".join(clauses)
        cursor = self._conn.execute(
            f"SELECT * FROM indicators WHERE {where} "
            f"ORDER BY confidence DESC LIMIT ?",
            params + [limit],
        )
        return [self._row_to_indicator(row) for row in cursor.fetchall()]

    def get_stale(self, max_age_days: int = 7, limit: int = 100) -> list[Indicator]:
        """Return indicators whose ``last_seen`` exceeds *max_age_days*."""
        from datetime import timedelta

        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        cursor = self._conn.execute(
            "SELECT * FROM indicators WHERE last_seen < ? ORDER BY last_seen ASC LIMIT ?",
            (cutoff, limit),
        )
        return [self._row_to_indicator(row) for row in cursor.fetchall()]

    def purge_stale(self, max_age_days: int = 30) -> int:
        """Delete indicators older than *max_age_days*. Returns count deleted."""
        from datetime import timedelta

        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        cursor = self._conn.execute(
            "DELETE FROM indicators WHERE last_seen < ?", (cutoff,)
        )
        self._conn.commit()
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Return aggregate statistics about the IOC database."""
        total = self._conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
        by_type = dict(
            self._conn.execute(
                "SELECT ioc_type, COUNT(*) FROM indicators GROUP BY ioc_type"
            ).fetchall()
        )
        by_source = dict(
            self._conn.execute(
                "SELECT source, COUNT(*) FROM indicators GROUP BY source"
            ).fetchall()
        )
        avg_conf = self._conn.execute(
            "SELECT AVG(confidence) FROM indicators"
        ).fetchone()[0]
        return {
            "total_indicators": total,
            "by_type": by_type,
            "by_source": by_source,
            "avg_confidence": round(avg_conf, 3) if avg_conf else 0.0,
        }

    def all_values(self) -> set[str]:
        """Return the set of all indicator values (for fast correlation lookups)."""
        cursor = self._conn.execute("SELECT DISTINCT value FROM indicators")
        return {row[0] for row in cursor.fetchall()}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_indicator(row: sqlite3.Row) -> Indicator:
        return Indicator(
            value=row["value"],
            ioc_type=IndicatorType(row["ioc_type"]),
            source=row["source"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            confidence=row["confidence"],
            tags=json.loads(row["tags"]),
            raw_context=json.loads(row["raw_context"]),
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> IOCDatabase:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        total = self._conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
        return f"<IOCDatabase path={self.db_path!r} indicators={total}>"
