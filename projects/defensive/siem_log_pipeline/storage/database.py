"""
storage.database — SQLite-backed event store.

Provides indexed storage and retrieval for normalized security events
with helper queries for dashboards, search, and reporting.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from ingestion.normalizer import NormalizedEvent


class EventDatabase:
    """Thin wrapper around an SQLite database for NormalizedEvent storage."""

    def __init__(self, db_path: str | Path = "sentinel.db") -> None:
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_table()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _create_table(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id        TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source    TEXT NOT NULL,
                severity  TEXT NOT NULL,
                category  TEXT NOT NULL,
                message   TEXT NOT NULL,
                raw_data  TEXT NOT NULL
            )
            """
        )
        # Indexes for common query patterns.
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_source ON events (source)"
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def insert_event(self, event: NormalizedEvent) -> None:
        """Insert a single normalized event into the database."""
        self._conn.execute(
            """
            INSERT OR IGNORE INTO events
                (id, timestamp, source, severity, category, message, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.id,
                event.timestamp,
                event.source,
                event.severity,
                event.category,
                event.message,
                json.dumps(event.raw_data),
            ),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Read — general
    # ------------------------------------------------------------------

    def get_events(
        self,
        *,
        source: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[NormalizedEvent]:
        """Retrieve events with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []

        if source:
            clauses.append("source = ?")
            params.append(source)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_event(r) for r in rows]

    def get_recent_events(self, limit: int = 20) -> list[NormalizedEvent]:
        """Return the most recent events."""
        rows = self._conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def get_event_count(self) -> int:
        """Total number of stored events."""
        row = self._conn.execute("SELECT COUNT(*) AS cnt FROM events").fetchone()
        return row["cnt"]

    # ------------------------------------------------------------------
    # Read — aggregations
    # ------------------------------------------------------------------

    def get_event_counts_by_source(self) -> dict[str, int]:
        """Return ``{source: count}`` mapping."""
        rows = self._conn.execute(
            "SELECT source, COUNT(*) AS cnt FROM events GROUP BY source ORDER BY cnt DESC"
        ).fetchall()
        return {r["source"]: r["cnt"] for r in rows}

    def get_severity_distribution(self) -> dict[str, int]:
        """Return ``{severity: count}`` mapping."""
        rows = self._conn.execute(
            "SELECT severity, COUNT(*) AS cnt FROM events GROUP BY severity ORDER BY cnt DESC"
        ).fetchall()
        return {r["severity"]: r["cnt"] for r in rows}

    def get_timeline(self, hours: int = 24) -> list[dict[str, Any]]:
        """Return event counts grouped by hour for the last *hours* hours.

        Each element: ``{"hour": "YYYY-MM-DD HH", "count": int}``
        """
        rows = self._conn.execute(
            """
            SELECT
                SUBSTR(timestamp, 1, 13) AS hour,
                COUNT(*) AS cnt
            FROM events
            WHERE timestamp >= datetime('now', ?)
            GROUP BY hour
            ORDER BY hour
            """,
            (f"-{hours} hours",),
        ).fetchall()
        return [{"hour": r["hour"], "count": r["cnt"]} for r in rows]

    # ------------------------------------------------------------------
    # Search support
    # ------------------------------------------------------------------

    def search(
        self,
        *,
        severity_list: list[str] | None = None,
        source: str | None = None,
        keyword: str | None = None,
        since: str | None = None,
        limit: int = 50,
    ) -> list[NormalizedEvent]:
        """Flexible search across stored events."""
        clauses: list[str] = []
        params: list[Any] = []

        if severity_list:
            placeholders = ", ".join("?" for _ in severity_list)
            clauses.append(f"severity IN ({placeholders})")
            params.extend(severity_list)
        if source:
            clauses.append("source = ?")
            params.append(source)
        if keyword:
            clauses.append("message LIKE ?")
            params.append(f"%{keyword}%")
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_event(r) for r in rows]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> NormalizedEvent:
        return NormalizedEvent(
            id=row["id"],
            timestamp=row["timestamp"],
            source=row["source"],
            severity=row["severity"],
            category=row["category"],
            message=row["message"],
            raw_data=json.loads(row["raw_data"]),
        )

    def close(self) -> None:
        self._conn.close()
