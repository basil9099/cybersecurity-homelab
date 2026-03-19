#!/usr/bin/env python3
"""
baseline/storage.py
===================
SQLite-backed time-series storage for traffic windows, baseline profiles,
and alert logs.

Schema
------
traffic_stats  — one row per aggregated window (JSON blob for dict fields)
baselines      — per (hour_of_day, day_of_week, metric_name) statistics
alerts_log     — all alerts fired (including suppressed ones)
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generator

from collector.aggregator import TrafficWindow


DEFAULT_DB = "network_baseline.db"

# ── DDL ──────────────────────────────────────────────────────────────────────

_CREATE_TRAFFIC_STATS = """
CREATE TABLE IF NOT EXISTS traffic_stats (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       REAL    NOT NULL,
    window_seconds  INTEGER NOT NULL DEFAULT 60,
    total_bytes     INTEGER NOT NULL DEFAULT 0,
    total_packets   INTEGER NOT NULL DEFAULT 0,
    unique_src_ips  INTEGER NOT NULL DEFAULT 0,
    unique_dst_ips  INTEGER NOT NULL DEFAULT 0,
    external_bytes_out INTEGER NOT NULL DEFAULT 0,
    bytes_per_protocol TEXT,   -- JSON
    pkts_per_protocol  TEXT,   -- JSON
    top_talkers        TEXT,   -- JSON
    port_counts        TEXT,   -- JSON
    src_port_spread    TEXT,   -- JSON
    external_dst_bytes TEXT,   -- JSON
    internal_pairs     TEXT    -- JSON
);
"""

_CREATE_BASELINES = """
CREATE TABLE IF NOT EXISTS baselines (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    hour_of_day  INTEGER NOT NULL,
    day_of_week  INTEGER NOT NULL,
    metric_name  TEXT    NOT NULL,
    mean         REAL    NOT NULL,
    std          REAL    NOT NULL DEFAULT 0,
    p25          REAL    NOT NULL DEFAULT 0,
    p75          REAL    NOT NULL DEFAULT 0,
    sample_count INTEGER NOT NULL DEFAULT 0,
    UNIQUE(hour_of_day, day_of_week, metric_name)
);
"""

_CREATE_ALERTS_LOG = """
CREATE TABLE IF NOT EXISTS alerts_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     REAL    NOT NULL,
    anomaly_type  TEXT    NOT NULL,
    score         REAL    NOT NULL,
    level         TEXT    NOT NULL DEFAULT 'low',
    detail        TEXT,   -- JSON
    suppressed    INTEGER NOT NULL DEFAULT 0
);
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_ts ON traffic_stats(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_bl ON baselines(hour_of_day, day_of_week);",
    "CREATE INDEX IF NOT EXISTS idx_al ON alerts_log(timestamp);",
]


# ── Dataclass for baseline rows ───────────────────────────────────────────────

@dataclass
class BaselineRow:
    hour_of_day: int
    day_of_week: int
    metric_name: str
    mean: float
    std: float
    p25: float
    p75: float
    sample_count: int


# ── Storage class ─────────────────────────────────────────────────────────────

class BaselineStorage:
    """Thread-safe(ish) SQLite wrapper for all persistence operations."""

    def __init__(self, db_path: str | Path = DEFAULT_DB):
        self.db_path = str(db_path)
        self._init_db()

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute(_CREATE_TRAFFIC_STATS)
            conn.execute(_CREATE_BASELINES)
            conn.execute(_CREATE_ALERTS_LOG)
            for idx in _CREATE_INDEXES:
                conn.execute(idx)

    # ── Traffic windows ───────────────────────────────────────────────────────

    def insert_window(self, window: TrafficWindow) -> int:
        """Insert a TrafficWindow and return its row id."""
        sql = """
        INSERT INTO traffic_stats (
            timestamp, window_seconds, total_bytes, total_packets,
            unique_src_ips, unique_dst_ips, external_bytes_out,
            bytes_per_protocol, pkts_per_protocol, top_talkers,
            port_counts, src_port_spread, external_dst_bytes, internal_pairs
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self._conn() as conn:
            cur = conn.execute(sql, (
                window.timestamp,
                window.window_seconds,
                window.total_bytes,
                window.total_packets,
                window.unique_src_ips,
                window.unique_dst_ips,
                window.external_bytes_out,
                json.dumps(window.bytes_per_protocol),
                json.dumps(window.pkts_per_protocol),
                json.dumps(window.top_talkers),
                json.dumps(window.port_counts),
                json.dumps(window.src_port_spread),
                json.dumps(window.external_dst_bytes),
                json.dumps(window.internal_pairs),
            ))
            return cur.lastrowid

    def query_windows(
        self,
        start: float | None = None,
        end: float | None = None,
        limit: int = 0,
    ) -> list[TrafficWindow]:
        """
        Query stored traffic windows by time range.

        Args:
            start: Unix timestamp lower bound (inclusive).
            end:   Unix timestamp upper bound (inclusive).
            limit: Max rows to return (0 = all).

        Returns:
            List of TrafficWindow objects sorted by timestamp ascending.
        """
        clauses: list[str] = []
        params: list[Any] = []
        if start is not None:
            clauses.append("timestamp >= ?")
            params.append(start)
        if end is not None:
            clauses.append("timestamp <= ?")
            params.append(end)

        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        lim = f"LIMIT {limit}" if limit > 0 else ""
        sql = f"SELECT * FROM traffic_stats {where} ORDER BY timestamp ASC {lim}"

        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [self._row_to_window(r) for r in rows]

    def count_windows(self) -> int:
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM traffic_stats").fetchone()[0]

    @staticmethod
    def _row_to_window(row: sqlite3.Row) -> TrafficWindow:
        w = TrafficWindow()
        w.timestamp = row["timestamp"]
        w.window_seconds = row["window_seconds"]
        w.total_bytes = row["total_bytes"]
        w.total_packets = row["total_packets"]
        w.unique_src_ips = row["unique_src_ips"]
        w.unique_dst_ips = row["unique_dst_ips"]
        w.external_bytes_out = row["external_bytes_out"]
        w.bytes_per_protocol = json.loads(row["bytes_per_protocol"] or "{}")
        w.pkts_per_protocol = json.loads(row["pkts_per_protocol"] or "{}")
        w.top_talkers = json.loads(row["top_talkers"] or "{}")
        w.port_counts = json.loads(row["port_counts"] or "{}")
        w.src_port_spread = json.loads(row["src_port_spread"] or "{}")
        w.external_dst_bytes = json.loads(row["external_dst_bytes"] or "{}")
        w.internal_pairs = json.loads(row["internal_pairs"] or "{}")
        return w

    # ── Baselines ─────────────────────────────────────────────────────────────

    def upsert_baseline(self, row: BaselineRow) -> None:
        """Insert or update a baseline row."""
        sql = """
        INSERT INTO baselines
            (hour_of_day, day_of_week, metric_name, mean, std, p25, p75, sample_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hour_of_day, day_of_week, metric_name)
        DO UPDATE SET
            mean=excluded.mean, std=excluded.std,
            p25=excluded.p25,   p75=excluded.p75,
            sample_count=excluded.sample_count
        """
        with self._conn() as conn:
            conn.execute(sql, (
                row.hour_of_day, row.day_of_week, row.metric_name,
                row.mean, row.std, row.p25, row.p75, row.sample_count,
            ))

    def get_baseline(
        self,
        hour_of_day: int,
        day_of_week: int,
    ) -> dict[str, BaselineRow]:
        """
        Retrieve all metric baselines for a given (hour, day) slot.

        Returns:
            Dict mapping metric_name -> BaselineRow.
            Empty dict if no baseline has been established yet.
        """
        sql = """
        SELECT * FROM baselines
        WHERE hour_of_day = ? AND day_of_week = ?
        """
        with self._conn() as conn:
            rows = conn.execute(sql, (hour_of_day, day_of_week)).fetchall()

        return {
            r["metric_name"]: BaselineRow(
                hour_of_day=r["hour_of_day"],
                day_of_week=r["day_of_week"],
                metric_name=r["metric_name"],
                mean=r["mean"],
                std=r["std"],
                p25=r["p25"],
                p75=r["p75"],
                sample_count=r["sample_count"],
            )
            for r in rows
        }

    def has_baseline(self) -> bool:
        """Return True if at least one baseline row exists."""
        with self._conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM baselines").fetchone()[0]
        return count > 0

    def baseline_coverage(self) -> dict[str, int]:
        """Return sample counts by metric for reporting purposes."""
        sql = "SELECT metric_name, SUM(sample_count) as total FROM baselines GROUP BY metric_name"
        with self._conn() as conn:
            rows = conn.execute(sql).fetchall()
        return {r["metric_name"]: r["total"] for r in rows}

    # ── Alerts ────────────────────────────────────────────────────────────────

    def insert_alert(
        self,
        anomaly_type: str,
        score: float,
        level: str,
        detail: dict[str, Any],
        suppressed: bool = False,
        timestamp: float | None = None,
    ) -> int:
        """Log an alert and return its row id."""
        sql = """
        INSERT INTO alerts_log (timestamp, anomaly_type, score, level, detail, suppressed)
        VALUES (?, ?, ?, ?, ?, ?)
        """
        ts = timestamp or time.time()
        with self._conn() as conn:
            cur = conn.execute(sql, (
                ts, anomaly_type, score, level,
                json.dumps(detail), int(suppressed),
            ))
            return cur.lastrowid

    def query_alerts(
        self,
        start: float | None = None,
        end: float | None = None,
        include_suppressed: bool = False,
        limit: int = 0,
    ) -> list[dict[str, Any]]:
        """Query alerts log, optionally filtering by time and suppression."""
        clauses: list[str] = []
        params: list[Any] = []
        if start is not None:
            clauses.append("timestamp >= ?")
            params.append(start)
        if end is not None:
            clauses.append("timestamp <= ?")
            params.append(end)
        if not include_suppressed:
            clauses.append("suppressed = 0")

        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        lim = f"LIMIT {limit}" if limit > 0 else ""
        sql = f"SELECT * FROM alerts_log {where} ORDER BY timestamp DESC {lim}"

        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [
            {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "anomaly_type": r["anomaly_type"],
                "score": r["score"],
                "level": r["level"],
                "detail": json.loads(r["detail"] or "{}"),
                "suppressed": bool(r["suppressed"]),
            }
            for r in rows
        ]

    def recent_alert_exists(
        self,
        anomaly_type: str,
        src_ip: str,
        within_seconds: int = 900,
    ) -> bool:
        """Check if a matching alert was already fired recently (for suppression)."""
        cutoff = time.time() - within_seconds
        sql = """
        SELECT COUNT(*) FROM alerts_log
        WHERE anomaly_type = ?
          AND suppressed = 0
          AND timestamp >= ?
          AND json_extract(detail, '$.src_ip') = ?
        """
        with self._conn() as conn:
            count = conn.execute(sql, (anomaly_type, cutoff, src_ip)).fetchone()[0]
        return count > 0
