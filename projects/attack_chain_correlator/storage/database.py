#!/usr/bin/env python3
"""
storage/database.py
===================
SQLite persistence for attack chains, normalized alerts, and scoring history.

Schema follows patterns established in the network baseline monitor's
storage.py, adapted for attack chain correlation data.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator


DEFAULT_DB = "attack_chains.db"

# ── DDL ──────────────────────────────────────────────────────────────────────

_CREATE_ALERTS = """
CREATE TABLE IF NOT EXISTS normalized_alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id        TEXT    UNIQUE NOT NULL,
    timestamp       REAL    NOT NULL,
    source          TEXT    NOT NULL,
    anomaly_type    TEXT    NOT NULL,
    severity        TEXT    NOT NULL DEFAULT 'low',
    score           REAL    NOT NULL DEFAULT 0.0,
    src_entity      TEXT    NOT NULL DEFAULT '',
    dst_entity      TEXT    NOT NULL DEFAULT '',
    technique_ids   TEXT,   -- JSON array
    tactic          TEXT    NOT NULL DEFAULT '',
    raw_detail      TEXT    -- JSON
);
"""

_CREATE_CHAINS = """
CREATE TABLE IF NOT EXISTS attack_chains (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id        TEXT    UNIQUE NOT NULL,
    entity_id       TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'active',
    created_at      REAL    NOT NULL,
    updated_at      REAL    NOT NULL,
    composite_score REAL    NOT NULL DEFAULT 0.0,
    posterior       REAL    NOT NULL DEFAULT 0.0,
    escalation      TEXT    NOT NULL DEFAULT 'none',
    stages_observed INTEGER NOT NULL DEFAULT 0,
    tactics         TEXT,   -- JSON array of tactic objects
    summary         TEXT    NOT NULL DEFAULT '',
    alert_count     INTEGER NOT NULL DEFAULT 0
);
"""

_CREATE_SCORE_HISTORY = """
CREATE TABLE IF NOT EXISTS score_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id        TEXT    NOT NULL,
    timestamp       REAL    NOT NULL,
    composite_score REAL    NOT NULL,
    posterior       REAL    NOT NULL,
    stages_observed INTEGER NOT NULL DEFAULT 0,
    escalation      TEXT    NOT NULL DEFAULT 'none'
);
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_alerts_ts ON normalized_alerts(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_entity ON normalized_alerts(src_entity);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_tactic ON normalized_alerts(tactic);",
    "CREATE INDEX IF NOT EXISTS idx_chains_entity ON attack_chains(entity_id);",
    "CREATE INDEX IF NOT EXISTS idx_chains_status ON attack_chains(status);",
    "CREATE INDEX IF NOT EXISTS idx_score_chain ON score_history(chain_id, timestamp);",
]


class ChainStorage:
    """SQLite persistence for the attack chain correlator."""

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
            conn.execute(_CREATE_ALERTS)
            conn.execute(_CREATE_CHAINS)
            conn.execute(_CREATE_SCORE_HISTORY)
            for idx in _CREATE_INDEXES:
                conn.execute(idx)

    # ── Alerts ────────────────────────────────────────────────────────────────

    def insert_alert(self, alert_dict: dict[str, Any]) -> int:
        """Insert a normalized alert. Returns row id."""
        sql = """
        INSERT OR IGNORE INTO normalized_alerts
            (alert_id, timestamp, source, anomaly_type, severity, score,
             src_entity, dst_entity, technique_ids, tactic, raw_detail)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self._conn() as conn:
            cur = conn.execute(sql, (
                alert_dict["alert_id"],
                alert_dict["timestamp"],
                alert_dict["source"],
                alert_dict["anomaly_type"],
                alert_dict["severity"],
                alert_dict["score"],
                alert_dict["src_entity"],
                alert_dict["dst_entity"],
                json.dumps(alert_dict.get("technique_ids", [])),
                alert_dict["tactic"],
                json.dumps(alert_dict.get("raw_detail", {})),
            ))
            return cur.lastrowid or 0

    def query_alerts(
        self,
        entity: str | None = None,
        tactic: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query normalized alerts with optional filters."""
        clauses: list[str] = []
        params: list[Any] = []
        if entity:
            clauses.append("src_entity = ?")
            params.append(entity)
        if tactic:
            clauses.append("tactic = ?")
            params.append(tactic)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)

        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        sql = f"SELECT * FROM normalized_alerts {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [
            {
                "alert_id": r["alert_id"],
                "timestamp": r["timestamp"],
                "source": r["source"],
                "anomaly_type": r["anomaly_type"],
                "severity": r["severity"],
                "score": r["score"],
                "src_entity": r["src_entity"],
                "dst_entity": r["dst_entity"],
                "technique_ids": json.loads(r["technique_ids"] or "[]"),
                "tactic": r["tactic"],
                "raw_detail": json.loads(r["raw_detail"] or "{}"),
            }
            for r in rows
        ]

    # ── Chains ────────────────────────────────────────────────────────────────

    def upsert_chain(self, chain_dict: dict[str, Any]) -> None:
        """Insert or update an attack chain."""
        sql = """
        INSERT INTO attack_chains
            (chain_id, entity_id, status, created_at, updated_at,
             composite_score, posterior, escalation, stages_observed,
             tactics, summary, alert_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(chain_id) DO UPDATE SET
            status=excluded.status,
            updated_at=excluded.updated_at,
            composite_score=excluded.composite_score,
            posterior=excluded.posterior,
            escalation=excluded.escalation,
            stages_observed=excluded.stages_observed,
            tactics=excluded.tactics,
            summary=excluded.summary,
            alert_count=excluded.alert_count
        """
        score = chain_dict.get("score", {})
        with self._conn() as conn:
            conn.execute(sql, (
                chain_dict["chain_id"],
                chain_dict["entity_id"],
                chain_dict["status"],
                chain_dict["created_at"],
                chain_dict["updated_at"],
                score.get("composite", 0.0),
                score.get("posterior", 0.0),
                score.get("escalation_level", "none"),
                len(chain_dict.get("tactics", [])),
                json.dumps(chain_dict.get("tactics", [])),
                chain_dict.get("summary", ""),
                chain_dict.get("alert_count", 0),
            ))

    def query_chains(
        self,
        status: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Query stored chains."""
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status)

        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        sql = f"SELECT * FROM attack_chains {where} ORDER BY composite_score DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [
            {
                "chain_id": r["chain_id"],
                "entity_id": r["entity_id"],
                "status": r["status"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "composite_score": r["composite_score"],
                "posterior": r["posterior"],
                "escalation": r["escalation"],
                "stages_observed": r["stages_observed"],
                "tactics": json.loads(r["tactics"] or "[]"),
                "summary": r["summary"],
                "alert_count": r["alert_count"],
            }
            for r in rows
        ]

    # ── Score history ─────────────────────────────────────────────────────────

    def record_score(self, chain_id: str, score_dict: dict[str, Any]) -> None:
        """Record a scoring snapshot for trend analysis."""
        sql = """
        INSERT INTO score_history
            (chain_id, timestamp, composite_score, posterior, stages_observed, escalation)
        VALUES (?, ?, ?, ?, ?, ?)
        """
        with self._conn() as conn:
            conn.execute(sql, (
                chain_id,
                time.time(),
                score_dict.get("composite", 0.0),
                score_dict.get("posterior", 0.0),
                score_dict.get("stages_observed", 0),
                score_dict.get("escalation_level", "none"),
            ))

    def get_score_trend(self, chain_id: str, limit: int = 50) -> list[dict[str, Any]]:
        """Get score history for a chain."""
        sql = """
        SELECT * FROM score_history
        WHERE chain_id = ?
        ORDER BY timestamp DESC LIMIT ?
        """
        with self._conn() as conn:
            rows = conn.execute(sql, (chain_id, limit)).fetchall()
        return [
            {
                "timestamp": r["timestamp"],
                "composite_score": r["composite_score"],
                "posterior": r["posterior"],
                "stages_observed": r["stages_observed"],
                "escalation": r["escalation"],
            }
            for r in rows
        ]

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, Any]:
        """Return database-level statistics."""
        with self._conn() as conn:
            alert_count = conn.execute("SELECT COUNT(*) FROM normalized_alerts").fetchone()[0]
            chain_count = conn.execute("SELECT COUNT(*) FROM attack_chains").fetchone()[0]
            active = conn.execute("SELECT COUNT(*) FROM attack_chains WHERE status='active'").fetchone()[0]
            escalated = conn.execute("SELECT COUNT(*) FROM attack_chains WHERE status='escalated'").fetchone()[0]
        return {
            "total_alerts": alert_count,
            "total_chains": chain_count,
            "active_chains": active,
            "escalated_chains": escalated,
        }
