"""SQLite database manager with schema creation and connection helpers."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Generator

SCHEMA_SQL = """
-- Threat events from GreyNoise / AbuseIPDB / OTX
CREATE TABLE IF NOT EXISTS threat_events (
    id          TEXT PRIMARY KEY,
    source      TEXT NOT NULL,
    ip          TEXT NOT NULL,
    country     TEXT,
    city        TEXT,
    latitude    REAL,
    longitude   REAL,
    asn         TEXT,
    asn_org     TEXT,
    category    TEXT,
    confidence  REAL DEFAULT 0.5,
    tags        TEXT DEFAULT '[]',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    raw_data    TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_te_country   ON threat_events(country);
CREATE INDEX IF NOT EXISTS idx_te_last_seen ON threat_events(last_seen);
CREATE INDEX IF NOT EXISTS idx_te_category  ON threat_events(category);
CREATE INDEX IF NOT EXISTS idx_te_ip        ON threat_events(ip);

-- CVE records from NVD
CREATE TABLE IF NOT EXISTS cves (
    cve_id          TEXT PRIMARY KEY,
    description     TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    cvss_severity   TEXT,
    epss_score      REAL,
    epss_percentile REAL,
    cwe_ids         TEXT DEFAULT '[]',
    affected_products TEXT DEFAULT '[]',
    published_date  TEXT NOT NULL,
    modified_date   TEXT,
    has_exploit     INTEGER DEFAULT 0,
    references_     TEXT DEFAULT '[]',
    fetched_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date);
CREATE INDEX IF NOT EXISTS idx_cves_cvss      ON cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_cves_epss      ON cves(epss_score);
CREATE INDEX IF NOT EXISTS idx_cves_severity  ON cves(cvss_severity);

-- Threat actors from MITRE ATT&CK
CREATE TABLE IF NOT EXISTS threat_actors (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    aliases          TEXT DEFAULT '[]',
    description      TEXT,
    country_origin   TEXT,
    first_seen       TEXT,
    last_seen        TEXT,
    target_sectors   TEXT DEFAULT '[]',
    target_countries TEXT DEFAULT '[]',
    sophistication   TEXT,
    campaign_count   INTEGER DEFAULT 0,
    technique_count  INTEGER DEFAULT 0,
    rank_score       REAL DEFAULT 0.0,
    updated_at       TEXT
);

-- Actor-to-technique mapping
CREATE TABLE IF NOT EXISTS actor_ttps (
    actor_id       TEXT NOT NULL,
    technique_id   TEXT NOT NULL,
    technique_name TEXT,
    tactic         TEXT,
    usage_count    INTEGER DEFAULT 1,
    PRIMARY KEY (actor_id, technique_id)
);

-- Exploit availability tracking
CREATE TABLE IF NOT EXISTS exploits (
    id             TEXT PRIMARY KEY,
    cve_id         TEXT,
    source         TEXT NOT NULL,
    title          TEXT,
    url            TEXT,
    author         TEXT,
    published_date TEXT,
    stars          INTEGER DEFAULT 0,
    verified       INTEGER DEFAULT 0,
    language       TEXT,
    stage          TEXT DEFAULT 'poc',
    fetched_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exploits_cve   ON exploits(cve_id);
CREATE INDEX IF NOT EXISTS idx_exploits_stage ON exploits(stage);

-- Social media / RSS intel
CREATE TABLE IF NOT EXISTS social_posts (
    id             TEXT PRIMARY KEY,
    source         TEXT NOT NULL,
    author         TEXT,
    title          TEXT,
    content        TEXT,
    url            TEXT,
    published_date TEXT,
    keywords       TEXT DEFAULT '[]',
    credibility    REAL DEFAULT 0.5,
    sentiment      TEXT,
    related_cves   TEXT DEFAULT '[]',
    fetched_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_social_published ON social_posts(published_date);

-- Collector health tracking
CREATE TABLE IF NOT EXISTS collector_health (
    collector_name  TEXT PRIMARY KEY,
    status          TEXT DEFAULT 'unknown',
    last_run        TEXT,
    last_success    TEXT,
    last_error      TEXT,
    items_collected INTEGER DEFAULT 0,
    avg_latency_ms  REAL DEFAULT 0.0,
    next_run        TEXT
);

-- Generated alerts
CREATE TABLE IF NOT EXISTS alerts (
    id             TEXT PRIMARY KEY,
    alert_type     TEXT NOT NULL,
    severity       TEXT NOT NULL,
    title          TEXT NOT NULL,
    description    TEXT,
    related_id     TEXT,
    created_at     TEXT NOT NULL,
    acknowledged   INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_created  ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
"""


class Database:
    """Thin wrapper around SQLite with schema bootstrapping."""

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self.db_path = str(db_path)
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        with self.conn() as c:
            c.executescript(SCHEMA_SQL)

    @contextmanager
    def conn(self) -> Generator[sqlite3.Connection, None, None]:
        connection = sqlite3.connect(self.db_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    # -- Generic helpers ---------------------------------------------------

    def upsert(self, table: str, data: dict[str, Any], conflict_col: str = "id") -> None:
        cols = list(data.keys())
        placeholders = ", ".join("?" for _ in cols)
        updates = ", ".join(f"{c} = excluded.{c}" for c in cols if c != conflict_col)
        sql = (
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders}) "
            f"ON CONFLICT({conflict_col}) DO UPDATE SET {updates}"
        )
        with self.conn() as c:
            c.execute(sql, [_serialize(data[col]) for col in cols])

    def upsert_many(self, table: str, rows: list[dict[str, Any]], conflict_col: str = "id") -> None:
        if not rows:
            return
        cols = list(rows[0].keys())
        placeholders = ", ".join("?" for _ in cols)
        updates = ", ".join(f"{c} = excluded.{c}" for c in cols if c != conflict_col)
        sql = (
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders}) "
            f"ON CONFLICT({conflict_col}) DO UPDATE SET {updates}"
        )
        with self.conn() as c:
            c.executemany(sql, [
                [_serialize(row[col]) for col in cols] for row in rows
            ])

    def query(
        self,
        sql: str,
        params: tuple = (),
    ) -> list[dict[str, Any]]:
        with self.conn() as c:
            rows = c.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def execute(self, sql: str, params: tuple = ()) -> None:
        with self.conn() as c:
            c.execute(sql, params)

    def count(self, table: str, where: str = "", params: tuple = ()) -> int:
        sql = f"SELECT COUNT(*) as cnt FROM {table}"
        if where:
            sql += f" WHERE {where}"
        rows = self.query(sql, params)
        return rows[0]["cnt"] if rows else 0


def _serialize(value: Any) -> Any:
    """Serialize lists/dicts to JSON strings for SQLite storage."""
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return value
