#!/usr/bin/env python3
"""
ingestion/network.py
====================
Ingest alerts from the Network Baseline Monitor and normalize them into
the unified alert schema.

Reads from the network baseline monitor's SQLite alerts_log table and
converts each row into a NormalizedAlert with ATT&CK mappings applied.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from ingestion.schema import AlertSource, NormalizedAlert, Severity
from mappings.mitre_attack import map_alert


def ingest_from_db(
    db_path: str | Path,
    since_timestamp: float = 0.0,
    include_suppressed: bool = False,
) -> list[NormalizedAlert]:
    """
    Read alerts from the network baseline monitor's SQLite database.

    Args:
        db_path:            Path to network_baseline.db.
        since_timestamp:    Only return alerts after this Unix timestamp.
        include_suppressed: Whether to include suppressed alerts.

    Returns:
        List of NormalizedAlert objects with ATT&CK mappings applied.
    """
    db_path = Path(db_path)
    if not db_path.exists():
        return []

    conn = sqlite3.connect(str(db_path), timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        clauses = ["timestamp > ?"]
        params: list[Any] = [since_timestamp]
        if not include_suppressed:
            clauses.append("suppressed = 0")

        where = "WHERE " + " AND ".join(clauses)
        rows = conn.execute(
            f"SELECT * FROM alerts_log {where} ORDER BY timestamp ASC",
            params,
        ).fetchall()
    finally:
        conn.close()

    return [_row_to_alert(r) for r in rows]


def _row_to_alert(row: sqlite3.Row) -> NormalizedAlert:
    """Convert a network baseline monitor alert row to NormalizedAlert."""
    detail = json.loads(row["detail"] or "{}")
    anomaly_type = row["anomaly_type"]

    mapping = map_alert("network_baseline", anomaly_type)

    severity_map = {"low": Severity.LOW, "medium": Severity.MEDIUM, "high": Severity.HIGH}
    severity = severity_map.get(row["level"], Severity.LOW)

    src_entity = detail.get("src_ip", "unknown")
    dst_entity = detail.get("dst_ip", "")

    return NormalizedAlert(
        timestamp=row["timestamp"],
        source=AlertSource.NETWORK_BASELINE,
        anomaly_type=anomaly_type,
        severity=severity,
        score=row["score"],
        src_entity=src_entity,
        dst_entity=dst_entity,
        technique_ids=list(mapping.technique_ids),
        tactic=mapping.tactic,
        raw_detail=detail,
    )
