"""CVE publication velocity analytics."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.database import Database


def compute_velocity(db: Database, days: int = 30) -> list[dict[str, Any]]:
    """Compute daily CVE publication counts."""
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = db.query(
        """
        SELECT DATE(published_date) as date,
               COUNT(*) as count,
               SUM(CASE WHEN cvss_severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
               SUM(CASE WHEN cvss_severity = 'HIGH' THEN 1 ELSE 0 END) as high_count
        FROM cves
        WHERE published_date >= ?
        GROUP BY DATE(published_date)
        ORDER BY date
        """,
        (since,),
    )
    return rows


def get_critical_cves(db: Database, min_cvss: float = 9.0, limit: int = 20) -> list[dict]:
    """Get recent critical CVEs."""
    return db.query(
        """
        SELECT * FROM cves
        WHERE cvss_score >= ?
        ORDER BY published_date DESC
        LIMIT ?
        """,
        (min_cvss, limit),
    )


def get_cve_stats(db: Database) -> dict[str, Any]:
    """Compute overall CVE statistics."""
    total = db.count("cves")
    critical = db.count("cves", "cvss_severity = 'CRITICAL'")
    high = db.count("cves", "cvss_severity = 'HIGH'")
    with_exploit = db.count("cves", "has_exploit = 1")

    avg_row = db.query("SELECT AVG(cvss_score) as avg_cvss, AVG(epss_score) as avg_epss FROM cves")
    avg_cvss = round(avg_row[0]["avg_cvss"] or 0, 2)
    avg_epss = round(avg_row[0]["avg_epss"] or 0, 4)

    velocity_7d = compute_velocity(db, 7)
    velocity_30d = compute_velocity(db, 30)

    return {
        "total_cves": total,
        "critical_count": critical,
        "high_count": high,
        "with_exploit": with_exploit,
        "avg_cvss": avg_cvss,
        "avg_epss": avg_epss,
        "velocity_7d": velocity_7d,
        "velocity_30d": velocity_30d,
    }
