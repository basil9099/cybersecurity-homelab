"""Alert generation for critical events."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from backend.database import Database


def check_and_generate_alerts(db: Database) -> list[dict]:
    """Check for alert-worthy conditions and create alerts."""
    alerts = []
    now = datetime.now(timezone.utc).isoformat()

    # 1. New critical CVEs (CVSS >= 9.0) not yet alerted
    critical_cves = db.query(
        """
        SELECT c.cve_id, c.cvss_score, c.description
        FROM cves c
        WHERE c.cvss_score >= 9.0
        AND NOT EXISTS (
            SELECT 1 FROM alerts a
            WHERE a.related_id = c.cve_id AND a.alert_type = 'critical_cve'
        )
        ORDER BY c.cvss_score DESC
        LIMIT 5
        """
    )
    for cve in critical_cves:
        aid = hashlib.sha256(f"alert:cve:{cve['cve_id']}".encode()).hexdigest()[:16]
        alert = {
            "id": aid,
            "alert_type": "critical_cve",
            "severity": "critical",
            "title": f"Critical CVE: {cve['cve_id']} (CVSS {cve['cvss_score']})",
            "description": (cve["description"] or "")[:200],
            "related_id": cve["cve_id"],
            "created_at": now,
            "acknowledged": 0,
        }
        alerts.append(alert)

    # 2. Newly weaponized exploits for high-severity CVEs
    weaponized = db.query(
        """
        SELECT e.id as exploit_id, e.cve_id, e.title, c.cvss_score
        FROM exploits e
        JOIN cves c ON e.cve_id = c.cve_id
        WHERE e.stage IN ('weaponized', 'in_framework')
        AND c.cvss_score >= 7.0
        AND NOT EXISTS (
            SELECT 1 FROM alerts a
            WHERE a.related_id = e.id AND a.alert_type = 'weaponization'
        )
        ORDER BY c.cvss_score DESC
        LIMIT 5
        """
    )
    for exp in weaponized:
        aid = hashlib.sha256(f"alert:weapon:{exp['exploit_id']}".encode()).hexdigest()[:16]
        alert = {
            "id": aid,
            "alert_type": "weaponization",
            "severity": "high",
            "title": f"Exploit weaponized: {exp['cve_id']} (CVSS {exp['cvss_score']})",
            "description": exp["title"] or "",
            "related_id": exp["exploit_id"],
            "created_at": now,
            "acknowledged": 0,
        }
        alerts.append(alert)

    # 3. High EPSS score CVEs
    high_epss = db.query(
        """
        SELECT c.cve_id, c.epss_score, c.cvss_score, c.description
        FROM cves c
        WHERE c.epss_score >= 0.7
        AND NOT EXISTS (
            SELECT 1 FROM alerts a
            WHERE a.related_id = c.cve_id AND a.alert_type = 'high_epss'
        )
        ORDER BY c.epss_score DESC
        LIMIT 3
        """
    )
    for cve in high_epss:
        aid = hashlib.sha256(f"alert:epss:{cve['cve_id']}".encode()).hexdigest()[:16]
        alert = {
            "id": aid,
            "alert_type": "high_epss",
            "severity": "high",
            "title": f"High exploitation probability: {cve['cve_id']} (EPSS {cve['epss_score']:.1%})",
            "description": (cve["description"] or "")[:200],
            "related_id": cve["cve_id"],
            "created_at": now,
            "acknowledged": 0,
        }
        alerts.append(alert)

    # Store new alerts
    if alerts:
        db.upsert_many("alerts", alerts, conflict_col="id")

    return alerts
