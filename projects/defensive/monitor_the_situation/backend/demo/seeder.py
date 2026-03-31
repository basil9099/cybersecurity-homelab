"""Seeds the database with all mock data for demo mode."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from backend.database import Database

logger = logging.getLogger("mts.demo")


class DemoSeeder:
    def __init__(self, db: Database) -> None:
        self.db = db

    def seed_all(self) -> None:
        """Populate every table with realistic mock data."""
        self._seed_cves()
        self._seed_threats()
        self._seed_actors()
        self._seed_exploits()
        self._seed_social()
        self._seed_collector_health()
        self._seed_alerts()
        logger.info("Demo data seeded successfully")

    def _seed_cves(self) -> None:
        from backend.demo.mock_cves import generate_mock_cves
        rows = generate_mock_cves()
        self.db.upsert_many("cves", rows, conflict_col="cve_id")
        logger.info("Seeded %d CVEs", len(rows))

    def _seed_threats(self) -> None:
        from backend.demo.mock_threats import generate_mock_threats
        rows = generate_mock_threats()
        self.db.upsert_many("threat_events", rows, conflict_col="id")
        logger.info("Seeded %d threat events", len(rows))

    def _seed_actors(self) -> None:
        from backend.demo.mock_actors import generate_mock_actors, generate_mock_ttps
        actors = generate_mock_actors()
        ttps = generate_mock_ttps()
        self.db.upsert_many("threat_actors", actors, conflict_col="id")
        for ttp in ttps:
            self.db.execute(
                "INSERT OR REPLACE INTO actor_ttps "
                "(actor_id, technique_id, technique_name, tactic, usage_count) "
                "VALUES (?, ?, ?, ?, ?)",
                (ttp["actor_id"], ttp["technique_id"], ttp["technique_name"],
                 ttp["tactic"], ttp["usage_count"]),
            )
        logger.info("Seeded %d actors with %d TTPs", len(actors), len(ttps))

    def _seed_exploits(self) -> None:
        from backend.demo.mock_exploits import generate_mock_exploits
        rows = generate_mock_exploits()
        self.db.upsert_many("exploits", rows, conflict_col="id")
        logger.info("Seeded %d exploits", len(rows))

    def _seed_social(self) -> None:
        from backend.demo.mock_social import generate_mock_social
        rows = generate_mock_social()
        self.db.upsert_many("social_posts", rows, conflict_col="id")
        logger.info("Seeded %d social posts", len(rows))

    def _seed_collector_health(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        collectors = [
            "nvd", "greynoise", "abuseipdb", "otx",
            "github_exploits", "exploitdb", "rss_feeds", "mastodon", "mitre_attack",
        ]
        for name in collectors:
            self.db.upsert("collector_health", {
                "collector_name": name,
                "status": "ok",
                "last_run": now,
                "last_success": now,
                "last_error": None,
                "items_collected": 0,
                "avg_latency_ms": 0.0,
                "next_run": now,
            }, conflict_col="collector_name")
        logger.info("Seeded collector health for %d collectors", len(collectors))

    def _seed_alerts(self) -> None:
        from backend.demo.mock_cves import generate_mock_cves
        import hashlib

        now = datetime.now(timezone.utc)
        alerts = []
        cves = generate_mock_cves()
        critical = [c for c in cves if c["cvss_severity"] == "CRITICAL"]

        for i, cve in enumerate(critical[:3]):
            aid = hashlib.sha256(f"alert:cve:{cve['cve_id']}".encode()).hexdigest()[:16]
            alerts.append({
                "id": aid,
                "alert_type": "critical_cve",
                "severity": "critical",
                "title": f"Critical CVE: {cve['cve_id']} (CVSS {cve['cvss_score']})",
                "description": cve["description"][:200],
                "related_id": cve["cve_id"],
                "created_at": now.isoformat(),
                "acknowledged": 0,
            })

        aid2 = hashlib.sha256(b"alert:weaponization:demo").hexdigest()[:16]
        alerts.append({
            "id": aid2,
            "alert_type": "weaponization",
            "severity": "high",
            "title": "Exploit weaponized for critical vulnerability",
            "description": "A proof-of-concept exploit has been weaponized and integrated into attack frameworks.",
            "related_id": critical[0]["cve_id"] if critical else None,
            "created_at": now.isoformat(),
            "acknowledged": 0,
        })

        self.db.upsert_many("alerts", alerts, conflict_col="id")
        logger.info("Seeded %d alerts", len(alerts))
