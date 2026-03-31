"""MITRE ATT&CK data collector (STIX from GitHub)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import aiohttp

from backend.collectors.base import BaseCollector

logger = logging.getLogger("mts.collectors.mitre")

MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


class MITREAttackCollector(BaseCollector):
    name = "mitre_attack"

    async def fetch(self) -> int:
        if self.demo_mode:
            return self._fetch_demo()
        return await self._fetch_live()

    def _fetch_demo(self) -> int:
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
        return len(actors)

    async def _fetch_live(self) -> int:
        now = datetime.now(timezone.utc)
        count = 0

        async with aiohttp.ClientSession() as session:
            async with session.get(
                MITRE_STIX_URL,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"MITRE STIX returned {resp.status}")
                data = await resp.json(content_type=None)

        objects = data.get("objects", [])

        # Build technique lookup
        techniques = {}
        for obj in objects:
            if obj.get("type") == "attack-pattern" and not obj.get("revoked"):
                refs = obj.get("external_references", [])
                for ref in refs:
                    if ref.get("source_name") == "mitre-attack":
                        tid = ref.get("external_id", "")
                        tactic = ""
                        phases = obj.get("kill_chain_phases", [])
                        if phases:
                            tactic = phases[0].get("phase_name", "")
                        techniques[obj["id"]] = {
                            "technique_id": tid,
                            "technique_name": obj.get("name", ""),
                            "tactic": tactic,
                        }

        # Extract groups
        for obj in objects:
            if obj.get("type") != "intrusion-set" or obj.get("revoked"):
                continue

            refs = obj.get("external_references", [])
            mitre_id = ""
            for ref in refs:
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id", "")

            if not mitre_id:
                continue

            actor_row = {
                "id": mitre_id,
                "name": obj.get("name", ""),
                "aliases": obj.get("aliases", []),
                "description": (obj.get("description", "") or "")[:1000],
                "country_origin": None,
                "first_seen": obj.get("first_seen"),
                "last_seen": obj.get("last_seen"),
                "target_sectors": [],
                "target_countries": [],
                "sophistication": obj.get("sophistication", "medium"),
                "campaign_count": 0,
                "technique_count": 0,
                "rank_score": 0.0,
                "updated_at": now.isoformat(),
            }
            self.db.upsert("threat_actors", actor_row, conflict_col="id")
            count += 1

        # Extract relationships (group -> technique)
        for obj in objects:
            if obj.get("type") != "relationship" or obj.get("revoked"):
                continue
            if obj.get("relationship_type") != "uses":
                continue

            source_ref = obj.get("source_ref", "")
            target_ref = obj.get("target_ref", "")

            if "intrusion-set" in source_ref and target_ref in techniques:
                tech = techniques[target_ref]
                # Find the MITRE group ID for this intrusion-set
                for o2 in objects:
                    if o2.get("id") == source_ref and o2.get("type") == "intrusion-set":
                        for ref in o2.get("external_references", []):
                            if ref.get("source_name") == "mitre-attack":
                                actor_id = ref.get("external_id", "")
                                self.db.execute(
                                    "INSERT OR REPLACE INTO actor_ttps "
                                    "(actor_id, technique_id, technique_name, tactic, usage_count) "
                                    "VALUES (?, ?, ?, ?, 1)",
                                    (actor_id, tech["technique_id"],
                                     tech["technique_name"], tech["tactic"]),
                                )
                        break

        return count
