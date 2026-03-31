"""AbuseIPDB blacklist collector."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

import aiohttp

from backend.collectors.base import BaseCollector

logger = logging.getLogger("mts.collectors.abuseipdb")

ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/blacklist"


class AbuseIPDBCollector(BaseCollector):
    name = "abuseipdb"

    async def fetch(self) -> int:
        if self.demo_mode:
            return self._fetch_demo()
        return await self._fetch_live()

    def _fetch_demo(self) -> int:
        from backend.demo.mock_threats import generate_mock_threats
        rows = [r for r in generate_mock_threats() if r["source"] == "abuseipdb"]
        self.db.upsert_many("threat_events", rows, conflict_col="id")
        return len(rows)

    async def _fetch_live(self) -> int:
        if not self.settings.abuseipdb_api_key:
            logger.warning("No AbuseIPDB API key configured")
            return 0

        headers = {"Key": self.settings.abuseipdb_api_key, "Accept": "application/json"}
        params = {"confidenceMinimum": 75, "limit": 100}
        now = datetime.now(timezone.utc)
        count = 0

        async with aiohttp.ClientSession() as session:
            async with session.get(
                ABUSEIPDB_API, headers=headers, params=params,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"AbuseIPDB returned {resp.status}")
                data = await resp.json()

            for item in data.get("data", []):
                ip = item.get("ipAddress", "")
                eid = hashlib.sha256(f"abuseipdb:{ip}".encode()).hexdigest()[:16]
                confidence = (item.get("abuseConfidenceScore", 50)) / 100.0

                row = {
                    "id": eid,
                    "source": "abuseipdb",
                    "ip": ip,
                    "country": item.get("countryCode"),
                    "city": None,
                    "latitude": None,
                    "longitude": None,
                    "asn": None,
                    "asn_org": item.get("isp"),
                    "category": "scanner",
                    "confidence": confidence,
                    "tags": [],
                    "first_seen": now.isoformat(),
                    "last_seen": item.get("lastReportedAt", now.isoformat()),
                    "raw_data": item,
                }
                self.db.upsert("threat_events", row, conflict_col="id")
                count += 1

        return count
