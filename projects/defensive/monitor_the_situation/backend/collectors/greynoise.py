"""GreyNoise Community API collector."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

import aiohttp

from backend.collectors.base import BaseCollector

logger = logging.getLogger("mts.collectors.greynoise")

GREYNOISE_API = "https://api.greynoise.io/v3/community"


class GreyNoiseCollector(BaseCollector):
    name = "greynoise"

    async def fetch(self) -> int:
        if self.demo_mode:
            return self._fetch_demo()
        return await self._fetch_live()

    def _fetch_demo(self) -> int:
        from backend.demo.mock_threats import generate_mock_threats
        rows = [r for r in generate_mock_threats() if r["source"] == "greynoise"]
        self.db.upsert_many("threat_events", rows, conflict_col="id")
        return len(rows)

    async def _fetch_live(self) -> int:
        if not self.settings.greynoise_api_key:
            logger.warning("No GreyNoise API key configured")
            return 0

        headers = {"key": self.settings.greynoise_api_key}
        now = datetime.now(timezone.utc)
        count = 0

        # Query recent scanner IPs
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{GREYNOISE_API}/experimental/gnql",
                params={"query": "classification:malicious last_seen:1d", "size": 100},
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"GreyNoise API returned {resp.status}")
                data = await resp.json()

            for item in data.get("data", []):
                ip = item.get("ip", "")
                eid = hashlib.sha256(f"greynoise:{ip}".encode()).hexdigest()[:16]
                row = {
                    "id": eid,
                    "source": "greynoise",
                    "ip": ip,
                    "country": item.get("metadata", {}).get("country"),
                    "city": item.get("metadata", {}).get("city"),
                    "latitude": None,
                    "longitude": None,
                    "asn": item.get("metadata", {}).get("asn"),
                    "asn_org": item.get("metadata", {}).get("organization"),
                    "category": _classify(item),
                    "confidence": 0.8 if item.get("classification") == "malicious" else 0.5,
                    "tags": item.get("tags", []),
                    "first_seen": item.get("first_seen", now.isoformat()),
                    "last_seen": item.get("last_seen", now.isoformat()),
                    "raw_data": item,
                }
                self.db.upsert("threat_events", row, conflict_col="id")
                count += 1

        return count


def _classify(item: dict) -> str:
    tags = " ".join(item.get("tags", [])).lower()
    if "brute" in tags or "ssh" in tags:
        return "brute_force"
    if "exploit" in tags or "rce" in tags:
        return "exploitation"
    if "malware" in tags or "trojan" in tags:
        return "malware"
    if "botnet" in tags or "mirai" in tags:
        return "botnet"
    return "scanner"
