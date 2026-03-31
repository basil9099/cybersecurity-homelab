"""AlienVault OTX pulse collector."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

import aiohttp

from backend.collectors.base import BaseCollector

logger = logging.getLogger("mts.collectors.otx")

OTX_API = "https://otx.alienvault.com/api/v1"


class OTXCollector(BaseCollector):
    name = "otx"

    async def fetch(self) -> int:
        if self.demo_mode:
            return self._fetch_demo()
        return await self._fetch_live()

    def _fetch_demo(self) -> int:
        from backend.demo.mock_threats import generate_mock_threats
        rows = [r for r in generate_mock_threats() if r["source"] == "otx"]
        self.db.upsert_many("threat_events", rows, conflict_col="id")
        return len(rows)

    async def _fetch_live(self) -> int:
        if not self.settings.otx_api_key:
            logger.warning("No OTX API key configured")
            return 0

        headers = {"X-OTX-API-KEY": self.settings.otx_api_key}
        now = datetime.now(timezone.utc)
        count = 0

        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{OTX_API}/pulses/subscribed",
                headers=headers,
                params={"limit": 20, "modified_since": (now.replace(hour=0, minute=0, second=0)).isoformat()},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"OTX API returned {resp.status}")
                data = await resp.json()

            for pulse in data.get("results", []):
                for indicator in pulse.get("indicators", []):
                    if indicator.get("type") not in ("IPv4", "IPv6"):
                        continue
                    ip = indicator.get("indicator", "")
                    eid = hashlib.sha256(f"otx:{ip}:{pulse.get('id', '')}".encode()).hexdigest()[:16]
                    row = {
                        "id": eid,
                        "source": "otx",
                        "ip": ip,
                        "country": None,
                        "city": None,
                        "latitude": None,
                        "longitude": None,
                        "asn": None,
                        "asn_org": None,
                        "category": "malware",
                        "confidence": 0.7,
                        "tags": pulse.get("tags", [])[:5],
                        "first_seen": indicator.get("created", now.isoformat()),
                        "last_seen": now.isoformat(),
                        "raw_data": {"pulse_id": pulse.get("id"), "pulse_name": pulse.get("name")},
                    }
                    self.db.upsert("threat_events", row, conflict_col="id")
                    count += 1

        return count
