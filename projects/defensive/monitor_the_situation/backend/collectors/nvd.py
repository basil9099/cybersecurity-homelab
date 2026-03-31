"""NVD API v2 collector for CVEs + EPSS scores."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import aiohttp

from backend.collectors.base import BaseCollector

logger = logging.getLogger("mts.collectors.nvd")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API = "https://api.first.org/data/v1/epss"


class NVDCollector(BaseCollector):
    name = "nvd"

    async def fetch(self) -> int:
        if self.demo_mode:
            return self._fetch_demo()
        return await self._fetch_live()

    def _fetch_demo(self) -> int:
        from backend.demo.mock_cves import generate_mock_cves
        rows = generate_mock_cves()
        self.db.upsert_many("cves", rows, conflict_col="cve_id")
        return len(rows)

    async def _fetch_live(self) -> int:
        now = datetime.now(timezone.utc)
        since = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S.000")
        until = now.strftime("%Y-%m-%dT%H:%M:%S.000")

        headers = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key

        params = {
            "pubStartDate": since,
            "pubEndDate": until,
            "resultsPerPage": 100,
        }

        count = 0
        async with aiohttp.ClientSession() as session:
            async with session.get(NVD_API, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"NVD API returned {resp.status}")
                data = await resp.json()

            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue

                metrics = cve.get("metrics", {})
                cvss31 = metrics.get("cvssMetricV31", [{}])
                cvss_data = cvss31[0].get("cvssData", {}) if cvss31 else {}

                desc_list = cve.get("descriptions", [])
                desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")

                row = {
                    "cve_id": cve_id,
                    "description": desc,
                    "cvss_score": cvss_data.get("baseScore"),
                    "cvss_vector": cvss_data.get("vectorString"),
                    "cvss_severity": cvss_data.get("baseSeverity"),
                    "epss_score": None,
                    "epss_percentile": None,
                    "cwe_ids": [w.get("value", "") for w in cve.get("weaknesses", [{}])[0].get("description", []) if w.get("value")],
                    "affected_products": [],
                    "published_date": cve.get("published", ""),
                    "modified_date": cve.get("lastModified", ""),
                    "has_exploit": 0,
                    "references_": [r.get("url", "") for r in cve.get("references", [])],
                    "fetched_at": now.isoformat(),
                }
                self.db.upsert("cves", row, conflict_col="cve_id")
                count += 1

        # Fetch EPSS scores for new CVEs
        if count > 0:
            await self._fetch_epss(session=None)

        return count

    async def _fetch_epss(self, session=None) -> None:
        """Update EPSS scores for CVEs missing them."""
        missing = self.db.query(
            "SELECT cve_id FROM cves WHERE epss_score IS NULL LIMIT 100"
        )
        if not missing:
            return

        cve_ids = [r["cve_id"] for r in missing]
        params = {"cve": ",".join(cve_ids)}

        try:
            async with aiohttp.ClientSession() as sess:
                async with sess.get(EPSS_API, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("data", []):
                            self.db.execute(
                                "UPDATE cves SET epss_score = ?, epss_percentile = ? WHERE cve_id = ?",
                                (float(item.get("epss", 0)), float(item.get("percentile", 0)), item.get("cve")),
                            )
        except Exception as e:
            logger.warning("EPSS fetch failed: %s", e)
