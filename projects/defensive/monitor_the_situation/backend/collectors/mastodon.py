"""Mastodon public timeline collector for infosec content."""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone

import aiohttp

from backend.collectors.base import BaseCollector

logger = logging.getLogger("mts.collectors.mastodon")

_FILTER_KEYWORDS = [
    "cve", "vulnerability", "exploit", "zero-day", "0day", "ransomware",
    "malware", "apt", "breach", "rce", "infosec", "cybersecurity",
    "threat", "backdoor", "phishing", "incident",
]


class MastodonCollector(BaseCollector):
    name = "mastodon"

    async def fetch(self) -> int:
        if self.demo_mode:
            return self._fetch_demo()
        return await self._fetch_live()

    def _fetch_demo(self) -> int:
        from backend.demo.mock_social import generate_mock_social
        rows = [r for r in generate_mock_social() if r["source"] == "mastodon"]
        self.db.upsert_many("social_posts", rows, conflict_col="id")
        return len(rows)

    async def _fetch_live(self) -> int:
        instance = self.settings.mastodon_instance.rstrip("/")
        now = datetime.now(timezone.utc)
        count = 0

        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{instance}/api/v1/timelines/public",
                params={"limit": 40, "local": "false"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Mastodon API returned {resp.status}")
                toots = await resp.json()

        for toot in toots:
            content = _strip_html(toot.get("content", ""))
            if not _is_security_relevant(content):
                continue

            toot_id = toot.get("id", "")
            pid = hashlib.sha256(f"mastodon:{toot_id}".encode()).hexdigest()[:16]
            account = toot.get("account", {})
            author = f"@{account.get('username', 'unknown')}@{instance.split('//')[1]}"

            cve_refs = re.findall(r"CVE-\d{4}-\d{4,}", content, re.IGNORECASE)

            row = {
                "id": pid,
                "source": "mastodon",
                "author": author,
                "title": content[:100],
                "content": content[:2000],
                "url": toot.get("url", ""),
                "published_date": toot.get("created_at", now.isoformat()),
                "keywords": _extract_keywords(content),
                "credibility": 0.6,
                "sentiment": "neutral",
                "related_cves": [c.upper() for c in cve_refs],
                "fetched_at": now.isoformat(),
            }
            self.db.upsert("social_posts", row, conflict_col="id")
            count += 1

        return count


def _strip_html(html: str) -> str:
    return re.sub(r"<[^>]+>", " ", html).strip()


def _is_security_relevant(text: str) -> bool:
    text_lower = text.lower()
    return any(kw in text_lower for kw in _FILTER_KEYWORDS)


def _extract_keywords(text: str) -> list[str]:
    text_lower = text.lower()
    return [kw for kw in _FILTER_KEYWORDS if kw in text_lower]
