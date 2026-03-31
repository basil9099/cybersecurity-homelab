"""RSS/Atom security blog feed collector."""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone

from backend.collectors.base import BaseCollector

logger = logging.getLogger("mts.collectors.rss")

_SECURITY_KEYWORDS = [
    "cve", "vulnerability", "exploit", "zero-day", "0day", "ransomware",
    "malware", "apt", "breach", "rce", "injection", "backdoor", "phishing",
    "patch", "critical", "trojan", "botnet", "ddos", "threat",
]


class RSSFeedCollector(BaseCollector):
    name = "rss_feeds"

    async def fetch(self) -> int:
        if self.demo_mode:
            return self._fetch_demo()
        return await self._fetch_live()

    def _fetch_demo(self) -> int:
        from backend.demo.mock_social import generate_mock_social
        rows = [r for r in generate_mock_social() if r["source"] == "rss"]
        self.db.upsert_many("social_posts", rows, conflict_col="id")
        return len(rows)

    async def _fetch_live(self) -> int:
        import feedparser

        now = datetime.now(timezone.utc)
        count = 0

        for feed_url in self.settings.rss_feeds:
            try:
                feed = feedparser.parse(feed_url)
                feed_name = feed.feed.get("title", feed_url)

                for entry in feed.entries[:10]:
                    title = entry.get("title", "")
                    content = entry.get("summary", entry.get("description", ""))
                    link = entry.get("link", "")

                    pid = hashlib.sha256(f"rss:{link}".encode()).hexdigest()[:16]
                    keywords = _extract_keywords(f"{title} {content}")
                    cve_refs = re.findall(r"CVE-\d{4}-\d{4,}", f"{title} {content}", re.IGNORECASE)

                    pub = entry.get("published_parsed")
                    if pub:
                        pub_date = datetime(*pub[:6], tzinfo=timezone.utc).isoformat()
                    else:
                        pub_date = now.isoformat()

                    row = {
                        "id": pid,
                        "source": "rss",
                        "author": feed_name,
                        "title": title[:500],
                        "content": content[:2000],
                        "url": link,
                        "published_date": pub_date,
                        "keywords": keywords,
                        "credibility": 0.8,
                        "sentiment": _classify_sentiment(title + " " + content),
                        "related_cves": [c.upper() for c in cve_refs],
                        "fetched_at": now.isoformat(),
                    }
                    self.db.upsert("social_posts", row, conflict_col="id")
                    count += 1
            except Exception as e:
                logger.warning("Failed to parse feed %s: %s", feed_url, e)

        return count


def _extract_keywords(text: str) -> list[str]:
    text_lower = text.lower()
    return [kw for kw in _SECURITY_KEYWORDS if kw in text_lower]


def _classify_sentiment(text: str) -> str:
    text_lower = text.lower()
    alert_words = ["actively exploited", "critical", "zero-day", "emergency", "urgent", "breach"]
    if any(w in text_lower for w in alert_words):
        return "alert"
    analysis_words = ["analysis", "deep dive", "research", "investigation", "report"]
    if any(w in text_lower for w in analysis_words):
        return "analysis"
    return "neutral"
