"""Models for social media threat intelligence."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SocialPost(BaseModel):
    id: str
    source: str  # rss, mastodon
    author: str | None = None
    title: str | None = None
    content: str | None = None
    url: str | None = None
    published_date: str | None = None
    keywords: list[str] = Field(default_factory=list)
    credibility: float = 0.5
    sentiment: str | None = None  # alert, neutral, analysis
    related_cves: list[str] = Field(default_factory=list)
    fetched_at: str = ""

    def to_db(self) -> dict:
        return self.model_dump()


class SourceCredibility(BaseModel):
    source_name: str
    credibility_score: float
    post_count: int = 0
    accuracy_rate: float | None = None


class TrendingTopic(BaseModel):
    keyword: str
    count: int
    recent_posts: list[str] = Field(default_factory=list)  # post IDs


class Alert(BaseModel):
    id: str
    alert_type: str  # critical_cve, weaponization, new_apt_campaign
    severity: str  # critical, high, medium, low
    title: str
    description: str | None = None
    related_id: str | None = None
    created_at: str = ""
    acknowledged: bool = False

    def to_db(self) -> dict:
        d = self.model_dump()
        d["acknowledged"] = int(d["acknowledged"])
        return d


class CollectorHealth(BaseModel):
    collector_name: str
    status: str = "unknown"  # ok, error, degraded, unknown
    last_run: str | None = None
    last_success: str | None = None
    last_error: str | None = None
    items_collected: int = 0
    avg_latency_ms: float = 0.0
    next_run: str | None = None
