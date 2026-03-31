"""Models for threat actor leaderboard."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TTP(BaseModel):
    technique_id: str  # e.g. T1566.001
    technique_name: str | None = None
    tactic: str | None = None  # e.g. initial-access
    usage_count: int = 1


class Campaign(BaseModel):
    name: str
    date: str | None = None
    target_sectors: list[str] = Field(default_factory=list)
    description: str | None = None


class ThreatActor(BaseModel):
    id: str  # MITRE ID e.g. G0007
    name: str
    aliases: list[str] = Field(default_factory=list)
    description: str | None = None
    country_origin: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    target_sectors: list[str] = Field(default_factory=list)
    target_countries: list[str] = Field(default_factory=list)
    sophistication: str | None = None  # low, medium, high, advanced
    campaign_count: int = 0
    technique_count: int = 0
    rank_score: float = 0.0
    updated_at: str | None = None

    def to_db(self) -> dict:
        return self.model_dump()


class ActorLeaderboardEntry(BaseModel):
    rank: int
    actor: ThreatActor
    ttps: list[TTP] = Field(default_factory=list)
