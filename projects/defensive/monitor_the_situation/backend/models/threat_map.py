"""Models for the global threat map."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ThreatEvent(BaseModel):
    id: str
    source: str  # greynoise, abuseipdb, otx
    ip: str
    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: str | None = None
    asn_org: str | None = None
    category: str | None = None  # scanner, brute_force, malware, exploitation
    confidence: float = 0.5
    tags: list[str] = Field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    raw_data: dict = Field(default_factory=dict)

    def to_db(self) -> dict:
        return self.model_dump()


class GeoPoint(BaseModel):
    latitude: float
    longitude: float
    country: str
    city: str | None = None
    asn: str | None = None
    asn_org: str | None = None


class CountryAggregation(BaseModel):
    country: str
    count: int
    categories: dict[str, int] = Field(default_factory=dict)


class ThreatMapStats(BaseModel):
    total_events: int = 0
    unique_ips: int = 0
    top_countries: list[CountryAggregation] = Field(default_factory=list)
    top_categories: dict[str, int] = Field(default_factory=dict)
    events_last_24h: int = 0
