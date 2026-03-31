"""Models for CVE tracking and velocity analytics."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CVERecord(BaseModel):
    cve_id: str
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_severity: str | None = None  # CRITICAL, HIGH, MEDIUM, LOW
    epss_score: float | None = None  # 0.0-1.0
    epss_percentile: float | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    affected_products: list[str] = Field(default_factory=list)
    published_date: str = ""
    modified_date: str | None = None
    has_exploit: bool = False
    references_: list[str] = Field(default_factory=list, alias="references")
    fetched_at: str = ""

    model_config = {"populate_by_name": True}

    def to_db(self) -> dict:
        d = self.model_dump(by_alias=False)
        d["has_exploit"] = int(d["has_exploit"])
        return d


class EPSSScore(BaseModel):
    cve_id: str
    epss: float
    percentile: float


class CVEVelocityPoint(BaseModel):
    date: str  # ISO date
    count: int
    critical_count: int = 0
    high_count: int = 0


class CVEStats(BaseModel):
    total_cves: int = 0
    critical_count: int = 0
    high_count: int = 0
    with_exploit: int = 0
    avg_cvss: float = 0.0
    avg_epss: float = 0.0
    velocity_7d: list[CVEVelocityPoint] = Field(default_factory=list)
    velocity_30d: list[CVEVelocityPoint] = Field(default_factory=list)
