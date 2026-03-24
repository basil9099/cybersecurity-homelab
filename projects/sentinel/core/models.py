"""
SENTINEL core data models.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class NormalizedFinding:
    """A single security finding normalised from any source tool."""

    finding_id: str
    source_tool: str       # spectre | nimbus | osint | api_tester | anomaly | network_monitor
    source_file: str
    timestamp: str         # ISO-8601
    title: str
    description: str
    severity: str          # critical | high | medium | low | info
    raw_severity_score: float   # 0.0–10.0
    entities: dict = field(default_factory=lambda: {
        "ips": [], "cves": [], "domains": [], "ports": [], "hostnames": []
    })
    raw: dict = field(default_factory=dict)

    @staticmethod
    def make_id() -> str:
        return uuid.uuid4().hex

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Campaign:
    """A cluster of correlated findings mapped to a kill-chain phase."""

    campaign_id: int
    finding_ids: list[str]
    kill_chain_phase: str
    kill_chain_score: float     # cosine similarity confidence 0–1
    risk_score: float           # composite weighted score 0–10
    entities: dict = field(default_factory=lambda: {
        "ips": [], "cves": [], "domains": [], "ports": [], "hostnames": []
    })
    tools_involved: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackPath:
    """An inferred entity-level attack progression path."""

    path_id: str
    nodes: list[str]
    edges: list[tuple]
    severity: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["edges"] = [list(e) for e in self.edges]
        return d
