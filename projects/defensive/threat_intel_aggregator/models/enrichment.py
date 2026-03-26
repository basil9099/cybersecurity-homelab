"""Enrichment result dataclass pairing log events with matched threat intel."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .indicator import Indicator


class RecommendedAction(str, Enum):
    """Suggested response actions for enriched alerts."""

    BLOCK = "block"
    INVESTIGATE = "investigate"
    MONITOR = "monitor"
    IGNORE = "ignore"
    ESCALATE = "escalate"

    @classmethod
    def from_threat_score(cls, score: float) -> RecommendedAction:
        """Derive a recommended action from a numeric threat score (0-100)."""
        if score >= 80:
            return cls.BLOCK
        if score >= 60:
            return cls.ESCALATE
        if score >= 40:
            return cls.INVESTIGATE
        if score >= 20:
            return cls.MONITOR
        return cls.IGNORE


@dataclass
class EnrichmentResult:
    """The product of correlating a local log event against threat intelligence.

    Attributes:
        original_event: The raw log entry that triggered the correlation.
        matched_indicators: IOCs from threat feeds that match artifacts in the event.
        threat_score: Aggregate risk score (0-100) computed from matched indicators.
        recommended_actions: Derived response actions.
        timestamp: When the enrichment was performed.
        metadata: Extra contextual data (log source path, correlation rule, etc.).
    """

    original_event: dict[str, Any]
    matched_indicators: list[Indicator] = field(default_factory=list)
    threat_score: float = 0.0
    recommended_actions: list[RecommendedAction] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.threat_score == 0.0 and self.matched_indicators:
            self.threat_score = self._compute_threat_score()
        if not self.recommended_actions and self.threat_score > 0:
            self.recommended_actions = [
                RecommendedAction.from_threat_score(self.threat_score)
            ]

    def _compute_threat_score(self) -> float:
        """Compute an aggregate threat score from matched indicators.

        Uses a weighted combination: max confidence contributes 60 %,
        number of distinct sources contributes 25 %, number of matches 15 %.
        """
        if not self.matched_indicators:
            return 0.0

        max_confidence = max(ind.confidence for ind in self.matched_indicators)
        unique_sources = len({ind.source for ind in self.matched_indicators})
        match_count = len(self.matched_indicators)

        source_factor = min(unique_sources / 4, 1.0)
        count_factor = min(match_count / 5, 1.0)

        score = (max_confidence * 60) + (source_factor * 25) + (count_factor * 15)
        return min(round(score, 1), 100.0)

    @property
    def severity_label(self) -> str:
        """Human-readable severity derived from threat score."""
        if self.threat_score >= 80:
            return "critical"
        if self.threat_score >= 60:
            return "high"
        if self.threat_score >= 40:
            return "medium"
        if self.threat_score >= 20:
            return "low"
        return "informational"

    @property
    def is_actionable(self) -> bool:
        """Whether this result warrants immediate attention."""
        return self.threat_score >= 40

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "original_event": self.original_event,
            "matched_indicators": [ind.to_dict() for ind in self.matched_indicators],
            "threat_score": self.threat_score,
            "severity": self.severity_label,
            "recommended_actions": [a.value for a in self.recommended_actions],
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }

    def summary(self) -> str:
        """One-line human-readable summary of the enrichment result."""
        indicator_types = {ind.ioc_type.value for ind in self.matched_indicators}
        return (
            f"[{self.severity_label.upper()}] score={self.threat_score:.0f} "
            f"matches={len(self.matched_indicators)} "
            f"types={','.join(sorted(indicator_types))} "
            f"actions={','.join(a.value for a in self.recommended_actions)}"
        )

    def __repr__(self) -> str:
        return (
            f"EnrichmentResult(score={self.threat_score:.1f}, "
            f"matches={len(self.matched_indicators)}, "
            f"severity={self.severity_label!r})"
        )
