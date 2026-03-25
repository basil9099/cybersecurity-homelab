"""
ingestion.normalizer — Event normalization layer.

Detects source type and converts raw log data into the unified
NormalizedEvent schema used throughout SENTINEL.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ingestion.parsers import (
    HoneypotParser,
    NetworkBaselineParser,
    AttackCorrelatorParser,
    CloudScannerParser,
)


@dataclass
class NormalizedEvent:
    """Canonical event representation used across all SENTINEL subsystems."""

    id: str
    timestamp: str
    source: str
    severity: str
    category: str
    message: str
    raw_data: dict[str, Any]


# Severity hierarchy (lowest index = most severe).
SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]


class EventNormalizer:
    """Detect source type and convert raw data into a NormalizedEvent."""

    def __init__(self) -> None:
        self._parsers: dict[str, Any] = {
            "honeypot": HoneypotParser(),
            "network_baseline": NetworkBaselineParser(),
            "attack_correlator": AttackCorrelatorParser(),
            "cloud_scanner": CloudScannerParser(),
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def normalize(
        self, source_type: str, raw_data: dict[str, Any]
    ) -> NormalizedEvent | None:
        """Normalize a single raw event dict into a *NormalizedEvent*.

        Returns ``None`` when the source type is unrecognized or the
        underlying parser cannot handle the data.
        """
        parser = self._parsers.get(source_type)
        if parser is None:
            return None

        try:
            parsed = parser.parse(raw_data)
        except Exception:
            return None

        return NormalizedEvent(
            id=parsed.get("id", str(uuid.uuid4())),
            timestamp=parsed.get("timestamp", _utcnow_iso()),
            source=parsed.get("source", source_type),
            severity=parsed.get("severity", "info"),
            category=parsed.get("category", "unknown"),
            message=parsed.get("message", ""),
            raw_data=raw_data,
        )

    def detect_source_type(self, raw_data: dict[str, Any]) -> str | None:
        """Heuristically determine which source produced *raw_data*."""
        if "protocol" in raw_data and "src_ip" in raw_data and "event_type" in raw_data:
            return "honeypot"
        if "alert_type" in raw_data and "severity" in raw_data and "details" in raw_data:
            return "network_baseline"
        if "chain_id" in raw_data and "tactic" in raw_data and "technique" in raw_data:
            return "attack_correlator"
        if "check_id" in raw_data and "resource" in raw_data and "status" in raw_data:
            return "cloud_scanner"
        return None


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
