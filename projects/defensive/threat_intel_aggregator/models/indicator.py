"""IOC indicator dataclass with type classification and metadata."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class IndicatorType(str, Enum):
    """Classification of indicator of compromise types."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"

    @classmethod
    def detect(cls, value: str) -> IndicatorType:
        """Auto-detect indicator type from its value."""
        value = value.strip()

        # IPv4 address
        if re.match(
            r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$",
            value,
        ):
            return cls.IP

        # IPv6 (simplified check)
        if ":" in value and re.match(r"^[0-9a-fA-F:]+$", value):
            return cls.IP

        # URL
        if re.match(r"^https?://", value, re.IGNORECASE):
            return cls.URL

        # SHA-256
        if re.match(r"^[a-fA-F0-9]{64}$", value):
            return cls.HASH_SHA256

        # SHA-1
        if re.match(r"^[a-fA-F0-9]{40}$", value):
            return cls.HASH_SHA1

        # MD5
        if re.match(r"^[a-fA-F0-9]{32}$", value):
            return cls.HASH_MD5

        # Email
        if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
            return cls.EMAIL

        # Domain (basic heuristic)
        if re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", value):
            return cls.DOMAIN

        return cls.UNKNOWN


@dataclass
class Indicator:
    """Represents a single indicator of compromise (IOC).

    Attributes:
        value: The raw IOC value (IP, domain, URL, hash, etc.).
        ioc_type: Classification of the indicator.
        source: Name of the feed or source that provided this indicator.
        first_seen: UTC timestamp when the indicator was first observed.
        last_seen: UTC timestamp when the indicator was most recently observed.
        confidence: Confidence score from 0.0 (low) to 1.0 (high).
        tags: Categorical labels (e.g. "malware", "c2", "phishing").
        raw_context: Arbitrary metadata from the originating feed.
    """

    value: str
    ioc_type: IndicatorType
    source: str
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 0.5
    tags: list[str] = field(default_factory=list)
    raw_context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.ioc_type == IndicatorType.UNKNOWN:
            self.ioc_type = IndicatorType.detect(self.value)
        self.confidence = max(0.0, min(1.0, self.confidence))

    @property
    def uid(self) -> str:
        """Deterministic unique identifier based on value, type, and source."""
        key = f"{self.value}|{self.ioc_type.value}|{self.source}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def is_stale(self) -> bool:
        """An indicator is considered stale if not seen in the last 7 days."""
        age = datetime.now(timezone.utc) - self.last_seen
        return age.days > 7

    @property
    def severity_label(self) -> str:
        """Human-readable severity derived from confidence score."""
        if self.confidence >= 0.8:
            return "critical"
        if self.confidence >= 0.6:
            return "high"
        if self.confidence >= 0.4:
            return "medium"
        if self.confidence >= 0.2:
            return "low"
        return "informational"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "uid": self.uid,
            "value": self.value,
            "ioc_type": self.ioc_type.value,
            "source": self.source,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "confidence": self.confidence,
            "tags": self.tags,
            "severity": self.severity_label,
            "raw_context": self.raw_context,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Indicator:
        """Deserialize from a plain dictionary."""
        return cls(
            value=data["value"],
            ioc_type=IndicatorType(data["ioc_type"]),
            source=data["source"],
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            confidence=data.get("confidence", 0.5),
            tags=data.get("tags", []),
            raw_context=data.get("raw_context", {}),
        )

    def __repr__(self) -> str:
        return (
            f"Indicator(value={self.value!r}, type={self.ioc_type.value}, "
            f"source={self.source!r}, confidence={self.confidence:.2f})"
        )
