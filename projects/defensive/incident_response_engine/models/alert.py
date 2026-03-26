"""Alert data model for incoming security events."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class AlertSeverity(str, Enum):
    """Alert severity levels aligned with common SIEM classifications."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __str__(self) -> str:
        return self.value


class AlertType(str, Enum):
    """Supported alert type classifications."""

    BRUTE_FORCE = "brute_force"
    MALWARE_DETECTED = "malware_detected"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PHISHING = "phishing"
    DOS_ATTACK = "dos_attack"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CUSTOM = "custom"

    def __str__(self) -> str:
        return self.value


@dataclass
class Alert:
    """Represents an incoming security alert to be processed by the engine.

    Attributes:
        id: Unique alert identifier.
        timestamp: When the alert was generated.
        alert_type: Classification of the alert.
        severity: Severity level of the alert.
        source_ip: Source IP address associated with the alert.
        dest_ip: Destination IP address associated with the alert.
        description: Human-readable description of the alert.
        tags: Tags for flexible matching and categorization.
        raw_data: Original raw data from the alert source.
    """

    alert_type: AlertType
    severity: AlertSeverity
    source_ip: str
    dest_ip: str
    description: str
    id: str = field(default_factory=lambda: f"ALERT-{uuid.uuid4().hex[:8].upper()}")
    timestamp: datetime = field(default_factory=datetime.utcnow)
    tags: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize alert to a dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "alert_type": str(self.alert_type),
            "severity": str(self.severity),
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "description": self.description,
            "tags": self.tags,
            "raw_data": self.raw_data,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Alert:
        """Deserialize an alert from a dictionary."""
        return cls(
            id=data.get("id", f"ALERT-{uuid.uuid4().hex[:8].upper()}"),
            timestamp=datetime.fromisoformat(data["timestamp"])
            if "timestamp" in data
            else datetime.utcnow(),
            alert_type=AlertType(data["alert_type"]),
            severity=AlertSeverity(data["severity"]),
            source_ip=data["source_ip"],
            dest_ip=data["dest_ip"],
            description=data["description"],
            tags=data.get("tags", []),
            raw_data=data.get("raw_data", {}),
        )
