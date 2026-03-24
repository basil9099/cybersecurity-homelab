#!/usr/bin/env python3
"""
ingestion/schema.py
===================
Unified alert schema that normalizes alerts from all homelab security tools
into a common format for attack chain correlation.

Every alert—regardless of source—gets mapped to this schema before entering
the correlation engine.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AlertSource(str, Enum):
    """Source tool that generated the alert."""
    NETWORK_BASELINE = "network_baseline"
    SPLUNK_SIEM = "splunk_siem"
    CLOUD_SCANNER = "cloud_scanner"
    VULN_SCANNER = "vuln_scanner"
    EXPLOIT_FRAMEWORK = "exploit_framework"
    MANUAL = "manual"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class NormalizedAlert:
    """
    Unified alert format consumed by the correlation engine.

    Fields:
        alert_id:       Unique identifier for this alert.
        timestamp:      Unix timestamp when the event occurred.
        source:         Which tool generated this alert.
        anomaly_type:   Tool-specific alert type (e.g. "port_scan", "c2_beaconing").
        severity:       Normalized severity level.
        score:          Numeric confidence/severity score (0.0–10.0).
        src_entity:     Source entity (IP, hostname, or user).
        dst_entity:     Destination entity (IP, hostname, service), if applicable.
        technique_ids:  List of MITRE ATT&CK technique IDs mapped to this alert.
        tactic:         Primary ATT&CK tactic (kill chain stage).
        raw_detail:     Original alert details preserved for drill-down.
    """
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)
    source: AlertSource = AlertSource.MANUAL
    anomaly_type: str = ""
    severity: Severity = Severity.LOW
    score: float = 0.0
    src_entity: str = ""
    dst_entity: str = ""
    technique_ids: list[str] = field(default_factory=list)
    tactic: str = ""
    raw_detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "source": self.source.value,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity.value,
            "score": self.score,
            "src_entity": self.src_entity,
            "dst_entity": self.dst_entity,
            "technique_ids": self.technique_ids,
            "tactic": self.tactic,
            "raw_detail": self.raw_detail,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> NormalizedAlert:
        return cls(
            alert_id=d.get("alert_id", uuid.uuid4().hex[:12]),
            timestamp=d.get("timestamp", time.time()),
            source=AlertSource(d.get("source", "manual")),
            anomaly_type=d.get("anomaly_type", ""),
            severity=Severity(d.get("severity", "low")),
            score=d.get("score", 0.0),
            src_entity=d.get("src_entity", ""),
            dst_entity=d.get("dst_entity", ""),
            technique_ids=d.get("technique_ids", []),
            tactic=d.get("tactic", ""),
            raw_detail=d.get("raw_detail", {}),
        )
