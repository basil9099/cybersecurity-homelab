#!/usr/bin/env python3
"""
ingestion/cloud.py
==================
Ingest findings from the NIMBUS cloud security scanner and normalize them
into the unified alert schema.

Reads JSON output from cloud scanner runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ingestion.schema import AlertSource, NormalizedAlert, Severity
from mappings.mitre_attack import map_alert


def ingest_from_json(
    json_path: str | Path,
    since_timestamp: float = 0.0,
) -> list[NormalizedAlert]:
    """
    Read NIMBUS cloud scanner JSON output and normalize findings.

    Expected format: list of finding objects with keys like
    rule_id, severity, resource, region, description, timestamp.
    """
    json_path = Path(json_path)
    if not json_path.exists():
        return []

    data = json.loads(json_path.read_text(encoding="utf-8"))
    findings = data if isinstance(data, list) else data.get("findings", [])

    alerts = []
    for finding in findings:
        alert = _finding_to_alert(finding)
        if alert and alert.timestamp > since_timestamp:
            alerts.append(alert)

    return sorted(alerts, key=lambda a: a.timestamp)


def _finding_to_alert(finding: dict[str, Any]) -> NormalizedAlert | None:
    """Convert a cloud scanner finding to NormalizedAlert."""
    try:
        timestamp = float(finding.get("timestamp", 0))
    except (ValueError, TypeError):
        return None

    anomaly_type = _classify_finding(finding)
    mapping = map_alert("cloud_scanner", anomaly_type)

    severity_str = str(finding.get("severity", "low")).lower()
    severity_map = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    severity = severity_map.get(severity_str, Severity.LOW)

    score_map = {
        Severity.LOW: 2.0,
        Severity.MEDIUM: 5.0,
        Severity.HIGH: 7.5,
        Severity.CRITICAL: 9.5,
    }

    return NormalizedAlert(
        timestamp=timestamp,
        source=AlertSource.CLOUD_SCANNER,
        anomaly_type=anomaly_type,
        severity=severity,
        score=score_map.get(severity, 2.0),
        src_entity=str(finding.get("resource", "")),
        dst_entity=str(finding.get("region", "")),
        technique_ids=list(mapping.technique_ids),
        tactic=mapping.tactic,
        raw_detail=finding,
    )


def _classify_finding(finding: dict[str, Any]) -> str:
    """Map a cloud finding to a known anomaly type based on rule_id or description."""
    rule_id = str(finding.get("rule_id", "")).lower()
    desc = str(finding.get("description", "")).lower()

    if "s3" in rule_id and "public" in desc:
        return "public_s3_bucket"
    if "iam" in rule_id or "permissive" in desc:
        return "overly_permissive_iam"
    if "security_group" in rule_id or "security group" in desc:
        return "security_group_open"
    if "logging" in rule_id or "cloudtrail" in desc:
        return "logging_disabled"
    return "cloud_misconfiguration"
