#!/usr/bin/env python3
"""
ingestion/siem.py
=================
Ingest alerts from Splunk SIEM CSV/JSON exports and normalize them into
the unified alert schema.

Supports two formats:
  - CSV exports from Splunk search results
  - JSON files (one alert per line or array of objects)
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from ingestion.schema import AlertSource, NormalizedAlert, Severity
from mappings.mitre_attack import map_alert


def ingest_from_csv(
    csv_path: str | Path,
    since_timestamp: float = 0.0,
) -> list[NormalizedAlert]:
    """
    Read Splunk CSV export and normalize alerts.

    Expected columns: _time, alert_type, severity, score, src, dest, detail
    Columns are flexible — unmapped columns go into raw_detail.
    """
    csv_path = Path(csv_path)
    if not csv_path.exists():
        return []

    alerts: list[NormalizedAlert] = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            alert = _csv_row_to_alert(row)
            if alert and alert.timestamp > since_timestamp:
                alerts.append(alert)

    return sorted(alerts, key=lambda a: a.timestamp)


def ingest_from_json(
    json_path: str | Path,
    since_timestamp: float = 0.0,
) -> list[NormalizedAlert]:
    """
    Read Splunk JSON export and normalize alerts.

    Supports: JSON array or newline-delimited JSON.
    """
    json_path = Path(json_path)
    if not json_path.exists():
        return []

    text = json_path.read_text(encoding="utf-8").strip()
    records: list[dict[str, Any]] = []

    if text.startswith("["):
        records = json.loads(text)
    else:
        for line in text.splitlines():
            line = line.strip()
            if line:
                records.append(json.loads(line))

    alerts = []
    for rec in records:
        alert = _json_record_to_alert(rec)
        if alert and alert.timestamp > since_timestamp:
            alerts.append(alert)

    return sorted(alerts, key=lambda a: a.timestamp)


def _csv_row_to_alert(row: dict[str, str]) -> NormalizedAlert | None:
    """Convert a Splunk CSV row to NormalizedAlert."""
    try:
        timestamp = float(row.get("_time", row.get("timestamp", "0")))
    except (ValueError, TypeError):
        return None

    anomaly_type = row.get("alert_type", row.get("type", "unknown"))
    mapping = map_alert("splunk_siem", anomaly_type)

    severity_str = row.get("severity", "low").lower()
    severity = _parse_severity(severity_str)

    try:
        score = float(row.get("score", row.get("urgency", "0")))
    except (ValueError, TypeError):
        score = 0.0

    return NormalizedAlert(
        timestamp=timestamp,
        source=AlertSource.SPLUNK_SIEM,
        anomaly_type=anomaly_type,
        severity=severity,
        score=min(score, 10.0),
        src_entity=row.get("src", row.get("src_ip", "")),
        dst_entity=row.get("dest", row.get("dst_ip", "")),
        technique_ids=list(mapping.technique_ids),
        tactic=mapping.tactic,
        raw_detail={k: v for k, v in row.items()},
    )


def _json_record_to_alert(rec: dict[str, Any]) -> NormalizedAlert | None:
    """Convert a Splunk JSON record to NormalizedAlert."""
    try:
        timestamp = float(rec.get("_time", rec.get("timestamp", 0)))
    except (ValueError, TypeError):
        return None

    anomaly_type = rec.get("alert_type", rec.get("type", "unknown"))
    mapping = map_alert("splunk_siem", anomaly_type)

    severity_str = str(rec.get("severity", "low")).lower()
    severity = _parse_severity(severity_str)

    try:
        score = float(rec.get("score", rec.get("urgency", 0)))
    except (ValueError, TypeError):
        score = 0.0

    return NormalizedAlert(
        timestamp=timestamp,
        source=AlertSource.SPLUNK_SIEM,
        anomaly_type=anomaly_type,
        severity=severity,
        score=min(score, 10.0),
        src_entity=str(rec.get("src", rec.get("src_ip", ""))),
        dst_entity=str(rec.get("dest", rec.get("dst_ip", ""))),
        technique_ids=list(mapping.technique_ids),
        tactic=mapping.tactic,
        raw_detail=rec,
    )


def _parse_severity(s: str) -> Severity:
    mapping = {
        "low": Severity.LOW,
        "informational": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    return mapping.get(s, Severity.LOW)
