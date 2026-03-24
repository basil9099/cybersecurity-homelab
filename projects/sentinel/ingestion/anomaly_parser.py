"""
Parser for Anomaly Detector output.

Accepts:
  - JSON: list of dicts with anomaly_score, features, label, timestamp
  - CSV: same fields as column headers (loaded via BaseParser.load_csv)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from core.models import NormalizedFinding
from ingestion.base_parser import BaseParser, ParseError

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SCORE_MAP = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0, "info": 0.5}


def _anomaly_score_to_severity(score: float) -> tuple[str, float]:
    """Map isolation-forest anomaly score (−1…0, lower = more anomalous) to severity."""
    # Anomaly detector typically outputs scores in [−1, 0]; more negative = more anomalous.
    # We normalise to [0, 10] where 0 = normal, 10 = most anomalous.
    normalised = max(0.0, min(10.0, (1.0 + abs(float(score))) * 5.0))
    if normalised >= 9.0:
        return "critical", normalised
    if normalised >= 7.0:
        return "high", normalised
    if normalised >= 4.0:
        return "medium", normalised
    if normalised >= 2.0:
        return "low", normalised
    return "info", normalised


class AnomalyParser(BaseParser):
    SOURCE_TOOL = "anomaly"

    def parse(self, data: Any, source_file: str = "") -> list[NormalizedFinding]:
        # Normalise: may arrive as list (JSON) or list[dict] (CSV already parsed)
        if isinstance(data, dict):
            # Might be wrapped: {"anomalies": [...]}
            data = data.get("anomalies", data.get("results", [data]))
        if not isinstance(data, list):
            raise ParseError("Anomaly Detector output must be a JSON array or CSV")

        scan_time = datetime.now(timezone.utc).isoformat()
        results: list[NormalizedFinding] = []

        for row in data:
            if not isinstance(row, dict):
                continue

            # Accept prediction=-1 or is_anomaly=true or anomaly_score < threshold
            is_anomaly = (
                str(row.get("prediction", "0")) == "-1"
                or str(row.get("is_anomaly", "false")).lower() in ("true", "1", "yes")
                or float(row.get("anomaly_score", 0)) < -0.1
            )
            if not is_anomaly:
                continue

            raw_score = float(row.get("anomaly_score", -0.5))
            sev, norm_score = _anomaly_score_to_severity(raw_score)
            ts = row.get("timestamp", scan_time)

            # Build description from available feature columns
            feature_strs = []
            for k, v in row.items():
                if k not in ("prediction", "is_anomaly", "anomaly_score", "timestamp"):
                    feature_strs.append(f"{k}={v}")

            text = " ".join(str(v) for v in row.values())
            ips = list(set(_IP_RE.findall(text)))

            label = row.get("label", row.get("event_type", "anomalous event"))
            title = f"Anomaly detected: {label}"
            desc = f"Anomaly score: {raw_score:.4f}. Features: {', '.join(feature_strs[:8])}"

            results.append(NormalizedFinding(
                finding_id=NormalizedFinding.make_id(),
                source_tool=self.SOURCE_TOOL,
                source_file=source_file,
                timestamp=ts,
                title=title,
                description=desc,
                severity=sev,
                raw_severity_score=norm_score,
                entities={
                    "ips": ips,
                    "cves": [],
                    "domains": [],
                    "ports": [],
                    "hostnames": [],
                },
                raw=row,
            ))

        return results
