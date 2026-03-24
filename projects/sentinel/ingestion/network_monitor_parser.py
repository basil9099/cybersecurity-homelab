"""
Parser for Network Baseline Monitor JSON output.

Expected top-level keys: alerts (list), windows (list), generated_at
Each alert has: rule, level, message, timestamp, detail (dict with src_ip, dst_ip, etc.)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from core.models import NormalizedFinding
from ingestion.base_parser import BaseParser, ParseError

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SCORE_MAP = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0, "info": 0.5}
_LEVEL_MAP = {"high": "high", "medium": "medium", "low": "low", "critical": "critical"}


class NetworkMonitorParser(BaseParser):
    SOURCE_TOOL = "network_monitor"

    def parse(self, data: Any, source_file: str = "") -> list[NormalizedFinding]:
        if not isinstance(data, dict):
            raise ParseError("Network Monitor JSON must be an object at top level")

        scan_time = data.get("generated_at", datetime.now(timezone.utc).isoformat())
        alerts = data.get("alerts", [])
        if not isinstance(alerts, list):
            raise ParseError("Network Monitor JSON 'alerts' must be a list")

        results: list[NormalizedFinding] = []
        for alert in alerts:
            if not isinstance(alert, dict):
                continue

            raw_level = alert.get("level", "medium").lower()
            sev = _LEVEL_MAP.get(raw_level, "medium")
            score = _SCORE_MAP[sev]
            ts = alert.get("timestamp", scan_time)

            detail = alert.get("detail", {}) or {}
            src_ip = detail.get("src_ip", "")
            dst_ip = detail.get("dst_ip", "")
            port = str(detail.get("port", detail.get("dst_port", "")))

            # Collect all IPs from message + detail block
            msg = alert.get("message", "")
            text = f"{msg} {src_ip} {dst_ip} {str(detail)}"
            ips = list(set(_IP_RE.findall(text)))
            ports = [port] if port and port != "None" else []

            results.append(NormalizedFinding(
                finding_id=NormalizedFinding.make_id(),
                source_tool=self.SOURCE_TOOL,
                source_file=source_file,
                timestamp=ts,
                title=f"Network alert: {alert.get('rule', 'unknown rule')}",
                description=msg,
                severity=sev,
                raw_severity_score=score,
                entities={
                    "ips": ips,
                    "cves": [],
                    "domains": [],
                    "ports": ports,
                    "hostnames": [],
                },
                raw=alert,
            ))

        return results
