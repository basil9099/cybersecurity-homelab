"""
Parser for NIMBUS (cloud_security_scanner) JSON output.

Expected top-level keys: findings (list), provider_scores, metadata
Each finding has: rule_id, provider, resource_type, resource_id, region,
                  severity, status, title, description, remediation, cis_benchmark
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from core.models import NormalizedFinding
from ingestion.base_parser import BaseParser, ParseError

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)

_SCORE_MAP = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0, "info": 0.5}


class NimbusParser(BaseParser):
    SOURCE_TOOL = "nimbus"

    def parse(self, data: Any, source_file: str = "") -> list[NormalizedFinding]:
        if not isinstance(data, dict):
            raise ParseError("NIMBUS JSON must be an object at top level")

        raw_findings = data.get("findings", [])
        if not isinstance(raw_findings, list):
            raise ParseError("NIMBUS JSON 'findings' must be a list")

        meta = data.get("metadata", {})
        scan_time = meta.get("scan_time", datetime.now(timezone.utc).isoformat())

        results: list[NormalizedFinding] = []
        for f in raw_findings:
            if not isinstance(f, dict):
                continue
            if f.get("status", "FAIL") != "FAIL":
                continue

            raw_sev = f.get("severity", "info").lower()
            sev = raw_sev if raw_sev in _SCORE_MAP else "info"
            resource_id = f.get("resource_id", "")

            ips = _IP_RE.findall(resource_id + " " + f.get("description", ""))
            domains = _DOMAIN_RE.findall(resource_id)

            results.append(NormalizedFinding(
                finding_id=NormalizedFinding.make_id(),
                source_tool=self.SOURCE_TOOL,
                source_file=source_file,
                timestamp=scan_time,
                title=f.get("title", "Unnamed cloud finding"),
                description=f.get("description", "") + ". " + f.get("remediation", ""),
                severity=sev,
                raw_severity_score=_SCORE_MAP[sev],
                entities={
                    "ips": list(set(ips)),
                    "cves": [],
                    "domains": list(set(domains)),
                    "ports": [],
                    "hostnames": [],
                },
                raw=f,
            ))

        return results
