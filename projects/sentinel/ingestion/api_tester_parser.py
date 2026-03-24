"""
Parser for API Security Tester JSON output.

Expected format: list of ScanResult objects, each with:
  scanner, target, findings (list of Finding dicts with title/severity/description/evidence)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from core.models import NormalizedFinding
from ingestion.base_parser import BaseParser, ParseError

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_SCORE_MAP = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0, "info": 0.5}


class ApiTesterParser(BaseParser):
    SOURCE_TOOL = "api_tester"

    def parse(self, data: Any, source_file: str = "") -> list[NormalizedFinding]:
        # Accept either a list of scan results or a single scan result dict
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            raise ParseError("API Tester JSON must be a list or object at top level")

        scan_time = datetime.now(timezone.utc).isoformat()
        results: list[NormalizedFinding] = []

        for scan in data:
            if not isinstance(scan, dict):
                continue
            target_url = scan.get("target", "")
            scanner_name = scan.get("scanner", "api_tester")
            # Extract scan-level timestamp if present
            ts = scan.get("scan_time", scan.get("timestamp", scan_time))

            # Parse target URL for entities
            parsed = urlparse(target_url)
            host = parsed.hostname or target_url
            ips_from_url = _IP_RE.findall(host)
            domains_from_url = [host] if host and not _IP_RE.match(host) else []

            for f in scan.get("findings", []):
                if not isinstance(f, dict):
                    continue
                raw_sev = f.get("severity", "info").lower()
                sev = raw_sev if raw_sev in _SCORE_MAP else "info"

                desc = f.get("description", "")
                evidence = f.get("evidence", "")
                attack_exp = f.get("attack_explanation", "")
                full_text = f"{f.get('title', '')} {desc} {evidence} {attack_exp}"

                ips = list(set(_IP_RE.findall(full_text) + ips_from_url))
                cves = list(set(_CVE_RE.findall(full_text)))
                domains = list(set(domains_from_url))

                results.append(NormalizedFinding(
                    finding_id=NormalizedFinding.make_id(),
                    source_tool=self.SOURCE_TOOL,
                    source_file=source_file,
                    timestamp=ts,
                    title=f.get("title", "API security finding"),
                    description=f"{desc} Evidence: {evidence}" if evidence else desc,
                    severity=sev,
                    raw_severity_score=_SCORE_MAP[sev],
                    entities={
                        "ips": ips,
                        "cves": cves,
                        "domains": domains,
                        "ports": [],
                        "hostnames": [],
                    },
                    raw={**f, "scanner": scanner_name, "target": target_url},
                ))

        return results
