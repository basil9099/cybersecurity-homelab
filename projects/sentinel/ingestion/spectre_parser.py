"""
Parser for SPECTRE (vulnerability_scanner) JSON output.

Expected top-level keys: target, port_range, scan_time, ports, banners, cves
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from core.models import NormalizedFinding
from ingestion.base_parser import BaseParser, ParseError


_SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "info",
    "INFO": "info",
}

_SCORE_MAP = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0, "info": 0.5}


class SpectreParser(BaseParser):
    SOURCE_TOOL = "spectre"

    def parse(self, data: Any, source_file: str = "") -> list[NormalizedFinding]:
        if not isinstance(data, dict):
            raise ParseError("SPECTRE JSON must be an object at top level")

        target = data.get("target", "unknown")
        scan_time = data.get("scan_time", datetime.now(timezone.utc).isoformat())
        ports: dict = data.get("ports", {})
        cves_map: dict = data.get("cves", {})
        banners: dict = data.get("banners", {})
        findings: list[NormalizedFinding] = []

        for port_str, port_info in ports.items():
            if not isinstance(port_info, dict):
                continue
            port_cves = cves_map.get(port_str, [])
            if not port_cves:
                # Still emit finding for open port even without CVEs
                sev = "info"
                score = 0.5
            else:
                # Severity is the highest among port's CVEs
                raw_sevs = [
                    _SEV_MAP.get(c.get("severity", "").upper(), "info")
                    for c in port_cves
                    if isinstance(c, dict)
                ]
                sev_order = ["critical", "high", "medium", "low", "info"]
                sev = min(raw_sevs, key=lambda s: sev_order.index(s)) if raw_sevs else "info"
                score = _SCORE_MAP[sev]

            service = port_info.get("service", "unknown")
            banner = banners.get(port_str, "")
            cve_ids = [c.get("id", "") for c in port_cves if isinstance(c, dict)]

            title = f"Open port {port_str}/{service} on {target}"
            if cve_ids:
                title += f" — {', '.join(cve_ids[:3])}"
                if len(cve_ids) > 3:
                    title += f" +{len(cve_ids) - 3} more"

            desc_parts = [f"Target: {target}", f"Port: {port_str} ({service})"]
            if banner:
                desc_parts.append(f"Banner: {banner}")
            if cve_ids:
                desc_parts.append(f"CVEs: {', '.join(cve_ids)}")

            findings.append(NormalizedFinding(
                finding_id=NormalizedFinding.make_id(),
                source_tool=self.SOURCE_TOOL,
                source_file=source_file,
                timestamp=scan_time,
                title=title,
                description=". ".join(desc_parts),
                severity=sev,
                raw_severity_score=score,
                entities={
                    "ips": [target] if _looks_like_ip(target) else [],
                    "cves": cve_ids,
                    "domains": [target] if not _looks_like_ip(target) else [],
                    "ports": [str(port_str)],
                    "hostnames": [],
                },
                raw={"port": port_str, "port_info": port_info, "cves": port_cves},
            ))

        return findings


def _looks_like_ip(s: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))
