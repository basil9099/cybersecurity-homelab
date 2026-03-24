"""
Parser for OSINT Framework JSON output.

Expected top-level keys: meta, organisation, infrastructure, breach_exposure,
                          risk_assessment
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


class OsintParser(BaseParser):
    SOURCE_TOOL = "osint"

    def parse(self, data: Any, source_file: str = "") -> list[NormalizedFinding]:
        if not isinstance(data, dict):
            raise ParseError("OSINT JSON must be an object at top level")

        meta = data.get("meta", {})
        target = meta.get("target", "unknown")
        scan_time = meta.get("generated_at", datetime.now(timezone.utc).isoformat())

        results: list[NormalizedFinding] = []

        # ------------------------------------------------------------------
        # Findings from risk_assessment block
        # ------------------------------------------------------------------
        risk = data.get("risk_assessment", {})
        for f in risk.get("findings", []):
            if not isinstance(f, dict):
                continue
            raw_sev = f.get("severity", "info").lower()
            sev = raw_sev if raw_sev in _SCORE_MAP else "info"
            desc = f.get("description", f.get("detail", ""))
            text = f"{f.get('title', '')} {desc}"
            ips = _IP_RE.findall(text)
            domains = _DOMAIN_RE.findall(text)
            if target and not _looks_like_ip(target):
                domains = list(set(domains) | {target})

            results.append(NormalizedFinding(
                finding_id=NormalizedFinding.make_id(),
                source_tool=self.SOURCE_TOOL,
                source_file=source_file,
                timestamp=scan_time,
                title=f.get("title", "OSINT finding"),
                description=desc,
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

        # ------------------------------------------------------------------
        # Breach exposures → one finding per exposed breach
        # ------------------------------------------------------------------
        breach = data.get("breach_exposure", {})
        for b in breach.get("breaches", []):
            if not isinstance(b, dict):
                continue
            results.append(NormalizedFinding(
                finding_id=NormalizedFinding.make_id(),
                source_tool=self.SOURCE_TOOL,
                source_file=source_file,
                timestamp=scan_time,
                title=f"Breach exposure: {b.get('name', 'Unknown breach')}",
                description=(
                    f"Organisation credentials found in breach '{b.get('name')}'. "
                    f"Data classes: {', '.join(b.get('data_classes', []))}. "
                    f"Breach date: {b.get('breach_date', 'unknown')}."
                ),
                severity="high",
                raw_severity_score=7.5,
                entities={
                    "ips": [],
                    "cves": [],
                    "domains": [target] if target and not _looks_like_ip(target) else [],
                    "ports": [],
                    "hostnames": [],
                },
                raw=b,
            ))

        # ------------------------------------------------------------------
        # Shodan-exposed services from infrastructure block
        # ------------------------------------------------------------------
        infra = data.get("infrastructure", {})
        for svc in infra.get("services", []):
            if not isinstance(svc, dict):
                continue
            ip = svc.get("ip", "")
            port = str(svc.get("port", ""))
            banner = svc.get("banner", "")
            results.append(NormalizedFinding(
                finding_id=NormalizedFinding.make_id(),
                source_tool=self.SOURCE_TOOL,
                source_file=source_file,
                timestamp=scan_time,
                title=f"Shodan: exposed service on {ip}:{port}",
                description=f"Internet-exposed service detected on {ip} port {port}. Banner: {banner}",
                severity="medium",
                raw_severity_score=5.0,
                entities={
                    "ips": [ip] if ip else [],
                    "cves": [],
                    "domains": [],
                    "ports": [port] if port else [],
                    "hostnames": [],
                },
                raw=svc,
            ))

        return results


def _looks_like_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))
