"""
Regex-based entity extraction — enriches NormalizedFinding.entities in-place.
"""

from __future__ import annotations

import re
from typing import Any

from core.models import NormalizedFinding

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|gov|edu|co|uk|de|fr|ru|cn|info|biz|mil|int|arpa|local)\b", re.I)
_PORT_RE = re.compile(r"\bports?\s+(\d{1,5})\b|\b(\d{1,5})/tcp\b|\b(\d{1,5})/udp\b", re.I)


def _flatten_values(obj: Any, depth: int = 3) -> list[str]:
    """Recursively gather string leaf values from a nested dict/list."""
    if depth <= 0:
        return []
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, (int, float)):
        return [str(obj)]
    if isinstance(obj, dict):
        out = []
        for v in obj.values():
            out.extend(_flatten_values(v, depth - 1))
        return out
    if isinstance(obj, list):
        out = []
        for item in obj:
            out.extend(_flatten_values(item, depth - 1))
        return out
    return []


class EntityExtractor:
    """Runs all regexes over finding text + raw dict and populates finding.entities."""

    def extract(self, finding: NormalizedFinding) -> None:
        """Enrich *finding.entities* in-place from title, description, and raw dict."""
        # Build search corpus
        raw_strings = _flatten_values(finding.raw, depth=3)
        corpus = " ".join([finding.title, finding.description] + raw_strings)

        # IPs
        ips = set(finding.entities.get("ips", [])) | set(_IP_RE.findall(corpus))
        # Remove loopback / broadcast
        ips = {ip for ip in ips if not ip.startswith("127.") and ip != "0.0.0.0" and ip != "255.255.255.255"}

        # CVEs
        cves = set(c.upper() for c in finding.entities.get("cves", [])) | {m.upper() for m in _CVE_RE.findall(corpus)}

        # Domains — deduplicate against IPs
        domains = set(finding.entities.get("domains", [])) | {m for m in _DOMAIN_RE.findall(corpus) if m not in ips}

        # Ports
        raw_ports = set(finding.entities.get("ports", []))
        for m in _PORT_RE.findall(corpus):
            # m is a tuple of 3 groups
            for g in m:
                if g:
                    raw_ports.add(g)
        # Filter obviously invalid port numbers
        valid_ports = {p for p in raw_ports if p.isdigit() and 1 <= int(p) <= 65535}

        finding.entities["ips"] = sorted(ips)
        finding.entities["cves"] = sorted(cves)
        finding.entities["domains"] = sorted(domains)
        finding.entities["ports"] = sorted(valid_ports, key=int)
        # hostnames stays as populated by parsers
