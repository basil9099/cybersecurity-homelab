"""Correlator -- cross-references TI indicators against local log sources."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from pathlib import Path
from typing import Any

from models.enrichment import EnrichmentResult
from models.indicator import Indicator, IndicatorType

from .ioc_database import IOCDatabase

logger = logging.getLogger(__name__)

# Regex patterns for extracting potential IOCs from free-form log text
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|tk|ml)\b"
)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


def _is_private_ip(ip_str: str) -> bool:
    """Return True if *ip_str* is RFC-1918 or loopback."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


class Correlator:
    """Cross-references threat intelligence with local log data.

    Accepts log events as dicts (e.g., parsed JSONL) and checks extracted
    artifacts (IPs, domains, URLs, hashes) against the IOC database.

    Typical workflow::

        db = IOCDatabase()
        db.upsert_many(feed_manager.fetch_all())
        correlator = Correlator(db)
        results = correlator.correlate_log_file("honeypot.jsonl")
    """

    def __init__(self, ioc_db: IOCDatabase) -> None:
        self.ioc_db = ioc_db
        self._ioc_values: set[str] | None = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def correlate_event(self, event: dict[str, Any]) -> EnrichmentResult | None:
        """Check a single log event against the IOC database.

        Returns an :class:`EnrichmentResult` if any matches are found,
        otherwise ``None``.
        """
        artifacts = self._extract_artifacts(event)
        if not artifacts:
            return None

        ioc_values = self._get_ioc_values()
        matched: list[Indicator] = []

        for artifact in artifacts:
            if artifact in ioc_values:
                indicators = self.ioc_db.lookup(artifact)
                matched.extend(indicators)

        if not matched:
            return None

        return EnrichmentResult(
            original_event=event,
            matched_indicators=matched,
            metadata={"artifact_count": len(artifacts)},
        )

    def correlate_events(
        self, events: list[dict[str, Any]]
    ) -> list[EnrichmentResult]:
        """Correlate a batch of log events. Returns only events with hits."""
        results: list[EnrichmentResult] = []
        for event in events:
            result = self.correlate_event(event)
            if result is not None:
                results.append(result)
        return results

    def correlate_log_file(self, path: str | Path) -> list[EnrichmentResult]:
        """Read a JSONL log file and correlate each line.

        Each line is expected to be a valid JSON object.
        """
        log_path = Path(path)
        if not log_path.exists():
            logger.warning("Log file not found: %s", log_path)
            return []

        events: list[dict[str, Any]] = []
        with open(log_path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.debug("Skipping non-JSON line %d in %s", lineno, log_path)

        logger.info("Loaded %d events from %s", len(events), log_path)
        return self.correlate_events(events)

    def correlate_log_lines(self, lines: list[str]) -> list[EnrichmentResult]:
        """Correlate raw log lines (each parsed as JSON)."""
        events: list[dict[str, Any]] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return self.correlate_events(events)

    # ------------------------------------------------------------------
    # Artifact extraction
    # ------------------------------------------------------------------

    def _extract_artifacts(self, event: dict[str, Any]) -> set[str]:
        """Extract potential IOC values from a log event dictionary."""
        artifacts: set[str] = set()

        # Direct field extraction for well-known keys
        for key in (
            "src_ip", "dst_ip", "source_ip", "dest_ip", "ip",
            "remote_ip", "client_ip", "server_ip", "attacker_ip",
        ):
            val = event.get(key)
            if val and isinstance(val, str) and not _is_private_ip(val):
                artifacts.add(val)

        for key in ("domain", "hostname", "host", "dns_query", "server_name"):
            val = event.get(key)
            if val and isinstance(val, str):
                artifacts.add(val)

        for key in ("url", "request_url", "uri"):
            val = event.get(key)
            if val and isinstance(val, str):
                artifacts.add(val)

        for key in ("md5", "sha1", "sha256", "hash", "file_hash"):
            val = event.get(key)
            if val and isinstance(val, str):
                artifacts.add(val)

        # Free-text extraction from message / raw fields
        for key in ("message", "raw", "payload", "data"):
            text = event.get(key)
            if not isinstance(text, str):
                continue
            for ip in _IP_RE.findall(text):
                if not _is_private_ip(ip):
                    artifacts.add(ip)
            for domain in _DOMAIN_RE.findall(text):
                artifacts.add(domain)
            for url in _URL_RE.findall(text):
                artifacts.add(url)
            for h in _HASH_RE.findall(text):
                if len(h) in (32, 40, 64):
                    artifacts.add(h)

        return artifacts

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _get_ioc_values(self) -> set[str]:
        """Lazy-load the set of all IOC values for fast O(1) lookups."""
        if self._ioc_values is None:
            self._ioc_values = self.ioc_db.all_values()
        return self._ioc_values

    def invalidate_cache(self) -> None:
        """Force reload of the IOC value set on next correlation."""
        self._ioc_values = None

    def __repr__(self) -> str:
        return f"<Correlator ioc_db={self.ioc_db!r}>"
