"""
ingestion.parsers — Source-specific log parsers.

Each parser converts a raw dict from its respective log source into
a normalized intermediate dict with keys:
    id, timestamp, source, severity, category, message
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ensure_id() -> str:
    return str(uuid.uuid4())


# ── Honeypot Parser ──────────────────────────────────────────────────────────


class HoneypotParser:
    """Parse honeypot JSONL records.

    Expected fields: protocol, src_ip, event_type, timestamp
    Optional: dst_port, payload, username, password
    """

    _SEVERITY_MAP: dict[str, str] = {
        "connection_attempt": "medium",
        "login_attempt": "high",
        "command_executed": "critical",
        "scan": "low",
        "probe": "low",
    }

    def parse(self, raw: dict[str, Any]) -> dict[str, Any]:
        event_type = raw.get("event_type", "unknown")
        protocol = raw.get("protocol", "unknown").upper()
        src_ip = raw.get("src_ip", "unknown")
        dst_port = raw.get("dst_port", "")

        severity = self._SEVERITY_MAP.get(event_type, "info")
        port_info = f":{dst_port}" if dst_port else ""
        message = (
            f"{protocol} {event_type.replace('_', ' ')} from {src_ip}{port_info}"
        )

        return {
            "id": _ensure_id(),
            "timestamp": raw.get("timestamp", _utcnow_iso()),
            "source": "honeypot",
            "severity": severity,
            "category": "intrusion_attempt",
            "message": message,
        }


# ── Network Baseline Parser ─────────────────────────────────────────────────


class NetworkBaselineParser:
    """Parse network baseline alert records.

    Expected fields: alert_type, severity, details
    Optional: src_ip, dst_ip, proto, bytes_transferred, timestamp
    """

    _VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

    def parse(self, raw: dict[str, Any]) -> dict[str, Any]:
        alert_type = raw.get("alert_type", "unknown_alert")
        severity = raw.get("severity", "info").lower()
        if severity not in self._VALID_SEVERITIES:
            severity = "info"

        details = raw.get("details", "")
        src_ip = raw.get("src_ip", "")
        dst_ip = raw.get("dst_ip", "")

        host_info = ""
        if src_ip and dst_ip:
            host_info = f" ({src_ip} -> {dst_ip})"
        elif src_ip:
            host_info = f" (from {src_ip})"

        message = f"{alert_type.replace('_', ' ').title()}: {details}{host_info}"

        return {
            "id": _ensure_id(),
            "timestamp": raw.get("timestamp", _utcnow_iso()),
            "source": "network_baseline",
            "severity": severity,
            "category": "network_anomaly",
            "message": message,
        }


# ── Attack Correlator Parser ────────────────────────────────────────────────


class AttackCorrelatorParser:
    """Parse attack chain correlator records.

    Expected fields: chain_id, tactic, technique, confidence
    Optional: src_ip, timestamp, evidence
    """

    def parse(self, raw: dict[str, Any]) -> dict[str, Any]:
        chain_id = raw.get("chain_id", "unknown")
        tactic = raw.get("tactic", "unknown")
        technique = raw.get("technique", "unknown")
        confidence = raw.get("confidence", 0.0)

        # Map confidence score to severity.
        if confidence >= 0.9:
            severity = "critical"
        elif confidence >= 0.7:
            severity = "high"
        elif confidence >= 0.4:
            severity = "medium"
        else:
            severity = "low"

        message = (
            f"Kill-chain {chain_id}: {tactic}/{technique} "
            f"(confidence={confidence:.0%})"
        )

        return {
            "id": _ensure_id(),
            "timestamp": raw.get("timestamp", _utcnow_iso()),
            "source": "attack_correlator",
            "severity": severity,
            "category": "attack_chain",
            "message": message,
        }


# ── Cloud Scanner Parser ────────────────────────────────────────────────────


class CloudScannerParser:
    """Parse cloud security scanner results.

    Expected fields: check_id, resource, status, provider
    Optional: region, details, timestamp
    """

    _STATUS_SEVERITY: dict[str, str] = {
        "fail": "high",
        "critical": "critical",
        "warn": "medium",
        "warning": "medium",
        "pass": "info",
        "info": "info",
    }

    def parse(self, raw: dict[str, Any]) -> dict[str, Any]:
        check_id = raw.get("check_id", "unknown")
        resource = raw.get("resource", "unknown")
        status = raw.get("status", "info").lower()
        provider = raw.get("provider", "unknown").upper()
        region = raw.get("region", "")
        details = raw.get("details", "")

        severity = self._STATUS_SEVERITY.get(status, "info")
        location = f" in {region}" if region else ""
        detail_suffix = f" — {details}" if details else ""

        message = (
            f"[{provider}] {check_id}: {resource}{location} "
            f"status={status}{detail_suffix}"
        )

        return {
            "id": _ensure_id(),
            "timestamp": raw.get("timestamp", _utcnow_iso()),
            "source": "cloud_scanner",
            "severity": severity,
            "category": "cloud_misconfiguration",
            "message": message,
        }
