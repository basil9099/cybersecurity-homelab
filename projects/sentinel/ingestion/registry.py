"""
Parser registry — maps source tool names to parser classes and auto-detects
which parser to use from JSON/CSV structure heuristics.
"""

from __future__ import annotations

import os
from typing import Any

from ingestion.base_parser import BaseParser
from ingestion.spectre_parser import SpectreParser
from ingestion.nimbus_parser import NimbusParser
from ingestion.osint_parser import OsintParser
from ingestion.api_tester_parser import ApiTesterParser
from ingestion.anomaly_parser import AnomalyParser
from ingestion.network_monitor_parser import NetworkMonitorParser

PARSER_REGISTRY: dict[str, type[BaseParser]] = {
    "spectre":         SpectreParser,
    "nimbus":          NimbusParser,
    "osint":           OsintParser,
    "api_tester":      ApiTesterParser,
    "anomaly":         AnomalyParser,
    "network_monitor": NetworkMonitorParser,
}


def get_parser(source_tool: str) -> BaseParser:
    """Return an instantiated parser for *source_tool* (exact match)."""
    cls = PARSER_REGISTRY.get(source_tool)
    if cls is None:
        raise KeyError(f"Unknown source tool '{source_tool}'. Valid: {list(PARSER_REGISTRY)}")
    return cls()


def auto_detect_parser(filepath: str, data: Any = None) -> BaseParser | None:
    """
    Detect the correct parser by inspecting JSON structure heuristics.
    Returns None if the format is not recognised.
    """
    # CSVs → anomaly detector
    if filepath.lower().endswith(".csv"):
        return AnomalyParser()

    if not isinstance(data, (dict, list)):
        return None

    if isinstance(data, dict):
        keys = set(data.keys())

        # SPECTRE: has "target" + "ports"
        if "target" in keys and "ports" in keys:
            return SpectreParser()

        # NIMBUS: has "findings" list where items have "provider"
        if "findings" in keys:
            findings = data.get("findings", [])
            if findings and isinstance(findings[0], dict) and "provider" in findings[0]:
                return NimbusParser()
            # API tester: single scan result object
            if "scanner" in keys and "target" in keys:
                return ApiTesterParser()

        # OSINT: has "meta" with "framework" or "target" + risk_assessment
        if "meta" in keys and ("risk_assessment" in keys or "infrastructure" in keys):
            return OsintParser()

        # Network Monitor: has "alerts" + "windows"
        if "alerts" in keys and "windows" in keys:
            return NetworkMonitorParser()

        # Anomaly: has "anomalies" or "results" list
        if "anomalies" in keys or "results" in keys:
            return AnomalyParser()

    # List-level checks
    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict):
            fkeys = set(first.keys())
            # API Tester: list of scan results each with "scanner" + "findings"
            if "scanner" in fkeys and "findings" in fkeys:
                return ApiTesterParser()
            # Anomaly: list with anomaly_score or prediction
            if "anomaly_score" in fkeys or "prediction" in fkeys or "is_anomaly" in fkeys:
                return AnomalyParser()

    return None


def load_file(filepath: str) -> tuple[BaseParser, list, list[str]]:
    """
    Load *filepath*, auto-detect parser, and return (parser, findings, warnings).
    Warnings is a list of non-fatal messages.
    """
    import json
    warnings: list[str] = []

    if not os.path.exists(filepath):
        warnings.append(f"File not found: {filepath}")
        return None, [], warnings  # type: ignore[return-value]

    # Load raw data first for heuristic detection
    suffix = os.path.splitext(filepath)[1].lower()
    if suffix == ".csv":
        parser = AnomalyParser()
    else:
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except Exception as exc:
            warnings.append(f"Cannot parse {filepath}: {exc}")
            return None, [], warnings  # type: ignore[return-value]

        parser = auto_detect_parser(filepath, raw)
        if parser is None:
            warnings.append(f"Cannot detect tool type for {filepath} — skipping")
            return None, [], warnings  # type: ignore[return-value]

    findings, parse_warnings = parser.safe_parse(filepath)
    warnings.extend(parse_warnings)
    return parser, findings, warnings
