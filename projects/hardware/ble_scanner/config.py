"""
Configuration Loader
--------------------
Loads config.yaml with sensible defaults when file is missing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]


@dataclass
class ScanConfig:
    """Scan-related configuration."""

    default_duration: int = 10
    default_rssi_threshold: int = -90
    adapter: str | None = None
    connection_timeout: int = 10


@dataclass
class AssessmentRule:
    """A single assessment rule from config."""

    id: str
    title: str
    description: str
    severity: str
    category: str
    check: str
    remediation: str
    enabled: bool = True


@dataclass
class Config:
    """Top-level configuration."""

    scan: ScanConfig = field(default_factory=ScanConfig)
    company_ids: dict[int, str] = field(default_factory=dict)
    standard_services: dict[str, str] = field(default_factory=dict)
    assessment_rules: list[AssessmentRule] = field(default_factory=list)
    known_vulnerable_uuids: list[dict[str, Any]] = field(default_factory=list)
    sensitive_data_patterns: list[dict[str, str]] = field(default_factory=list)


def _default_company_ids() -> dict[int, str]:
    return {
        0x004C: "Apple, Inc.",
        0x0006: "Microsoft",
        0x00E0: "Google",
        0x0075: "Samsung Electronics",
        0x010F: "Xiaomi",
        0x0059: "Nordic Semiconductor",
        0x000D: "Texas Instruments",
        0x0131: "Tile, Inc.",
        0x0087: "Garmin International",
        0x00D2: "Huawei Technologies",
    }


def _default_standard_services() -> dict[str, str]:
    return {
        "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
        "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
        "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
        "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
        "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
        "00001810-0000-1000-8000-00805f9b34fb": "Blood Pressure",
        "00001816-0000-1000-8000-00805f9b34fb": "Cycling Speed and Cadence",
        "00001819-0000-1000-8000-00805f9b34fb": "Location and Navigation",
        "0000fe95-0000-1000-8000-00805f9b34fb": "Xiaomi Inc.",
        "0000fff0-0000-1000-8000-00805f9b34fb": "Common vendor custom base",
    }


def _default_assessment_rules() -> list[AssessmentRule]:
    return [
        AssessmentRule(
            id="BLE-AUTH-001", title="No Pairing Required",
            description="Device allows full GATT access without pairing/bonding",
            severity="high", category="authentication", check="check_no_pairing",
            remediation="Implement BLE pairing with MITM protection (Secure Connections)",
        ),
        AssessmentRule(
            id="BLE-AUTH-002", title="Just Works Pairing",
            description="Device uses Just Works pairing (no MITM protection)",
            severity="medium", category="authentication", check="check_just_works_pairing",
            remediation="Use Numeric Comparison or Passkey Entry for MITM protection",
        ),
        AssessmentRule(
            id="BLE-CHAR-001", title="Writable Characteristic Without Authentication",
            description="Characteristic allows unauthenticated writes",
            severity="high", category="configuration", check="check_unauthenticated_writes",
            remediation="Require authentication/encryption for write operations",
        ),
        AssessmentRule(
            id="BLE-CHAR-002", title="Sensitive Data in Readable Characteristic",
            description="Potentially sensitive data exposed in readable characteristics",
            severity="medium", category="data-exposure", check="check_sensitive_data_exposure",
            remediation="Encrypt sensitive data or require authentication for read access",
        ),
        AssessmentRule(
            id="BLE-CHAR-003", title="Device Information Service Exposed",
            description="Device exposes detailed hardware/firmware information",
            severity="low", category="data-exposure", check="check_device_info_exposure",
            remediation="Minimize exposed device information or require pairing",
        ),
        AssessmentRule(
            id="BLE-VULN-001", title="Known Vulnerable Service UUID",
            description="Device advertises a service UUID with known vulnerabilities",
            severity="high", category="vulnerability", check="check_known_vulnerable_uuids",
            remediation="Update device firmware to patched version",
        ),
        AssessmentRule(
            id="BLE-VULN-002", title="Legacy BLE Version Indicators",
            description="Device characteristics suggest BLE 4.0/4.1 without Secure Connections",
            severity="medium", category="vulnerability", check="check_legacy_ble",
            remediation="Update to firmware supporting BLE 4.2+ Secure Connections",
        ),
        AssessmentRule(
            id="BLE-PRIV-001", title="Static MAC Address (Public)",
            description="Device uses a static public MAC address enabling tracking",
            severity="medium", category="privacy", check="check_static_mac",
            remediation="Implement BLE address randomization (LE Random Address)",
        ),
        AssessmentRule(
            id="BLE-CONF-001", title="Excessive Characteristic Permissions",
            description="Characteristics with both read+write and no auth requirements",
            severity="medium", category="configuration", check="check_excessive_permissions",
            remediation="Apply principle of least privilege to characteristic permissions",
        ),
        AssessmentRule(
            id="BLE-CONF-002", title="Notification/Indication Without Encryption",
            description="Characteristic supports notifications without requiring encryption",
            severity="low", category="configuration", check="check_unencrypted_notifications",
            remediation="Require encrypted link for notification/indication subscriptions",
        ),
    ]


def _default_known_vulnerable_uuids() -> list[dict[str, Any]]:
    return [
        {
            "uuid": "0000fff0-0000-1000-8000-00805f9b34fb",
            "description": "Common cheap IoT vendor base UUID - often has hardcoded credentials",
            "cve_references": [],
        },
        {
            "uuid": "0000fee7-0000-1000-8000-00805f9b34fb",
            "description": "Tencent Holdings Limited - historical auth bypass",
            "cve_references": [],
        },
    ]


def _default_sensitive_patterns() -> list[dict[str, str]]:
    return [
        {"pattern": r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$", "label": "Email address"},
        {"pattern": r"^\d{3}-\d{2}-\d{4}$", "label": "SSN-like pattern"},
        {"pattern": r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", "label": "MAC address"},
        {"pattern": r"password|passwd|pwd|token|key|secret", "label": "Credential keyword"},
    ]


def load_config(path: str | None = None) -> Config:
    """Load configuration from YAML file, falling back to defaults."""
    if path is None:
        path = os.path.join(os.path.dirname(__file__), "config.yaml")

    cfg = Config()

    if yaml is not None and os.path.isfile(path):
        with open(path, "r") as f:
            raw = yaml.safe_load(f) or {}

        if "scan" in raw:
            s = raw["scan"]
            cfg.scan = ScanConfig(
                default_duration=s.get("default_duration", 10),
                default_rssi_threshold=s.get("default_rssi_threshold", -90),
                adapter=s.get("adapter"),
                connection_timeout=s.get("connection_timeout", 10),
            )

        if "company_ids" in raw:
            cfg.company_ids = {int(k): v for k, v in raw["company_ids"].items()}

        if "standard_services" in raw:
            cfg.standard_services = raw["standard_services"]

        if "assessment_rules" in raw:
            cfg.assessment_rules = [
                AssessmentRule(**r) for r in raw["assessment_rules"]
            ]

        if "known_vulnerable_uuids" in raw:
            cfg.known_vulnerable_uuids = raw["known_vulnerable_uuids"]

        if "sensitive_data_patterns" in raw:
            cfg.sensitive_data_patterns = raw["sensitive_data_patterns"]

    # Fill in defaults for any empty sections
    if not cfg.company_ids:
        cfg.company_ids = _default_company_ids()
    if not cfg.standard_services:
        cfg.standard_services = _default_standard_services()
    if not cfg.assessment_rules:
        cfg.assessment_rules = _default_assessment_rules()
    if not cfg.known_vulnerable_uuids:
        cfg.known_vulnerable_uuids = _default_known_vulnerable_uuids()
    if not cfg.sensitive_data_patterns:
        cfg.sensitive_data_patterns = _default_sensitive_patterns()

    return cfg
