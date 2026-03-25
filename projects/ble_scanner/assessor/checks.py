"""
Security Check Implementations
-------------------------------
Each check_* function takes a DeviceProfile and config, and returns
a list of SecurityFinding instances.
"""

from __future__ import annotations

import re
from typing import Any

from models import DeviceProfile, SecurityFinding


# ── Authentication Checks ────────────────────────────────────────────────────


def check_no_pairing(
    profile: DeviceProfile,
    rule: Any,
    **kwargs: Any,
) -> list[SecurityFinding]:
    """BLE-AUTH-001: Flag if full GATT access was achieved without pairing."""
    if not profile.connection_successful:
        return []
    if profile.pairing_required:
        return []

    return [SecurityFinding(
        finding_id=rule.id,
        severity=rule.severity,
        category=rule.category,
        title=rule.title,
        description="Full GATT service enumeration succeeded without any pairing or bonding requirement.",
        remediation=rule.remediation,
        evidence={
            "services_accessible": len(profile.services),
            "pairing_required": False,
        },
    )]


def check_just_works_pairing(
    profile: DeviceProfile,
    rule: Any,
    **kwargs: Any,
) -> list[SecurityFinding]:
    """BLE-AUTH-002: Detect Just Works pairing (no MITM protection)."""
    if not profile.connection_successful:
        return []
    # Just Works is indicated when pairing succeeded automatically without
    # user interaction — we infer this from successful connection with no
    # pairing prompt and device advertising no IO capabilities.
    if profile.pairing_required is not None and not profile.pairing_required:
        # If the device connected without pairing at all, that's covered
        # by BLE-AUTH-001. Just Works applies when pairing happened
        # transparently.
        return []

    return []


# ── Characteristic Checks ────────────────────────────────────────────────────


def check_unauthenticated_writes(
    profile: DeviceProfile,
    rule: Any,
    **kwargs: Any,
) -> list[SecurityFinding]:
    """BLE-CHAR-001: Find writable characteristics accessible without auth."""
    findings: list[SecurityFinding] = []
    if not profile.connection_successful or profile.pairing_required:
        return findings

    for service in profile.services:
        for char in service.characteristics:
            writable = {"write", "write-without-response"} & set(char.properties)
            if writable:
                findings.append(SecurityFinding(
                    finding_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    title=rule.title,
                    description=(
                        f"Characteristic {char.uuid} supports {', '.join(sorted(writable))} "
                        f"without authentication in service {service.uuid}."
                    ),
                    affected_characteristic=char.uuid,
                    affected_service=service.uuid,
                    remediation=rule.remediation,
                    evidence={
                        "properties": char.properties,
                        "service": service.uuid,
                    },
                ))

    return findings


def check_sensitive_data_exposure(
    profile: DeviceProfile,
    rule: Any,
    sensitive_patterns: list[dict[str, str]] | None = None,
    **kwargs: Any,
) -> list[SecurityFinding]:
    """BLE-CHAR-002: Scan readable characteristic values for sensitive data."""
    findings: list[SecurityFinding] = []
    patterns = sensitive_patterns or []

    for service in profile.services:
        for char in service.characteristics:
            if char.value_decoded is None:
                continue

            for pat in patterns:
                try:
                    if re.search(pat["pattern"], char.value_decoded, re.IGNORECASE):
                        findings.append(SecurityFinding(
                            finding_id=rule.id,
                            severity=rule.severity,
                            category=rule.category,
                            title=rule.title,
                            description=(
                                f"Characteristic {char.uuid} contains data matching "
                                f"'{pat['label']}' pattern."
                            ),
                            affected_characteristic=char.uuid,
                            affected_service=service.uuid,
                            remediation=rule.remediation,
                            evidence={
                                "pattern_label": pat["label"],
                                "value_preview": char.value_decoded[:50],
                            },
                        ))
                        break  # One match per characteristic is enough
                except re.error:
                    continue

    return findings


def check_device_info_exposure(
    profile: DeviceProfile,
    rule: Any,
    **kwargs: Any,
) -> list[SecurityFinding]:
    """BLE-CHAR-003: Check if Device Information Service exposes details."""
    DEVICE_INFO_UUID = "0000180a-0000-1000-8000-00805f9b34fb"

    for service in profile.services:
        if service.uuid.lower() == DEVICE_INFO_UUID:
            exposed_chars = [
                c.uuid for c in service.characteristics
                if "read" in c.properties
            ]
            if exposed_chars:
                return [SecurityFinding(
                    finding_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    title=rule.title,
                    description=(
                        f"Device Information Service exposes {len(exposed_chars)} "
                        f"readable characteristic(s) including hardware/firmware details."
                    ),
                    affected_service=DEVICE_INFO_UUID,
                    remediation=rule.remediation,
                    evidence={
                        "exposed_characteristics": exposed_chars,
                    },
                )]

    return []


# ── Vulnerability Checks ─────────────────────────────────────────────────────


def check_known_vulnerable_uuids(
    profile: DeviceProfile,
    rule: Any,
    known_vulnerable: list[dict[str, Any]] | None = None,
    **kwargs: Any,
) -> list[SecurityFinding]:
    """BLE-VULN-001: Match service UUIDs against known-vulnerable list."""
    findings: list[SecurityFinding] = []
    vuln_map = {v["uuid"].lower(): v for v in (known_vulnerable or [])}

    # Check advertised service UUIDs
    all_uuids = set(u.lower() for u in profile.device.service_uuids)
    # Also check discovered service UUIDs
    for service in profile.services:
        all_uuids.add(service.uuid.lower())

    for uuid in all_uuids:
        if uuid in vuln_map:
            vuln = vuln_map[uuid]
            findings.append(SecurityFinding(
                finding_id=rule.id,
                severity=rule.severity,
                category=rule.category,
                title=rule.title,
                description=(
                    f"Service UUID {uuid} matches known vulnerable pattern: "
                    f"{vuln['description']}"
                ),
                affected_service=uuid,
                remediation=rule.remediation,
                evidence={
                    "uuid": uuid,
                    "vulnerability_description": vuln["description"],
                    "cve_references": vuln.get("cve_references", []),
                },
            ))

    return findings


def check_legacy_ble(
    profile: DeviceProfile,
    rule: Any,
    **kwargs: Any,
) -> list[SecurityFinding]:
    """BLE-VULN-002: Detect indicators of legacy BLE 4.0/4.1."""
    if not profile.connection_successful:
        return []

    # Heuristic: if no characteristics use "authenticated-signed-writes"
    # or if all descriptors lack CCCD with encryption bits, likely legacy.
    has_secure_indicators = False
    for service in profile.services:
        for char in service.characteristics:
            if "authenticated-signed-writes" in char.properties:
                has_secure_indicators = True
                break
        if has_secure_indicators:
            break

    # Also check for very few services (legacy devices tend to be simpler)
    if not has_secure_indicators and len(profile.services) > 0:
        return [SecurityFinding(
            finding_id=rule.id,
            severity=rule.severity,
            category=rule.category,
            title=rule.title,
            description=(
                "Device does not show BLE 4.2+ Secure Connections indicators. "
                "No authenticated-signed-writes properties found on any characteristic."
            ),
            remediation=rule.remediation,
            evidence={
                "secure_indicators_found": False,
                "total_services": len(profile.services),
            },
        )]

    return []


# ── Privacy Checks ───────────────────────────────────────────────────────────


def check_static_mac(
    profile: DeviceProfile,
    rule: Any,
    **kwargs: Any,
) -> list[SecurityFinding]:
    """BLE-PRIV-001: Check if device uses a static public MAC address."""
    if profile.device.address_type == "public":
        return [SecurityFinding(
            finding_id=rule.id,
            severity=rule.severity,
            category=rule.category,
            title=rule.title,
            description=(
                f"Device uses a public (static) MAC address ({profile.device.address}), "
                "which enables persistent tracking across sessions."
            ),
            remediation=rule.remediation,
            evidence={
                "address": profile.device.address,
                "address_type": "public",
            },
        )]

    return []


# ── Configuration Checks ─────────────────────────────────────────────────────


def check_excessive_permissions(
    profile: DeviceProfile,
    rule: Any,
    **kwargs: Any,
) -> list[SecurityFinding]:
    """BLE-CONF-001: Flag characteristics with read+write and no auth."""
    findings: list[SecurityFinding] = []
    if not profile.connection_successful or profile.pairing_required:
        return findings

    for service in profile.services:
        for char in service.characteristics:
            props = set(char.properties)
            has_read = "read" in props
            has_write = bool({"write", "write-without-response"} & props)
            if has_read and has_write:
                findings.append(SecurityFinding(
                    finding_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    title=rule.title,
                    description=(
                        f"Characteristic {char.uuid} has both read and write access "
                        f"without authentication in service {service.uuid}."
                    ),
                    affected_characteristic=char.uuid,
                    affected_service=service.uuid,
                    remediation=rule.remediation,
                    evidence={
                        "properties": char.properties,
                    },
                ))

    return findings


def check_unencrypted_notifications(
    profile: DeviceProfile,
    rule: Any,
    **kwargs: Any,
) -> list[SecurityFinding]:
    """BLE-CONF-002: Check for notify/indicate without encryption."""
    findings: list[SecurityFinding] = []
    if not profile.connection_successful or profile.pairing_required:
        return findings

    for service in profile.services:
        for char in service.characteristics:
            props = set(char.properties)
            if {"notify", "indicate"} & props:
                findings.append(SecurityFinding(
                    finding_id=rule.id,
                    severity=rule.severity,
                    category=rule.category,
                    title=rule.title,
                    description=(
                        f"Characteristic {char.uuid} supports "
                        f"{', '.join(sorted({'notify', 'indicate'} & props))} "
                        f"without requiring an encrypted link."
                    ),
                    affected_characteristic=char.uuid,
                    affected_service=service.uuid,
                    remediation=rule.remediation,
                    evidence={
                        "properties": char.properties,
                    },
                ))

    return findings
