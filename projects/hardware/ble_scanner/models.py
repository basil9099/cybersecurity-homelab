"""
Data Models
-----------
All dataclasses used across PHANTOM BLE Scanner modules.
"""

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class BLEDevice:
    """A discovered BLE device from scanning."""

    address: str
    name: str | None
    rssi: int
    address_type: str               # "public" | "random"
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)
    service_uuids: list[str] = field(default_factory=list)
    tx_power: int | None = None
    raw_advertisement: dict[str, Any] = field(default_factory=dict)
    first_seen: str = ""
    last_seen: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Convert bytes values in manufacturer_data to hex strings
        d["manufacturer_data"] = {
            k: v.hex() if isinstance(v, bytes) else v
            for k, v in d["manufacturer_data"].items()
        }
        return d


@dataclass
class GATTDescriptor:
    """A GATT characteristic descriptor."""

    uuid: str
    handle: int
    value: bytes | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if isinstance(d["value"], bytes):
            d["value"] = d["value"].hex()
        return d


@dataclass
class GATTCharacteristic:
    """A GATT service characteristic."""

    uuid: str
    handle: int
    properties: list[str] = field(default_factory=list)
    value: bytes | None = None
    value_decoded: str | None = None
    descriptors: list[GATTDescriptor] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if isinstance(d["value"], bytes):
            d["value"] = d["value"].hex()
        d["descriptors"] = [desc.to_dict() if isinstance(desc, GATTDescriptor) else desc
                            for desc in self.descriptors]
        return d


@dataclass
class GATTService:
    """A GATT service with its characteristics."""

    uuid: str
    description: str
    characteristics: list[GATTCharacteristic] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "uuid": self.uuid,
            "description": self.description,
            "characteristics": [c.to_dict() for c in self.characteristics],
        }


@dataclass
class DeviceProfile:
    """Full enumeration result for a BLE device."""

    device: BLEDevice
    services: list[GATTService] = field(default_factory=list)
    connection_successful: bool = False
    pairing_required: bool | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "device": self.device.to_dict(),
            "services": [s.to_dict() for s in self.services],
            "connection_successful": self.connection_successful,
            "pairing_required": self.pairing_required,
            "error": self.error,
        }


@dataclass
class SecurityFinding:
    """A single security finding from assessment."""

    finding_id: str
    severity: str                    # critical, high, medium, low, info
    category: str                    # encryption, authentication, data-exposure, configuration
    title: str
    description: str
    affected_characteristic: str | None = None
    affected_service: str | None = None
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AssessmentReport:
    """Complete security assessment report."""

    target: BLEDevice
    profile: DeviceProfile | None
    findings: list[SecurityFinding] = field(default_factory=list)
    risk_score: float = 0.0
    scan_time: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "profile": self.profile.to_dict() if self.profile else None,
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "scan_time": self.scan_time,
            "metadata": self.metadata,
        }
