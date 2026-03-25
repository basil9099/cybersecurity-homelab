"""
Demo Provider
-------------
Generates realistic simulated BLE device data for demo mode.
Provides six device archetypes covering the full range of security checks.
"""

from __future__ import annotations

import datetime

from models import (
    BLEDevice,
    DeviceProfile,
    GATTCharacteristic,
    GATTDescriptor,
    GATTService,
)


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


# ── Device Archetypes ────────────────────────────────────────────────────────


def _fitness_tracker() -> BLEDevice:
    return BLEDevice(
        address="AA:BB:CC:DD:EE:01",
        name="FitBand-Pro",
        rssi=-45,
        address_type="public",
        manufacturer_data={0x004C: b"\x02\x15\x01\x02\x03"},
        service_uuids=[
            "0000180d-0000-1000-8000-00805f9b34fb",  # Heart Rate
            "0000180f-0000-1000-8000-00805f9b34fb",  # Battery
            "0000180a-0000-1000-8000-00805f9b34fb",  # Device Info
        ],
        tx_power=-12,
        first_seen=_now_iso(),
        last_seen=_now_iso(),
    )


def _smart_lock() -> BLEDevice:
    return BLEDevice(
        address="AA:BB:CC:DD:EE:02",
        name="SmartLock-v3",
        rssi=-62,
        address_type="public",
        manufacturer_data={0x0059: b"\x01\x00\x03\x00"},
        service_uuids=[
            "0000fff0-0000-1000-8000-00805f9b34fb",  # Known vulnerable vendor
            "0000180a-0000-1000-8000-00805f9b34fb",  # Device Info
        ],
        tx_power=-8,
        first_seen=_now_iso(),
        last_seen=_now_iso(),
    )


def _medical_device() -> BLEDevice:
    return BLEDevice(
        address="AA:BB:CC:DD:EE:03",
        name="BP-Monitor-X200",
        rssi=-55,
        address_type="public",
        manufacturer_data={0x000D: b"\x04\x00\x01\x02"},
        service_uuids=[
            "00001810-0000-1000-8000-00805f9b34fb",  # Blood Pressure
            "0000180a-0000-1000-8000-00805f9b34fb",  # Device Info
            "0000180f-0000-1000-8000-00805f9b34fb",  # Battery
        ],
        tx_power=-10,
        first_seen=_now_iso(),
        last_seen=_now_iso(),
    )


def _ble_beacon() -> BLEDevice:
    return BLEDevice(
        address="AA:BB:CC:DD:EE:04",
        name=None,
        rssi=-78,
        address_type="public",
        manufacturer_data={0x004C: b"\x02\x15" + b"\xAA" * 16 + b"\x00\x01\x00\x02\xC5"},
        service_uuids=[],
        tx_power=-59,
        first_seen=_now_iso(),
        last_seen=_now_iso(),
    )


def _smart_bulb() -> BLEDevice:
    return BLEDevice(
        address="AA:BB:CC:DD:EE:05",
        name="SmartBulb-RGB",
        rssi=-70,
        address_type="public",
        manufacturer_data={0x010F: b"\x95\xFE\x01\x02"},
        service_uuids=[
            "0000fee7-0000-1000-8000-00805f9b34fb",  # Known vulnerable
            "0000fff0-0000-1000-8000-00805f9b34fb",  # Vendor custom
        ],
        tx_power=-15,
        first_seen=_now_iso(),
        last_seen=_now_iso(),
    )


def _secure_device() -> BLEDevice:
    return BLEDevice(
        address="11:22:33:44:55:66",
        name="SecureTag-Pro",
        rssi=-50,
        address_type="random",
        manufacturer_data={0x0059: b"\x02\x01\x06"},
        service_uuids=[
            "00001800-0000-1000-8000-00805f9b34fb",  # Generic Access
        ],
        tx_power=-4,
        first_seen=_now_iso(),
        last_seen=_now_iso(),
    )


# ── Scan Results ─────────────────────────────────────────────────────────────


def generate_demo_scan() -> list[BLEDevice]:
    """Generate a list of simulated BLE devices for scan demo."""
    return [
        _fitness_tracker(),
        _smart_lock(),
        _medical_device(),
        _ble_beacon(),
        _smart_bulb(),
        _secure_device(),
    ]


# ── Enumeration Profiles ────────────────────────────────────────────────────


def _fitness_tracker_profile() -> DeviceProfile:
    return DeviceProfile(
        device=_fitness_tracker(),
        connection_successful=True,
        pairing_required=False,
        services=[
            GATTService(
                uuid="0000180d-0000-1000-8000-00805f9b34fb",
                description="Heart Rate",
                characteristics=[
                    GATTCharacteristic(
                        uuid="00002a37-0000-1000-8000-00805f9b34fb",
                        handle=14,
                        properties=["notify"],
                        value=None,
                        value_decoded=None,
                        descriptors=[
                            GATTDescriptor(
                                uuid="00002902-0000-1000-8000-00805f9b34fb",
                                handle=15,
                            ),
                        ],
                    ),
                    GATTCharacteristic(
                        uuid="00002a38-0000-1000-8000-00805f9b34fb",
                        handle=17,
                        properties=["read"],
                        value=b"\x01",
                        value_decoded="Heart Rate Sensor",
                    ),
                ],
            ),
            GATTService(
                uuid="0000180f-0000-1000-8000-00805f9b34fb",
                description="Battery Service",
                characteristics=[
                    GATTCharacteristic(
                        uuid="00002a19-0000-1000-8000-00805f9b34fb",
                        handle=20,
                        properties=["read", "notify"],
                        value=b"\x4b",
                        value_decoded="75",
                    ),
                ],
            ),
            GATTService(
                uuid="0000180a-0000-1000-8000-00805f9b34fb",
                description="Device Information",
                characteristics=[
                    GATTCharacteristic(
                        uuid="00002a29-0000-1000-8000-00805f9b34fb",
                        handle=23,
                        properties=["read"],
                        value=b"FitTech Inc.",
                        value_decoded="FitTech Inc.",
                    ),
                    GATTCharacteristic(
                        uuid="00002a24-0000-1000-8000-00805f9b34fb",
                        handle=25,
                        properties=["read"],
                        value=b"FitBand-Pro v2.3",
                        value_decoded="FitBand-Pro v2.3",
                    ),
                    GATTCharacteristic(
                        uuid="00002a26-0000-1000-8000-00805f9b34fb",
                        handle=27,
                        properties=["read"],
                        value=b"1.4.2",
                        value_decoded="1.4.2",
                    ),
                    GATTCharacteristic(
                        uuid="00002a25-0000-1000-8000-00805f9b34fb",
                        handle=29,
                        properties=["read"],
                        value=b"SN-2024-08-12345",
                        value_decoded="SN-2024-08-12345",
                    ),
                ],
            ),
        ],
    )


def _smart_lock_profile() -> DeviceProfile:
    return DeviceProfile(
        device=_smart_lock(),
        connection_successful=True,
        pairing_required=False,
        services=[
            GATTService(
                uuid="0000fff0-0000-1000-8000-00805f9b34fb",
                description="Common vendor custom base",
                characteristics=[
                    GATTCharacteristic(
                        uuid="0000fff1-0000-1000-8000-00805f9b34fb",
                        handle=10,
                        properties=["read", "write"],
                        value=b"\x00",
                        value_decoded="Lock Status: Locked",
                    ),
                    GATTCharacteristic(
                        uuid="0000fff2-0000-1000-8000-00805f9b34fb",
                        handle=12,
                        properties=["write-without-response"],
                        value=None,
                        value_decoded=None,
                    ),
                    GATTCharacteristic(
                        uuid="0000fff3-0000-1000-8000-00805f9b34fb",
                        handle=14,
                        properties=["read", "notify"],
                        value=b"admin@smartlock.local",
                        value_decoded="admin@smartlock.local",
                    ),
                ],
            ),
            GATTService(
                uuid="0000180a-0000-1000-8000-00805f9b34fb",
                description="Device Information",
                characteristics=[
                    GATTCharacteristic(
                        uuid="00002a29-0000-1000-8000-00805f9b34fb",
                        handle=20,
                        properties=["read"],
                        value=b"LockCorp",
                        value_decoded="LockCorp",
                    ),
                    GATTCharacteristic(
                        uuid="00002a26-0000-1000-8000-00805f9b34fb",
                        handle=22,
                        properties=["read"],
                        value=b"3.0.1",
                        value_decoded="3.0.1",
                    ),
                ],
            ),
        ],
    )


def _medical_device_profile() -> DeviceProfile:
    return DeviceProfile(
        device=_medical_device(),
        connection_successful=True,
        pairing_required=False,
        services=[
            GATTService(
                uuid="00001810-0000-1000-8000-00805f9b34fb",
                description="Blood Pressure",
                characteristics=[
                    GATTCharacteristic(
                        uuid="00002a35-0000-1000-8000-00805f9b34fb",
                        handle=10,
                        properties=["indicate"],
                        value=None,
                        descriptors=[
                            GATTDescriptor(uuid="00002902-0000-1000-8000-00805f9b34fb", handle=11),
                        ],
                    ),
                    GATTCharacteristic(
                        uuid="00002a49-0000-1000-8000-00805f9b34fb",
                        handle=13,
                        properties=["read"],
                        value=b"\x04\x00",
                        value_decoded="Blood Pressure Feature",
                    ),
                ],
            ),
            GATTService(
                uuid="0000180a-0000-1000-8000-00805f9b34fb",
                description="Device Information",
                characteristics=[
                    GATTCharacteristic(
                        uuid="00002a29-0000-1000-8000-00805f9b34fb",
                        handle=20,
                        properties=["read"],
                        value=b"MedTech Ltd",
                        value_decoded="MedTech Ltd",
                    ),
                    GATTCharacteristic(
                        uuid="00002a25-0000-1000-8000-00805f9b34fb",
                        handle=22,
                        properties=["read"],
                        value=b"MT-BP-2024-78901",
                        value_decoded="MT-BP-2024-78901",
                    ),
                ],
            ),
            GATTService(
                uuid="0000180f-0000-1000-8000-00805f9b34fb",
                description="Battery Service",
                characteristics=[
                    GATTCharacteristic(
                        uuid="00002a19-0000-1000-8000-00805f9b34fb",
                        handle=30,
                        properties=["read", "notify"],
                        value=b"\x5a",
                        value_decoded="90",
                    ),
                ],
            ),
        ],
    )


def _smart_bulb_profile() -> DeviceProfile:
    return DeviceProfile(
        device=_smart_bulb(),
        connection_successful=True,
        pairing_required=False,
        services=[
            GATTService(
                uuid="0000fee7-0000-1000-8000-00805f9b34fb",
                description="Tencent Holdings Limited",
                characteristics=[
                    GATTCharacteristic(
                        uuid="0000fec7-0000-1000-8000-00805f9b34fb",
                        handle=10,
                        properties=["read", "write"],
                        value=b"\x01\xFF\x80\x00",
                        value_decoded=None,
                    ),
                ],
            ),
            GATTService(
                uuid="0000fff0-0000-1000-8000-00805f9b34fb",
                description="Common vendor custom base",
                characteristics=[
                    GATTCharacteristic(
                        uuid="0000fff1-0000-1000-8000-00805f9b34fb",
                        handle=15,
                        properties=["read", "write-without-response"],
                        value=b"\xFF\x00\x80",
                        value_decoded=None,
                    ),
                    GATTCharacteristic(
                        uuid="0000fff2-0000-1000-8000-00805f9b34fb",
                        handle=17,
                        properties=["read", "write", "notify"],
                        value=b"\x64",
                        value_decoded="100",
                    ),
                ],
            ),
        ],
    )


def _secure_device_profile() -> DeviceProfile:
    return DeviceProfile(
        device=_secure_device(),
        connection_successful=True,
        pairing_required=True,
        error="BleakError: pairing required - device requested authentication",
        services=[],
    )


# ── Public API ───────────────────────────────────────────────────────────────

_PROFILE_MAP: dict[str, callable] = {
    "AA:BB:CC:DD:EE:01": _fitness_tracker_profile,
    "AA:BB:CC:DD:EE:02": _smart_lock_profile,
    "AA:BB:CC:DD:EE:03": _medical_device_profile,
    "AA:BB:CC:DD:EE:05": _smart_bulb_profile,
    "11:22:33:44:55:66": _secure_device_profile,
}


def generate_demo_enumeration(address: str) -> DeviceProfile | None:
    """Generate a simulated GATT profile for a demo device.

    Args:
        address: The device address to look up.

    Returns:
        A DeviceProfile if the address matches a demo device, else None.
    """
    factory = _PROFILE_MAP.get(address.upper())
    if factory:
        return factory()
    return None
