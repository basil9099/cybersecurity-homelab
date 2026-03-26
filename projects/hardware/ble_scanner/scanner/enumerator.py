"""
GATT Service Enumerator
-----------------------
Connects to a BLE device via BleakClient and walks all
services, characteristics, and descriptors.
"""

from __future__ import annotations

from typing import Any

from models import BLEDevice, DeviceProfile, GATTService, GATTCharacteristic, GATTDescriptor
from config import Config

try:
    from bleak import BleakClient
    from bleak.exc import BleakError
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


class ServiceEnumerator:
    """Enumerate GATT services on a connected BLE device."""

    def __init__(self, config: Config):
        self.config = config

    def _resolve_service_name(self, uuid: str) -> str:
        """Map a service UUID to its human-readable name."""
        return self.config.standard_services.get(uuid.lower(), "Unknown Service")

    async def enumerate(
        self,
        device: BLEDevice,
        timeout: float | None = None,
        read_all: bool = False,
    ) -> DeviceProfile:
        """Connect to a device and enumerate all GATT services.

        Args:
            device: The target BLE device.
            timeout: Connection timeout in seconds.
            read_all: If True, attempt to read all readable characteristics.

        Returns:
            A DeviceProfile with the enumeration results.
        """
        if not BLEAK_AVAILABLE:
            raise RuntimeError(
                "bleak is not installed. Install with: pip install bleak"
            )

        timeout = timeout or self.config.scan.connection_timeout
        profile = DeviceProfile(device=device)

        try:
            async with BleakClient(
                device.address,
                timeout=timeout,
            ) as client:
                profile.connection_successful = client.is_connected
                if not client.is_connected:
                    profile.error = "Connection established but client reports not connected"
                    return profile

                # No pairing prompt was required to get here
                profile.pairing_required = False

                for service in client.services:
                    gatt_chars: list[GATTCharacteristic] = []

                    for char in service.characteristics:
                        props = [p.lower() for p in char.properties]

                        # Attempt to read value
                        value = None
                        value_decoded = None
                        if read_all and "read" in props:
                            try:
                                value = await client.read_gatt_char(char)
                                try:
                                    value_decoded = value.decode("utf-8", errors="replace")
                                except Exception:
                                    pass
                            except Exception:
                                pass

                        # Enumerate descriptors
                        descs: list[GATTDescriptor] = []
                        for desc in char.descriptors:
                            desc_value = None
                            if read_all:
                                try:
                                    desc_value = await client.read_gatt_descriptor(desc.handle)
                                except Exception:
                                    pass
                            descs.append(GATTDescriptor(
                                uuid=str(desc.uuid),
                                handle=desc.handle,
                                value=desc_value,
                            ))

                        gatt_chars.append(GATTCharacteristic(
                            uuid=str(char.uuid),
                            handle=char.handle,
                            properties=props,
                            value=value,
                            value_decoded=value_decoded,
                            descriptors=descs,
                        ))

                    profile.services.append(GATTService(
                        uuid=str(service.uuid),
                        description=self._resolve_service_name(str(service.uuid)),
                        characteristics=gatt_chars,
                    ))

        except (BleakError, OSError, TimeoutError) as exc:
            profile.error = f"{type(exc).__name__}: {exc}"
            if "pairing" in str(exc).lower() or "authentication" in str(exc).lower():
                profile.pairing_required = True

        return profile
