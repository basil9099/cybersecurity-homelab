"""
BLE Device Discovery
--------------------
Wraps bleak.BleakScanner to discover nearby BLE devices and convert
results into BLEDevice dataclass instances.
"""

from __future__ import annotations

import asyncio
import datetime
import fnmatch
from typing import Any, Callable

from models import BLEDevice
from config import Config

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice as BleakDevice
    from bleak.backends.scanner import AdvertisementData
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


class DeviceScanner:
    """Discover nearby BLE devices using bleak."""

    def __init__(self, config: Config):
        self.config = config

    def _resolve_manufacturer(self, company_id: int) -> str:
        """Resolve a Bluetooth SIG company ID to a name."""
        return self.config.company_ids.get(company_id, f"Unknown (0x{company_id:04X})")

    def _resolve_service(self, uuid: str) -> str:
        """Resolve a GATT service UUID to a human-readable name."""
        return self.config.standard_services.get(uuid.lower(), uuid)

    def _convert_device(
        self,
        device: Any,
        adv: Any,
        now_iso: str,
    ) -> BLEDevice:
        """Convert a bleak device + advertisement data into our model."""
        mfr_data: dict[int, bytes] = {}
        if hasattr(adv, "manufacturer_data") and adv.manufacturer_data:
            mfr_data = dict(adv.manufacturer_data)

        service_uuids = list(adv.service_uuids) if hasattr(adv, "service_uuids") else []
        tx_power = getattr(adv, "tx_power", None)

        # Determine address type from bleak details
        details = getattr(device, "details", {})
        address_type = "public"
        if isinstance(details, dict):
            props = details.get("props", {})
            addr_type = props.get("AddressType", "")
            if "random" in str(addr_type).lower():
                address_type = "random"

        return BLEDevice(
            address=device.address,
            name=device.name or adv.local_name,
            rssi=adv.rssi if hasattr(adv, "rssi") else -999,
            address_type=address_type,
            manufacturer_data=mfr_data,
            service_uuids=service_uuids,
            tx_power=tx_power,
            raw_advertisement={},
            first_seen=now_iso,
            last_seen=now_iso,
        )

    async def scan(
        self,
        duration: float | None = None,
        filter_name: str | None = None,
        filter_rssi: int | None = None,
    ) -> list[BLEDevice]:
        """Discover BLE devices for the given duration.

        Args:
            duration: Scan duration in seconds (default from config).
            filter_name: Glob pattern to match device names.
            filter_rssi: Minimum RSSI threshold.

        Returns:
            List of discovered BLEDevice instances.
        """
        if not BLEAK_AVAILABLE:
            raise RuntimeError(
                "bleak is not installed. Install with: pip install bleak"
            )

        duration = duration or self.config.scan.default_duration
        filter_rssi = filter_rssi if filter_rssi is not None else self.config.scan.default_rssi_threshold
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        scanner_kwargs: dict[str, Any] = {}
        if self.config.scan.adapter:
            scanner_kwargs["adapter"] = self.config.scan.adapter

        devices_and_advs = await BleakScanner.discover(
            timeout=duration,
            return_adv=True,
            **scanner_kwargs,
        )

        results: list[BLEDevice] = []
        for device, adv in devices_and_advs.values():
            ble_dev = self._convert_device(device, adv, now_iso)

            # Apply filters
            if filter_rssi is not None and ble_dev.rssi < filter_rssi:
                continue
            if filter_name and ble_dev.name:
                if not fnmatch.fnmatch(ble_dev.name, filter_name):
                    continue
            elif filter_name and not ble_dev.name:
                continue

            results.append(ble_dev)

        # Sort by RSSI (strongest first)
        results.sort(key=lambda d: d.rssi, reverse=True)
        return results

    async def continuous_scan(
        self,
        duration: float,
        callback: Callable[[BLEDevice], None],
        filter_rssi: int | None = None,
    ) -> list[BLEDevice]:
        """Scan continuously, calling back for each new device.

        Args:
            duration: Total scan duration in seconds.
            callback: Called with each newly discovered device.
            filter_rssi: Minimum RSSI threshold.

        Returns:
            List of all discovered devices.
        """
        if not BLEAK_AVAILABLE:
            raise RuntimeError("bleak is not installed.")

        filter_rssi = filter_rssi if filter_rssi is not None else self.config.scan.default_rssi_threshold
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        seen: dict[str, BLEDevice] = {}

        def _detection_callback(device: Any, adv: Any) -> None:
            if hasattr(adv, "rssi") and filter_rssi is not None and adv.rssi < filter_rssi:
                return
            if device.address not in seen:
                ble_dev = self._convert_device(device, adv, now_iso)
                seen[device.address] = ble_dev
                callback(ble_dev)
            else:
                seen[device.address].last_seen = datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat()

        scanner_kwargs: dict[str, Any] = {}
        if self.config.scan.adapter:
            scanner_kwargs["adapter"] = self.config.scan.adapter

        scanner = BleakScanner(
            detection_callback=_detection_callback,
            **scanner_kwargs,
        )
        await scanner.start()
        await asyncio.sleep(duration)
        await scanner.stop()

        return list(seen.values())
