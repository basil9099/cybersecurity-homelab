"""Demo subpackage — simulated BLE device data for hardware-free testing."""

from .demo_provider import generate_demo_scan, generate_demo_enumeration

__all__ = ["generate_demo_scan", "generate_demo_enumeration"]
