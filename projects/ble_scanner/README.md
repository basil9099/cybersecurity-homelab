# PHANTOM — BLE Security Scanner & Analyzer

**PH**ysical **AN**alysis **TO**ol for co**M**munications

A Bluetooth Low Energy (BLE) security assessment tool for discovering nearby
devices, enumerating GATT services/characteristics, and identifying security
misconfigurations. Part of the cybersecurity homelab toolkit.

```
 ____  _   _    _    _   _ _____ ___  __  __
|  _ \| | | |  / \  | \ | |_   _/ _ \|  \/  |
| |_) | |_| | / _ \ |  \| | | || | | | |\/| |
|  __/|  _  |/ ___ \| |\  | | || |_| | |  | |
|_|   |_| |_/_/   \_\_| \_| |_| \___/|_|  |_|
```

## Features

- **Device Discovery** — Scan for nearby BLE devices with filtering by name/RSSI
- **GATT Enumeration** — Connect and walk all services, characteristics, and descriptors
- **Security Assessment** — 10 automated checks covering authentication, data exposure, privacy, and configuration
- **Demo Mode** — Full simulation with 6 device archetypes, no BLE hardware needed
- **Multiple Output Formats** — Terminal tables/trees, JSON reports, JSONL structured logs

## Requirements

- Python 3.10+
- Bluetooth adapter (for live scanning; not needed in demo mode)
- Linux, macOS, or Windows

```bash
pip install -r requirements.txt
```

## Quick Start

```bash
# Demo mode — no hardware needed
python main.py scan --demo
python main.py enumerate --demo --target AA:BB:CC:DD:EE:02
python main.py assess --demo --target AA:BB:CC:DD:EE:02

# Live scanning (requires Bluetooth adapter)
python main.py scan --duration 15
python main.py enumerate --target AA:BB:CC:DD:EE:FF --read-all
python main.py assess --target AA:BB:CC:DD:EE:FF --severity high
```

## Commands

### `scan` — Discover BLE Devices

```
python main.py scan [--duration SEC] [--filter-name PAT] [--filter-rssi N]
                     [--continuous] [--format table|json|jsonl] [--demo]
```

### `enumerate` — GATT Service Enumeration

```
python main.py enumerate --target ADDR [--timeout SEC] [--read-all]
                          [--format tree|json] [--demo]
```

### `assess` — Security Assessment

```
python main.py assess --target ADDR [--timeout SEC] [--severity LEVEL]
                       [--format terminal|json|all] [--demo]
```

### `report` — Regenerate Reports

```
python main.py report --input PATH [--format terminal|json|all]
```

## Security Checks

| ID | Severity | Check |
|---|---|---|
| BLE-AUTH-001 | HIGH | No pairing required for full GATT access |
| BLE-AUTH-002 | MEDIUM | Just Works pairing (no MITM protection) |
| BLE-CHAR-001 | HIGH | Writable characteristic without authentication |
| BLE-CHAR-002 | MEDIUM | Sensitive data in readable characteristics |
| BLE-CHAR-003 | LOW | Device Information Service exposed |
| BLE-VULN-001 | HIGH | Known vulnerable service UUID |
| BLE-VULN-002 | MEDIUM | Legacy BLE 4.0/4.1 indicators |
| BLE-PRIV-001 | MEDIUM | Static public MAC address (tracking risk) |
| BLE-CONF-001 | MEDIUM | Excessive characteristic permissions |
| BLE-CONF-002 | LOW | Notifications without encryption |

## Demo Devices

| Address | Name | Archetype |
|---|---|---|
| AA:BB:CC:DD:EE:01 | FitBand-Pro | Fitness tracker with exposed health data |
| AA:BB:CC:DD:EE:02 | SmartLock-v3 | Insecure smart lock (writable, no auth) |
| AA:BB:CC:DD:EE:03 | BP-Monitor-X200 | Medical device with data exposure |
| AA:BB:CC:DD:EE:04 | [Beacon] | BLE beacon with static MAC |
| AA:BB:CC:DD:EE:05 | SmartBulb-RGB | Smart bulb with known vulnerable UUIDs |
| 11:22:33:44:55:66 | SecureTag-Pro | Properly secured reference device |

## Architecture

```
main.py              CLI entry point (async-aware argparse)
config.py            YAML configuration loader with defaults
models.py            All dataclasses (BLEDevice, GATTService, etc.)
scanner/
  discovery.py       BLE device discovery (bleak BleakScanner)
  enumerator.py      GATT service enumeration (bleak BleakClient)
assessor/
  rules.py           Assessment engine (introspective check dispatch)
  checks.py          Individual check_* implementations
reporter/
  report_generator.py  JSON, JSONL, and terminal formatters
demo/
  demo_provider.py   Simulated device data (6 archetypes)
```

## Legal Disclaimer

This tool is provided for **authorized security testing and educational purposes only**.

- Only scan and assess BLE devices you own or have explicit written permission to test
- Unauthorized access to wireless devices may violate local, state, and federal laws
- The authors assume no liability for misuse of this tool
- Always comply with applicable laws and regulations in your jurisdiction
