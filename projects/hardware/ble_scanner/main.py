#!/usr/bin/env python3
"""
PHANTOM — BLE Security Scanner & Analyzer
==========================================
A Bluetooth Low Energy security assessment tool that discovers nearby
devices, enumerates GATT services, and identifies security misconfigurations.

Usage:
    python main.py scan --demo
    python main.py enumerate --demo --target AA:BB:CC:DD:EE:02
    python main.py assess --demo --target AA:BB:CC:DD:EE:02
    python main.py report --input phantom_report.json

WARNING: Only scan and assess BLE devices you own or have explicit permission to test.
Unauthorized access to wireless devices may violate local laws.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime
import json
import os
import random
import sys

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False

from config import load_config, Config
from models import AssessmentReport


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

VERSION = "1.0.0"

BANNER_ART = r"""
 ____  _   _    _    _   _ _____ ___  __  __
|  _ \| | | |  / \  | \ | |_   _/ _ \|  \/  |
| |_) | |_| | / _ \ |  \| | | || | | | |\/| |
|  __/|  _  |/ ___ \| |\  | | || |_| | |  | |
|_|   |_| |_/_/   \_\_| \_| |_| \___/|_|  |_|
"""

TAGLINES = [
    "Your devices, your responsibility.",
    "Every beacon tells a story.",
    "Not all that pairs is secure.",
    "Trust but verify your BLE posture.",
    "The airwaves remember everything.",
    "GATT your back.",
]


def print_banner() -> None:
    print(c(BANNER_ART, Fore.CYAN if COLORS else ""))
    print(c(f"       v{VERSION} — BLE Security Scanner & Analyzer", Style.BRIGHT if COLORS else ""))
    print()
    print(c(f'  "{random.choice(TAGLINES)}"', Fore.YELLOW if COLORS else ""))
    print()
    print(c("  [ BLE Discovery | GATT Enumeration | Security Assessment ]", Fore.CYAN if COLORS else ""))
    print(c("  For authorized security assessments only.", Style.DIM if COLORS else ""))
    print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def c(text: str, color: str) -> str:
    if not COLORS:
        return text
    return f"{color}{text}{Style.RESET_ALL}"


def info(msg: str) -> None:
    print(c("[*]", Fore.CYAN) + f" {msg}")


def success(msg: str) -> None:
    print(c("[+]", Fore.GREEN) + f" {msg}")


def warn(msg: str) -> None:
    print(c("[!]", Fore.YELLOW) + f" {msg}")


def error(msg: str) -> None:
    print(c("[-]", Fore.RED) + f" {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Subcommand Handlers
# ---------------------------------------------------------------------------

async def cmd_scan(args: argparse.Namespace, config: Config) -> int:
    """Discover nearby BLE devices."""
    from reporter import ReportGenerator

    if args.demo:
        from demo import generate_demo_scan

        info("Running in DEMO mode — generating simulated BLE devices...")
        devices = generate_demo_scan()
        success(f"Found {len(devices)} devices (simulated)")
    else:
        from scanner import DeviceScanner

        scanner = DeviceScanner(config)
        duration = args.duration or config.scan.default_duration
        info(f"Scanning for BLE devices ({duration}s) ...")

        try:
            if args.continuous:
                def on_device(dev):
                    name = dev.name or "[Unknown]"
                    mfr = "—"
                    if dev.manufacturer_data:
                        first_id = next(iter(dev.manufacturer_data))
                        mfr = config.company_ids.get(first_id, f"0x{first_id:04X}")
                    print(f"  {c('[+]', Fore.GREEN if COLORS else '')} "
                          f"{dev.address}  {name:<24} RSSI:{dev.rssi}  {mfr}")

                devices = await scanner.continuous_scan(
                    duration=duration,
                    callback=on_device,
                    filter_rssi=args.filter_rssi,
                )
            else:
                devices = await scanner.scan(
                    duration=duration,
                    filter_name=args.filter_name,
                    filter_rssi=args.filter_rssi,
                )
        except RuntimeError as exc:
            error(str(exc))
            warn("Use --demo for simulation mode without BLE hardware.")
            return 1
        except Exception as exc:
            error(f"Scan failed: {exc}")
            warn("Ensure Bluetooth is enabled or use --demo for simulation mode.")
            return 1

        success(f"Found {len(devices)} devices")

    print()
    fmt = args.format if hasattr(args, "format") and args.format else "table"

    if fmt == "table":
        table = ReportGenerator.format_scan_table(devices, config)
        print(table)
    elif fmt == "json":
        reporter = ReportGenerator(args.output_dir)
        path = reporter.generate_scan_json(devices)
        success(f"JSON scan results saved → {path}")
    elif fmt == "jsonl":
        for dev in devices:
            print(json.dumps(dev.to_dict(), default=str))

    print()
    return 0


async def cmd_enumerate(args: argparse.Namespace, config: Config) -> int:
    """Connect to a device and enumerate GATT services."""
    from reporter import ReportGenerator

    if not args.target:
        error("Target device address required (--target)")
        return 1

    if args.demo:
        from demo import generate_demo_enumeration

        info(f"Running in DEMO mode — enumerating simulated device {args.target}...")
        profile = generate_demo_enumeration(args.target)
        if profile is None:
            error(f"No demo device found for address {args.target}")
            info("Available demo addresses: AA:BB:CC:DD:EE:01 through AA:BB:CC:DD:EE:05, 11:22:33:44:55:66")
            return 1
    else:
        from scanner import ServiceEnumerator
        from models import BLEDevice

        enumerator = ServiceEnumerator(config)
        target_device = BLEDevice(
            address=args.target,
            name=None,
            rssi=0,
            address_type="unknown",
        )

        info(f"Connecting to {args.target} ...")
        try:
            profile = await enumerator.enumerate(
                device=target_device,
                timeout=args.timeout or config.scan.connection_timeout,
                read_all=args.read_all,
            )
        except RuntimeError as exc:
            error(str(exc))
            return 1
        except Exception as exc:
            error(f"Enumeration failed: {exc}")
            return 1

    if profile.connection_successful:
        success(f"Connected — {len(profile.services)} services discovered")
    elif profile.error:
        warn(f"Connection issue: {profile.error}")

    print()
    fmt = args.format if hasattr(args, "format") and args.format else "tree"

    if fmt == "tree":
        tree = ReportGenerator.format_enumeration_tree(profile)
        print(tree)
    elif fmt == "json":
        print(json.dumps(profile.to_dict(), indent=2, default=str))

    print()
    return 0


async def cmd_assess(args: argparse.Namespace, config: Config) -> int:
    """Run security assessment against a target device."""
    from assessor import SecurityAssessor
    from reporter import ReportGenerator

    if not args.target:
        error("Target device address required (--target)")
        return 1

    scan_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if args.demo:
        from demo import generate_demo_enumeration

        info(f"Running in DEMO mode — assessing simulated device {args.target}...")
        profile = generate_demo_enumeration(args.target)
        if profile is None:
            error(f"No demo device found for address {args.target}")
            info("Available demo addresses: AA:BB:CC:DD:EE:01 through AA:BB:CC:DD:EE:05, 11:22:33:44:55:66")
            return 1
    else:
        from scanner import ServiceEnumerator
        from models import BLEDevice

        enumerator = ServiceEnumerator(config)
        target_device = BLEDevice(
            address=args.target,
            name=None,
            rssi=0,
            address_type="unknown",
        )

        info(f"Connecting to {args.target} for enumeration ...")
        try:
            profile = await enumerator.enumerate(
                device=target_device,
                timeout=args.timeout or config.scan.connection_timeout,
                read_all=True,
            )
        except RuntimeError as exc:
            error(str(exc))
            return 1
        except Exception as exc:
            error(f"Enumeration failed: {exc}")
            return 1

    # Run assessment
    assessor = SecurityAssessor(config)
    report = assessor.full_assessment(profile, scan_time=scan_time)

    # Filter by severity if requested
    if args.severity:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        threshold = sev_order.get(args.severity, 4)
        report.findings = [
            f for f in report.findings
            if sev_order.get(f.severity, 4) <= threshold
        ]
        report.risk_score = assessor.compute_risk_score(report.findings)

    success(f"Assessment complete — {len(report.findings)} finding(s)")
    print()

    fmt = args.format if hasattr(args, "format") and args.format else "all"

    if fmt in ("terminal", "all"):
        summary = ReportGenerator.format_assessment_summary(report)
        print(summary)

    if fmt in ("json", "all"):
        reporter = ReportGenerator(args.output_dir)
        path = reporter.generate_json(report)
        print()
        success(f"JSON report saved → {path}")

        jsonl_path = reporter.generate_jsonl(report.findings)
        success(f"JSONL findings saved → {jsonl_path}")

    print()
    return 0


async def cmd_report(args: argparse.Namespace, config: Config) -> int:
    """Generate report from saved scan/assessment data."""
    from reporter import ReportGenerator

    if not args.input:
        error("Input file required (--input)")
        return 1

    if not os.path.isfile(args.input):
        error(f"File not found: {args.input}")
        return 1

    info(f"Loading data from {args.input} ...")

    with open(args.input, "r") as f:
        data = json.load(f)

    # Reconstruct report from JSON
    from models import BLEDevice, SecurityFinding

    target = BLEDevice(**{
        k: v for k, v in data.get("target", {}).items()
        if k in BLEDevice.__dataclass_fields__
    })

    findings = []
    for fd in data.get("findings", []):
        findings.append(SecurityFinding(**{
            k: v for k, v in fd.items()
            if k in SecurityFinding.__dataclass_fields__
        }))

    report = AssessmentReport(
        target=target,
        profile=None,
        findings=findings,
        risk_score=data.get("risk_score", 0.0),
        scan_time=data.get("scan_time", ""),
        metadata=data.get("metadata", {}),
    )

    print()
    fmt = args.format if hasattr(args, "format") and args.format else "all"

    if fmt in ("terminal", "all"):
        summary = ReportGenerator.format_assessment_summary(report)
        print(summary)

    if fmt in ("json", "all"):
        reporter = ReportGenerator(args.output_dir)
        path = reporter.generate_json(report, "phantom_report_regenerated.json")
        print()
        success(f"JSON report saved → {path}")

    print()
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _demo_parent() -> argparse.ArgumentParser:
    """Shared parent parser for --demo flag on subcommands."""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--demo", action="store_true",
                   help="Run in simulation mode (no BLE hardware needed)")
    return p


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phantom",
        description="PHANTOM — BLE Security Scanner & Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py scan --demo
  python main.py scan --duration 15 --filter-rssi -70
  python main.py enumerate --demo --target AA:BB:CC:DD:EE:02
  python main.py assess --demo --target AA:BB:CC:DD:EE:02
  python main.py assess --target AA:BB:CC:DD:EE:FF --severity high
  python main.py report --input phantom_report.json
        """,
    )

    # Global options
    parser.add_argument("--config", default=None, metavar="PATH",
                        help="Path to config.yaml (default: ./config.yaml)")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose/debug output")
    parser.add_argument("--output-dir", default="./output", metavar="DIR",
                        help="Output directory for reports and logs (default: ./output)")

    sub = parser.add_subparsers(dest="command", required=True)

    # ── scan ──────────────────────────────────────────────────────────────
    p_scan = sub.add_parser("scan", help="Discover nearby BLE devices",
                            parents=[_demo_parent()])
    p_scan.add_argument("--duration", type=float, default=None,
                        help="Scan duration in seconds (default: 10)")
    p_scan.add_argument("--filter-name", default=None, metavar="PAT",
                        help="Filter devices by name pattern (glob)")
    p_scan.add_argument("--filter-rssi", type=int, default=None,
                        help="Minimum RSSI threshold (default: -90)")
    p_scan.add_argument("--continuous", action="store_true",
                        help="Continuous scan with live display")
    p_scan.add_argument("--format", default="table", choices=["table", "json", "jsonl"],
                        help="Output format (default: table)")

    # ── enumerate ─────────────────────────────────────────────────────────
    p_enum = sub.add_parser("enumerate", help="Enumerate GATT services on a device",
                            parents=[_demo_parent()])
    p_enum.add_argument("--target", required=True, metavar="ADDR",
                        help="Target device address (MAC or UUID)")
    p_enum.add_argument("--timeout", type=float, default=None,
                        help="Connection timeout in seconds (default: 10)")
    p_enum.add_argument("--read-all", action="store_true",
                        help="Attempt to read all readable characteristics")
    p_enum.add_argument("--format", default="tree", choices=["tree", "json"],
                        help="Output format (default: tree)")

    # ── assess ────────────────────────────────────────────────────────────
    p_assess = sub.add_parser("assess", help="Run security assessment against a device",
                              parents=[_demo_parent()])
    p_assess.add_argument("--target", required=True, metavar="ADDR",
                          help="Target device address (MAC or UUID)")
    p_assess.add_argument("--timeout", type=float, default=None,
                          help="Connection timeout in seconds (default: 10)")
    p_assess.add_argument("--severity", default=None,
                          choices=["critical", "high", "medium", "low", "info"],
                          help="Minimum severity to report (default: all)")
    p_assess.add_argument("--format", default="all", choices=["terminal", "json", "all"],
                          help="Report format (default: all)")

    # ── report ────────────────────────────────────────────────────────────
    p_report = sub.add_parser("report", help="Generate report from saved data")
    p_report.add_argument("--input", metavar="PATH",
                          help="Input JSON from previous scan/assess")
    p_report.add_argument("--format", default="all", choices=["terminal", "json", "all"],
                          help="Report format (default: all)")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    print_banner()

    # Load configuration
    config = load_config(args.config)

    # Ensure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)

    # Print run configuration
    is_demo = getattr(args, "demo", False)
    print(c(f"  Mode      : {'DEMO (simulated)' if is_demo else 'LIVE'}", Fore.WHITE if COLORS else ""))
    print(c(f"  Command   : {args.command}", Fore.WHITE if COLORS else ""))
    print(c(f"  Output    : {args.output_dir}/", Fore.WHITE if COLORS else ""))
    print()

    dispatch = {
        "scan": cmd_scan,
        "enumerate": cmd_enumerate,
        "assess": cmd_assess,
        "report": cmd_report,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return asyncio.run(handler(args, config))
    except KeyboardInterrupt:
        print()
        info("Interrupted — exiting.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
