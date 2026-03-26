#!/usr/bin/env python3
"""WATCHTOWER -- Threat Intelligence Feed Aggregator.

Main entry point with CLI supporting fetch, correlate, dashboard, and demo modes.

Usage:
    python main.py demo          Full demonstration with mock data
    python main.py fetch         Fetch indicators from all configured feeds
    python main.py correlate     Correlate local logs against IOC database
    python main.py dashboard     Display the terminal dashboard
    python main.py check <IOC>   Look up a single IOC across all feeds
    python main.py report        Generate an HTML threat report
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# Ensure project root is on sys.path so subpackage imports work when
# running as ``python main.py`` from within the project directory.
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from rich.console import Console

from correlation.correlator import Correlator
from correlation.ioc_database import IOCDatabase
from dashboard.html_report import HTMLReportGenerator
from dashboard.terminal_dashboard import TerminalDashboard
from feeds.feed_manager import FeedManager
from models.enrichment import EnrichmentResult

logger = logging.getLogger("watchtower")
console = Console()

# Default paths
DEFAULT_DB_PATH = _PROJECT_ROOT / "data" / "ioc_database.sqlite"
DEFAULT_LOG_DIR = _PROJECT_ROOT / "data" / "logs"


# ======================================================================
# CLI argument parsing
# ======================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="watchtower",
        description="WATCHTOWER -- Threat Intelligence Feed Aggregator",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--db",
        type=str,
        default=str(DEFAULT_DB_PATH),
        help="Path to the SQLite IOC database",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Force demo mode (mock data, no API keys required)",
    )

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # demo
    sub.add_parser("demo", help="Run a full demonstration with mock data")

    # fetch
    fetch_p = sub.add_parser("fetch", help="Fetch IOCs from all feeds")
    fetch_p.add_argument(
        "--limit", type=int, default=100, help="Max indicators per feed"
    )

    # correlate
    corr_p = sub.add_parser("correlate", help="Correlate logs against IOC database")
    corr_p.add_argument(
        "--log-file", type=str, default=None,
        help="Path to a JSONL log file to correlate",
    )

    # dashboard
    sub.add_parser("dashboard", help="Render the terminal dashboard")

    # check
    check_p = sub.add_parser("check", help="Look up a single IOC")
    check_p.add_argument("ioc", type=str, help="IP, domain, URL, or hash to check")

    # report
    report_p = sub.add_parser("report", help="Generate an HTML report")
    report_p.add_argument(
        "--output", type=str, default="watchtower_report.html",
        help="Output file path",
    )

    return parser


# ======================================================================
# Command implementations
# ======================================================================

def _load_api_keys() -> dict[str, str]:
    """Read API keys from environment variables."""
    keys: dict[str, str] = {}
    mapping = {
        "ABUSEIPDB_API_KEY": "abuseipdb",
        "OTX_API_KEY": "alienvault_otx",
        "URLHAUS_API_KEY": "urlhaus",
    }
    for env_var, feed_name in mapping.items():
        val = os.environ.get(env_var)
        if val:
            keys[feed_name] = val
    return keys


def cmd_demo(args: argparse.Namespace) -> None:
    """Run a full demo: fetch mock data, correlate sample logs, show dashboard."""
    console.print("[bold cyan]WATCHTOWER Demo Mode[/bold cyan]\n")

    # 1. Initialize
    console.print("[dim]Initializing IOC database (in-memory)...[/dim]")
    db = IOCDatabase(":memory:")
    manager = FeedManager(demo_mode=True)

    # 2. Fetch
    console.print("[dim]Fetching indicators from mock feeds...[/dim]")
    indicators = manager.fetch_all(limit_per_feed=100)
    count = db.upsert_many(indicators)
    console.print(f"  Stored [bold]{count}[/bold] indicators in database.\n")

    # 3. Correlate
    console.print("[dim]Correlating sample logs against IOC database...[/dim]")
    from demo.sample_logs import SAMPLE_HONEYPOT_LOGS, SAMPLE_NETWORK_LOGS

    correlator = Correlator(db)
    all_events = SAMPLE_HONEYPOT_LOGS + SAMPLE_NETWORK_LOGS
    results = correlator.correlate_events(all_events)
    console.print(
        f"  Found [bold red]{len(results)}[/bold red] correlation hits "
        f"out of {len(all_events)} log events.\n"
    )

    # 4. Dashboard
    dashboard = TerminalDashboard(console=console)
    dashboard.render(db, results, manager.health_report())

    # 5. HTML report
    report_path = HTMLReportGenerator().generate(
        db, results, manager.health_report(),
        output_path=_PROJECT_ROOT / "watchtower_demo_report.html",
    )
    console.print(f"\n[green]HTML report written to:[/green] {report_path}")

    db.close()


def cmd_fetch(args: argparse.Namespace) -> None:
    """Fetch indicators from all feeds and store in the database."""
    demo = args.demo or not _load_api_keys()
    if demo:
        console.print("[yellow]No API keys found -- using demo mode.[/yellow]\n")

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = IOCDatabase(db_path)

    manager = FeedManager(
        api_keys=_load_api_keys(),
        demo_mode=demo,
    )

    console.print("[dim]Fetching indicators...[/dim]")
    indicators = manager.fetch_all(limit_per_feed=args.limit)
    count = db.upsert_many(indicators)
    console.print(f"[green]Stored {count} indicators in {db_path}[/green]")

    # Print per-feed health
    for h in manager.health_report():
        status = "[green]OK[/green]" if h.available else "[red]FAIL[/red]"
        console.print(f"  {h.name}: {status} ({h.indicators_fetched} indicators)")

    db.close()


def cmd_correlate(args: argparse.Namespace) -> None:
    """Correlate local logs against the IOC database."""
    demo = args.demo
    db_path = Path(args.db)

    if demo or not db_path.exists():
        console.print("[yellow]Using demo mode for correlation.[/yellow]\n")
        db = IOCDatabase(":memory:")
        manager = FeedManager(demo_mode=True)
        indicators = manager.fetch_all()
        db.upsert_many(indicators)
    else:
        db = IOCDatabase(db_path)

    correlator = Correlator(db)

    if args.log_file:
        results = correlator.correlate_log_file(args.log_file)
    elif demo:
        from demo.sample_logs import SAMPLE_HONEYPOT_LOGS, SAMPLE_NETWORK_LOGS
        results = correlator.correlate_events(
            SAMPLE_HONEYPOT_LOGS + SAMPLE_NETWORK_LOGS
        )
    else:
        # Look for JSONL files in the default log directory
        log_dir = DEFAULT_LOG_DIR
        if not log_dir.exists():
            console.print(f"[red]Log directory not found: {log_dir}[/red]")
            db.close()
            return
        results = []
        for logfile in sorted(log_dir.glob("*.jsonl")):
            results.extend(correlator.correlate_log_file(logfile))

    console.print(f"\n[bold]Correlation complete: {len(results)} hits[/bold]\n")
    for r in sorted(results, key=lambda x: x.threat_score, reverse=True):
        console.print(f"  {r.summary()}")

    db.close()


def cmd_dashboard(args: argparse.Namespace) -> None:
    """Render the terminal dashboard."""
    demo = args.demo
    db_path = Path(args.db)

    if demo or not db_path.exists():
        db = IOCDatabase(":memory:")
        manager = FeedManager(demo_mode=True)
        indicators = manager.fetch_all()
        db.upsert_many(indicators)
        from demo.sample_logs import SAMPLE_HONEYPOT_LOGS, SAMPLE_NETWORK_LOGS
        correlator = Correlator(db)
        results = correlator.correlate_events(
            SAMPLE_HONEYPOT_LOGS + SAMPLE_NETWORK_LOGS
        )
        health = manager.health_report()
    else:
        db = IOCDatabase(db_path)
        results = []
        health = []

    dashboard = TerminalDashboard(console=console)
    dashboard.render(db, results, health)
    db.close()


def cmd_check(args: argparse.Namespace) -> None:
    """Check a single IOC value against all feeds."""
    demo = args.demo or not _load_api_keys()
    if demo:
        console.print("[yellow]Using demo mode.[/yellow]\n")

    manager = FeedManager(
        api_keys=_load_api_keys(),
        demo_mode=demo,
    )

    console.print(f"[dim]Checking: {args.ioc}[/dim]\n")
    results = manager.check_all(args.ioc)

    if not results:
        console.print("[green]No threat intelligence hits.[/green]")
        return

    console.print(f"[bold red]Found {len(results)} hit(s):[/bold red]\n")
    for ind in results:
        console.print(f"  Source: [bold]{ind.source}[/bold]")
        console.print(f"  Type:   {ind.ioc_type.value}")
        console.print(f"  Conf:   {ind.confidence:.2f} ({ind.severity_label})")
        console.print(f"  Tags:   {', '.join(ind.tags)}")
        console.print()


def cmd_report(args: argparse.Namespace) -> None:
    """Generate an HTML threat intelligence report."""
    demo = args.demo
    db_path = Path(args.db)

    if demo or not db_path.exists():
        db = IOCDatabase(":memory:")
        manager = FeedManager(demo_mode=True)
        indicators = manager.fetch_all()
        db.upsert_many(indicators)
        from demo.sample_logs import SAMPLE_HONEYPOT_LOGS, SAMPLE_NETWORK_LOGS
        correlator = Correlator(db)
        results = correlator.correlate_events(
            SAMPLE_HONEYPOT_LOGS + SAMPLE_NETWORK_LOGS
        )
        health = manager.health_report()
    else:
        db = IOCDatabase(db_path)
        results = []
        health = []

    report_path = HTMLReportGenerator().generate(
        db, results, health, output_path=args.output
    )
    console.print(f"[green]Report written to: {report_path}[/green]")
    db.close()


# ======================================================================
# Entry point
# ======================================================================

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    commands = {
        "demo": cmd_demo,
        "fetch": cmd_fetch,
        "correlate": cmd_correlate,
        "dashboard": cmd_dashboard,
        "check": cmd_check,
        "report": cmd_report,
    }

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    handler = commands.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    try:
        handler(args)
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        if args.verbose:
            console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
