#!/usr/bin/env python3
"""
SENTINEL — SIEM Log Pipeline
==============================
Lightweight log aggregation and visualization pipeline for cybersecurity
homelab environments. Ingests logs from honeypot events, network baseline
alerts, attack chain correlator output, and cloud scanner findings into
a unified event store with terminal dashboards and HTML reporting.

Usage:
    python main.py ingest --watch-dir ./logs/              Watch a directory for new log files
    python main.py ingest --http --port 8000               Start HTTP ingestion endpoint
    python main.py dashboard                               Launch interactive terminal dashboard
    python main.py search --severity high --last 24h       Search stored events
    python main.py report -o report.html                   Generate HTML summary report
    python main.py demo                                    Run self-contained demo

WARNING: This tool is intended for authorized security monitoring in
controlled lab environments only. Never deploy against systems you do
not own or have explicit permission to monitor.
"""

from __future__ import annotations

import argparse
import sys
import signal
from pathlib import Path

VERSION = "1.0.0"

BANNER = r"""
 ____  _____ _   _ _____ ___ _   _ _____ _
/ ___|| ____| \ | |_   _|_ _| \ | | ____| |
\___ \|  _| |  \| | | |  | ||  \| |  _| | |
 ___) | |___| |\  | | |  | || |\  | |___| |___
|____/|_____|_| \_| |_| |___|_| \_|_____|_____|
"""


def _print_banner() -> None:
    """Display the SENTINEL startup banner."""
    print(BANNER)
    print(f"  v{VERSION} — SIEM Log Pipeline for Cybersecurity Homelabs")
    print("  For authorized security monitoring only.\n")


# ── Subcommand Handlers ─────────────────────────────────────────────────────


def cmd_ingest(args: argparse.Namespace) -> int:
    """Run the log ingestion pipeline in directory-watch or HTTP mode."""
    from ingestion.collector import DirectoryCollector, HTTPCollector
    from ingestion.normalizer import EventNormalizer
    from storage.database import EventDatabase

    _print_banner()
    db = EventDatabase(args.db)
    normalizer = EventNormalizer()

    if args.http:
        print(f"[*] Starting HTTP ingestion endpoint on 0.0.0.0:{args.port}")
        collector = HTTPCollector(
            db=db,
            normalizer=normalizer,
            host="0.0.0.0",
            port=args.port,
        )
        collector.run()
    else:
        watch_dir = Path(args.watch_dir)
        if not watch_dir.exists():
            print(f"[-] Watch directory does not exist: {watch_dir}", file=sys.stderr)
            return 1

        print(f"[*] Watching directory: {watch_dir}")
        print(f"[*] Database: {args.db}")
        print("[*] Press Ctrl+C to stop.\n")

        collector = DirectoryCollector(
            db=db,
            normalizer=normalizer,
            watch_dir=watch_dir,
            poll_interval=args.poll_interval,
        )

        def _sigint_handler(sig: int, frame: object) -> None:
            print("\n[*] Shutting down ingestion...")
            collector.stop()

        signal.signal(signal.SIGINT, _sigint_handler)
        collector.run()

    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Launch the interactive terminal dashboard."""
    from storage.database import EventDatabase
    from dashboard.terminal_dashboard import TerminalDashboard

    _print_banner()
    db = EventDatabase(args.db)
    dashboard = TerminalDashboard(db=db, refresh_interval=args.refresh)
    dashboard.run()
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    """Run a search query against the event store."""
    from storage.database import EventDatabase
    from search.query_engine import QueryEngine, SearchQuery

    db = EventDatabase(args.db)
    engine = QueryEngine(db=db)

    query = SearchQuery(
        severity=args.severity,
        source=args.source,
        keyword=args.keyword,
        time_range=args.last,
        limit=args.limit,
    )

    results = engine.search(query)

    if not results:
        print("[*] No events match the query.")
        return 0

    print(f"[+] Found {len(results)} event(s):\n")
    for event in results:
        sev_indicator = {
            "critical": "!!!",
            "high": "!! ",
            "medium": "!  ",
            "low": ".  ",
            "info": "   ",
        }.get(event.severity, "   ")

        print(
            f"  [{sev_indicator}] {event.timestamp}  "
            f"[{event.source:<20}] [{event.severity:<8}] {event.message}"
        )

    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Generate an HTML summary report."""
    from storage.database import EventDatabase
    from dashboard.html_report import HTMLReportGenerator

    _print_banner()
    db = EventDatabase(args.db)
    generator = HTMLReportGenerator(db=db)

    output_path = Path(args.output)
    path = generator.generate(output_path)
    print(f"[+] HTML report written: {path}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Run a fully self-contained demo with synthetic log data."""
    import tempfile
    from demo.generator import DemoGenerator
    from ingestion.normalizer import EventNormalizer
    from storage.database import EventDatabase
    from dashboard.terminal_dashboard import TerminalDashboard
    from dashboard.html_report import HTMLReportGenerator
    from search.query_engine import QueryEngine, SearchQuery

    _print_banner()
    print("[*] SENTINEL Demo Mode")
    print("=" * 55)

    # Use a temporary database unless one is specified
    db_path = args.db if args.db != "sentinel.db" else str(
        Path(tempfile.gettempdir()) / "sentinel_demo.db"
    )
    # Remove stale demo database
    if Path(db_path).exists():
        Path(db_path).unlink()

    db = EventDatabase(db_path)
    normalizer = EventNormalizer()
    generator = DemoGenerator()

    # Step 1: Generate synthetic events
    print("\n[*] Step 1: Generating synthetic log data from all sources...")
    raw_events = generator.generate_all(count_per_source=args.event_count)
    print(f"[+]   Generated {len(raw_events)} raw events across "
          f"{len(generator.SOURCE_TYPES)} sources.")

    # Step 2: Normalize and store
    print("\n[*] Step 2: Normalizing and storing events...")
    stored_count = 0
    for source_type, raw_data in raw_events:
        normalized = normalizer.normalize(source_type, raw_data)
        if normalized:
            db.insert_event(normalized)
            stored_count += 1

    print(f"[+]   Stored {stored_count} normalized events in {db_path}")

    # Step 3: Run sample queries
    print("\n[*] Step 3: Running sample queries...")
    engine = QueryEngine(db=db)

    high_crit = engine.search(SearchQuery(severity="high", limit=5))
    print(f"[+]   High/Critical events: {len(high_crit)} (showing up to 5)")
    for event in high_crit[:5]:
        print(f"        [{event.severity:<8}] [{event.source:<20}] {event.message[:70]}")

    # Step 4: Generate HTML report
    print("\n[*] Step 4: Generating HTML report...")
    report_gen = HTMLReportGenerator(db=db)
    output_dir = Path(args.output) if args.output else Path(tempfile.gettempdir())
    report_path = report_gen.generate(output_dir / "sentinel_demo_report.html")
    print(f"[+]   Report written: {report_path}")

    # Step 5: Show terminal dashboard (unless --no-dashboard)
    if not args.no_dashboard:
        print("\n[*] Step 5: Launching terminal dashboard (press 'q' to exit)...")
        print("    (Use --no-dashboard to skip this step)\n")
        try:
            dashboard = TerminalDashboard(db=db, refresh_interval=2)
            dashboard.run()
        except (KeyboardInterrupt, Exception):
            pass
    else:
        print("\n[*] Step 5: Skipping dashboard (--no-dashboard flag set).")

    print(f"\n[+] Demo complete! Database: {db_path}")
    print(f"[+] HTML report: {report_path}")
    return 0


# ── CLI Parser ───────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="SENTINEL — SIEM Log Pipeline for Cybersecurity Homelabs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Self-contained demo (no infrastructure needed):
  python main.py demo

  # Watch a directory for new log files:
  python main.py ingest --watch-dir ./logs/

  # Start HTTP ingestion endpoint:
  python main.py ingest --http --port 8000

  # Launch terminal dashboard:
  python main.py dashboard

  # Search for high-severity events in the last 24 hours:
  python main.py search --severity high --last 24h

  # Generate HTML report:
  python main.py report -o sentinel_report.html
        """,
    )

    parser.add_argument(
        "--db", default="sentinel.db",
        help="Path to the SQLite database (default: sentinel.db)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ── ingest ───────────────────────────────────────────────────────────────
    p_ingest = sub.add_parser("ingest", help="Ingest logs from directories or HTTP")
    p_ingest.add_argument("--watch-dir", default="./logs",
                          help="Directory to watch for log files (default: ./logs)")
    p_ingest.add_argument("--http", action="store_true",
                          help="Start HTTP ingestion endpoint instead of directory watch")
    p_ingest.add_argument("--port", type=int, default=8000,
                          help="HTTP endpoint port (default: 8000)")
    p_ingest.add_argument("--poll-interval", type=float, default=2.0,
                          help="Directory poll interval in seconds (default: 2.0)")

    # ── dashboard ────────────────────────────────────────────────────────────
    p_dash = sub.add_parser("dashboard", help="Launch terminal dashboard")
    p_dash.add_argument("--refresh", type=int, default=5,
                        help="Dashboard refresh interval in seconds (default: 5)")

    # ── search ───────────────────────────────────────────────────────────────
    p_search = sub.add_parser("search", help="Search stored events")
    p_search.add_argument("--severity", default=None,
                          choices=["critical", "high", "medium", "low", "info"],
                          help="Filter by minimum severity")
    p_search.add_argument("--source", default=None,
                          help="Filter by source name")
    p_search.add_argument("--keyword", default=None,
                          help="Search keyword in event messages")
    p_search.add_argument("--last", default=None,
                          help="Time range filter (e.g., 1h, 24h, 7d)")
    p_search.add_argument("--limit", type=int, default=50,
                          help="Maximum results to return (default: 50)")

    # ── report ───────────────────────────────────────────────────────────────
    p_report = sub.add_parser("report", help="Generate HTML summary report")
    p_report.add_argument("--output", "-o", default="sentinel_report.html",
                          help="Output file path (default: sentinel_report.html)")

    # ── demo ─────────────────────────────────────────────────────────────────
    p_demo = sub.add_parser("demo", help="Run self-contained demo with synthetic data")
    p_demo.add_argument("--output", "-o", default=None,
                        help="Report output directory (default: /tmp)")
    p_demo.add_argument("--event-count", type=int, default=50,
                        help="Number of events per source (default: 50)")
    p_demo.add_argument("--no-dashboard", action="store_true",
                        help="Skip the interactive dashboard at the end")

    return parser


def main() -> int:
    """Entry point for the SENTINEL pipeline."""
    parser = build_parser()
    args = parser.parse_args()

    dispatch: dict[str, callable] = {
        "ingest": cmd_ingest,
        "dashboard": cmd_dashboard,
        "search": cmd_search,
        "report": cmd_report,
        "demo": cmd_demo,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\n[*] Interrupted. Exiting.")
        return 130
    except Exception as exc:
        print(f"[-] Fatal error: {exc}", file=sys.stderr)
        if "--verbose" in sys.argv:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
