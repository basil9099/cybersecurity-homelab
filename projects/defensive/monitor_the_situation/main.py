#!/usr/bin/env python3
"""MONITOR THE SITUATION -- Cybersecurity Situational Awareness Dashboard.

Main entry point with CLI supporting demo, serve, fetch, and reset-db modes.

Usage:
    python main.py demo                 Launch dashboard with mock data
    python main.py serve                Start the API server
    python main.py fetch                Run a one-shot data fetch from all sources
    python main.py reset-db             Reset the database (destructive)
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from rich.console import Console

logger = logging.getLogger("mts")
console = Console()

BANNER = r"""
 __  __  ___  _   _ ___ _____ ___  ____
|  \/  |/ _ \| \ | |_ _|_   _/ _ \|  _ \
| |\/| | | | |  \| || |  | || | | | |_) |
| |  | | |_| | |\  || |  | || |_| |  _ <
|_|  |_|\___/|_| \_|___| |_| \___/|_| \_\

  _____ _   _ _____   ____ ___ _____ _   _    _  _____ ___ ___  _   _
 |_   _| | | | ____| / ___|_ _|_   _| | | |  / \|_   _|_ _/ _ \| \ | |
   | | | |_| |  _|   \___ \| |  | | | | | | / _ \ | |  | | | | |  \| |
   | | |  _  | |___   ___) | |  | | | |_| |/ ___ \| |  | | |_| | |\  |
   |_| |_| |_|_____| |____/___| |_|  \___/_/   \_\_| |___\___/|_| \_|

  Cybersecurity Situational Awareness Dashboard
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Monitor the Situation -- Threat Intelligence Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "--db", default=None, help="Path to SQLite database"
    )
    parser.add_argument(
        "--host", default="0.0.0.0", help="Server bind host (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="Server port (default: 8000)"
    )

    sub = parser.add_subparsers(dest="command")

    # demo
    demo_p = sub.add_parser("demo", help="Launch with mock data (no API keys needed)")
    demo_p.add_argument(
        "--no-browser", action="store_true", help="Don't open browser automatically"
    )

    # serve
    serve_p = sub.add_parser("serve", help="Start the API server")
    serve_p.add_argument(
        "--demo", action="store_true", help="Use demo mode with mock data"
    )

    # fetch
    sub.add_parser("fetch", help="Run a one-shot fetch from all sources")

    # reset-db
    sub.add_parser("reset-db", help="Reset the database (destructive)")

    return parser


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_demo(args: argparse.Namespace) -> None:
    """Launch the full stack in demo mode with mock data."""
    from backend.config import Settings

    settings = Settings.from_env()
    settings.demo_mode = True
    if args.db:
        settings.db_path = Path(args.db)
    settings.host = args.host
    settings.port = args.port

    console.print(BANNER, style="bold cyan")
    console.print("[bold green]Starting in DEMO mode...[/bold green]")
    console.print(f"  API server: http://{settings.host}:{settings.port}")
    console.print(f"  Frontend:   http://localhost:3000")
    console.print(f"  Database:   {settings.db_path}")
    console.print()

    from backend.database import Database
    from backend.demo.seeder import DemoSeeder

    db = Database(settings.db_path)
    seeder = DemoSeeder(db)
    seeder.seed_all()
    console.print("[green]Demo data seeded successfully.[/green]")

    _start_server(settings, db)


def cmd_serve(args: argparse.Namespace) -> None:
    """Start the API server."""
    from backend.config import Settings

    settings = Settings.from_env()
    if args.demo:
        settings.demo_mode = True
    if args.db:
        settings.db_path = Path(args.db)
    settings.host = args.host
    settings.port = args.port

    console.print(BANNER, style="bold cyan")
    mode_label = "DEMO" if settings.demo_mode else "LIVE"
    console.print(f"[bold green]Starting in {mode_label} mode...[/bold green]")

    from backend.database import Database

    db = Database(settings.db_path)

    if settings.demo_mode:
        from backend.demo.seeder import DemoSeeder
        seeder = DemoSeeder(db)
        seeder.seed_all()

    _start_server(settings, db)


def cmd_fetch(args: argparse.Namespace) -> None:
    """Run a one-shot fetch from all configured sources."""
    import asyncio
    from backend.config import Settings
    from backend.database import Database

    settings = Settings.from_env()
    if args.db:
        settings.db_path = Path(args.db)

    console.print(BANNER, style="bold cyan")
    console.print("[bold]Running one-shot fetch...[/bold]")

    db = Database(settings.db_path)

    from backend.collectors.base import run_all_collectors
    asyncio.run(run_all_collectors(settings, db))
    console.print("[green]Fetch complete.[/green]")


def cmd_reset_db(args: argparse.Namespace) -> None:
    """Reset the database."""
    from backend.config import Settings

    settings = Settings.from_env()
    if args.db:
        settings.db_path = Path(args.db)

    db_path = Path(settings.db_path)
    if db_path.exists():
        db_path.unlink()
        console.print(f"[yellow]Deleted {db_path}[/yellow]")
    else:
        console.print(f"[dim]No database found at {db_path}[/dim]")

    from backend.database import Database
    Database(settings.db_path)
    console.print("[green]Fresh database created.[/green]")


def _start_server(settings: "Settings", db: "Database") -> None:
    """Start the uvicorn server."""
    import uvicorn
    from backend.app import create_app

    app = create_app(settings, db)
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    _setup_logging(args.verbose)

    commands = {
        "demo": cmd_demo,
        "serve": cmd_serve,
        "fetch": cmd_fetch,
        "reset-db": cmd_reset_db,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
