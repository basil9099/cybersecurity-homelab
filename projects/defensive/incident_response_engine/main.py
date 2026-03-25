#!/usr/bin/env python3
"""AEGIS - Automated Engagement & Guardian Incident System.

Main entry point for the Incident Response Playbook Engine.
Provides CLI modes for demo execution, live alert processing,
and playbook management.

Usage:
    python main.py demo [scenario]     Run demo scenario(s)
    python main.py run --alert <json>  Process an alert in live mode
    python main.py list-playbooks      List available playbooks
    python main.py list-scenarios      List available demo scenarios
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console

# Ensure project root is on the path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from demo.scenarios import DemoRunner, SCENARIOS
from engine.playbook_runner import PlaybookRunner
from models.alert import Alert
from reporting.incident_report import IncidentReporter

console = Console()

PLAYBOOKS_DIR = PROJECT_ROOT / "playbooks"


def cmd_demo(args: argparse.Namespace) -> None:
    """Execute demo scenario(s).

    Args:
        args: Parsed CLI arguments containing optional scenario key.
    """
    runner = DemoRunner(playbooks_dir=PLAYBOOKS_DIR)

    if args.scenario and args.scenario != "all":
        runner.run_scenario(args.scenario)
    else:
        runner.run_all_scenarios()


def cmd_run(args: argparse.Namespace) -> None:
    """Process an alert through the engine.

    Args:
        args: Parsed CLI arguments containing alert JSON.
    """
    # Parse alert
    try:
        if args.alert.startswith("@"):
            # Load from file
            alert_path = Path(args.alert[1:])
            with open(alert_path) as f:
                alert_data = json.load(f)
        else:
            alert_data = json.loads(args.alert)
    except (json.JSONDecodeError, FileNotFoundError) as exc:
        console.print(f"[red]Error parsing alert:[/red] {exc}")
        sys.exit(1)

    alert = Alert.from_dict(alert_data)

    # Initialize engine
    demo_mode = not args.live
    runner = PlaybookRunner(playbooks_dir=PLAYBOOKS_DIR, demo_mode=demo_mode)
    runner.load_playbooks()

    if demo_mode:
        console.print("[yellow]Running in DEMO mode (all actions simulated)[/yellow]\n")
    else:
        console.print("[bold red]Running in LIVE mode[/bold red]\n")

    # Process alert
    result = runner.process_alert(alert)

    if result:
        # Generate reports
        reporter = IncidentReporter(output_dir=PROJECT_ROOT / "reports")
        reports = reporter.generate(result, alert, format="both")
        console.print("\n[bold]Reports generated:[/bold]")
        for fmt, path in reports.items():
            console.print(f"  [green]{fmt.upper()}:[/green] {path}")


def cmd_list_playbooks(args: argparse.Namespace) -> None:
    """List all available playbooks.

    Args:
        args: Parsed CLI arguments (unused).
    """
    runner = PlaybookRunner(playbooks_dir=PLAYBOOKS_DIR, demo_mode=True)
    runner.load_playbooks()
    runner.list_playbooks()


def cmd_list_scenarios(args: argparse.Namespace) -> None:
    """List available demo scenarios.

    Args:
        args: Parsed CLI arguments (unused).
    """
    runner = DemoRunner(playbooks_dir=PLAYBOOKS_DIR)
    runner.list_scenarios()


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="aegis",
        description=(
            "AEGIS - Automated Engagement & Guardian Incident System\n"
            "Incident Response Playbook Engine"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py demo                    Run all demo scenarios\n"
            "  python main.py demo brute_force        Run specific scenario\n"
            "  python main.py list-playbooks           List available playbooks\n"
            "  python main.py list-scenarios            List demo scenarios\n"
            '  python main.py run --alert \'{"alert_type":"brute_force",...}\'\n'
            "  python main.py run --alert @alert.json  Load alert from file\n"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # demo command
    demo_parser = subparsers.add_parser(
        "demo", help="Run demo scenario(s) with simulated actions"
    )
    demo_parser.add_argument(
        "scenario",
        nargs="?",
        default="all",
        choices=["all"] + list(SCENARIOS.keys()),
        help="Specific scenario to run (default: all)",
    )
    demo_parser.set_defaults(func=cmd_demo)

    # run command
    run_parser = subparsers.add_parser(
        "run", help="Process an alert through the engine"
    )
    run_parser.add_argument(
        "--alert",
        required=True,
        help="Alert as JSON string or @filepath to load from file",
    )
    run_parser.add_argument(
        "--live",
        action="store_true",
        default=False,
        help="Run in live mode (default: demo/simulated mode)",
    )
    run_parser.set_defaults(func=cmd_run)

    # list-playbooks command
    list_pb_parser = subparsers.add_parser(
        "list-playbooks", help="List all available playbooks"
    )
    list_pb_parser.set_defaults(func=cmd_list_playbooks)

    # list-scenarios command
    list_sc_parser = subparsers.add_parser(
        "list-scenarios", help="List available demo scenarios"
    )
    list_sc_parser.set_defaults(func=cmd_list_scenarios)

    return parser


def main() -> None:
    """Main entry point for the AEGIS CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
