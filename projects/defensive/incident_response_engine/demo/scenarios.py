"""Pre-built demo scenarios that simulate the full incident response lifecycle.

Each scenario creates a realistic alert, runs it through the engine,
and demonstrates playbook matching, step execution, and report generation.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table

from engine.playbook_runner import PlaybookRunner
from models.alert import Alert, AlertType, AlertSeverity
from reporting.incident_report import IncidentReporter

console = Console()


def _build_brute_force_alert() -> Alert:
    """Create a simulated brute force attack alert."""
    return Alert(
        alert_type=AlertType.BRUTE_FORCE,
        severity=AlertSeverity.HIGH,
        source_ip="203.0.113.42",
        dest_ip="10.0.1.15",
        description=(
            "Multiple failed SSH login attempts detected from external IP. "
            "Over 150 failed attempts in 5 minutes against root account on "
            "production server srv-web-01."
        ),
        tags=["ssh", "authentication", "external_threat", "brute_force"],
        raw_data={
            "failed_attempts": 153,
            "time_window_minutes": 5,
            "target_account": "root",
            "target_host": "srv-web-01",
            "service": "sshd",
            "geo_location": "Unknown - TOR exit node",
        },
    )


def _build_malware_alert() -> Alert:
    """Create a simulated malware detection alert."""
    return Alert(
        alert_type=AlertType.MALWARE_DETECTED,
        severity=AlertSeverity.CRITICAL,
        source_ip="10.0.2.88",
        dest_ip="185.220.101.34",
        description=(
            "Endpoint Detection and Response (EDR) identified a known Emotet "
            "variant executing on workstation WS-FIN-012. Malware is attempting "
            "to establish C2 communication with known malicious infrastructure."
        ),
        tags=["malware", "trojan", "emotet", "c2", "endpoint"],
        raw_data={
            "malware_family": "Emotet",
            "malware_hash": "a1b2c3d4e5f6789012345678abcdef01",
            "detection_engine": "CrowdStrike Falcon",
            "hostname": "WS-FIN-012",
            "user": "jsmith",
            "department": "Finance",
            "c2_domains": ["evil-c2.example.com", "malware-drop.example.net"],
            "process_name": "svchost_update.exe",
            "process_path": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost_update.exe",
        },
    )


def _build_exfiltration_alert() -> Alert:
    """Create a simulated data exfiltration alert."""
    return Alert(
        alert_type=AlertType.DATA_EXFILTRATION,
        severity=AlertSeverity.CRITICAL,
        source_ip="10.0.3.22",
        dest_ip="45.33.32.156",
        description=(
            "DLP system detected anomalous outbound data transfer of 2.3 GB "
            "to an external IP address. Transfer originated from database server "
            "DB-CUST-01 containing PII data. Transfer protocol: HTTPS with "
            "certificate pinning to unknown CA."
        ),
        tags=["exfiltration", "dlp", "data_loss", "pii", "anomalous_transfer"],
        raw_data={
            "data_volume_gb": 2.3,
            "transfer_protocol": "HTTPS",
            "source_host": "DB-CUST-01",
            "database": "customer_records",
            "classification": "PII - Confidential",
            "anomaly_score": 0.97,
            "baseline_daily_transfer_gb": 0.1,
            "cert_issuer": "Unknown CA",
            "duration_minutes": 45,
        },
    )


def _build_unauthorized_access_alert() -> Alert:
    """Create a simulated unauthorized access alert."""
    return Alert(
        alert_type=AlertType.UNAUTHORIZED_ACCESS,
        severity=AlertSeverity.HIGH,
        source_ip="10.0.1.105",
        dest_ip="10.0.5.10",
        description=(
            "SIEM correlation rule triggered: User 'svc_backup' accessed "
            "sensitive HR file share outside of scheduled backup window. "
            "Access originated from an unusual workstation not associated "
            "with the service account."
        ),
        tags=["unauthorized", "access_violation", "service_account", "authentication"],
        raw_data={
            "account": "svc_backup",
            "resource": "\\\\fileserver\\HR\\Payroll",
            "access_type": "READ",
            "workstation": "WS-DEV-099",
            "normal_workstation": "SRV-BACKUP-01",
            "time_of_access": "2024-03-15T02:34:00Z",
            "scheduled_window": "01:00-02:00 UTC",
            "files_accessed": 47,
        },
    )


# Scenario registry
SCENARIOS: dict[str, dict] = {
    "brute_force": {
        "name": "SSH Brute Force Attack",
        "description": "External attacker performing SSH brute force against production server",
        "builder": _build_brute_force_alert,
    },
    "malware": {
        "name": "Emotet Malware Detection",
        "description": "EDR detects Emotet trojan with active C2 communication",
        "builder": _build_malware_alert,
    },
    "exfiltration": {
        "name": "Database Exfiltration",
        "description": "DLP detects anomalous 2.3 GB transfer of PII data to external IP",
        "builder": _build_exfiltration_alert,
    },
    "unauthorized_access": {
        "name": "Service Account Abuse",
        "description": "Service account accessing sensitive data outside normal parameters",
        "builder": _build_unauthorized_access_alert,
    },
}


class DemoRunner:
    """Runs pre-built demo scenarios through the AEGIS engine.

    Demonstrates the full lifecycle: alert generation, playbook matching,
    step execution with simulated output, and report generation.

    Attributes:
        runner: The PlaybookRunner engine instance.
        reporter: The IncidentReporter for generating reports.
    """

    def __init__(self, playbooks_dir: str | Path = "playbooks") -> None:
        self.runner = PlaybookRunner(playbooks_dir=playbooks_dir, demo_mode=True)
        self.reporter = IncidentReporter(output_dir="reports")

    def list_scenarios(self) -> None:
        """Display available demo scenarios."""
        table = Table(
            title="AEGIS - Available Demo Scenarios",
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("Key", style="bold green", min_width=20)
        table.add_column("Name", min_width=25)
        table.add_column("Description", min_width=45)

        for key, info in SCENARIOS.items():
            table.add_row(key, info["name"], info["description"])

        console.print()
        console.print(table)
        console.print()

    def run_scenario(self, scenario_key: str) -> None:
        """Run a single demo scenario.

        Args:
            scenario_key: Key identifying the scenario to run.

        Raises:
            KeyError: If the scenario key is not found.
        """
        if scenario_key not in SCENARIOS:
            console.print(f"[red]Unknown scenario: {scenario_key}[/red]")
            console.print(f"Available: {', '.join(SCENARIOS.keys())}")
            return

        scenario = SCENARIOS[scenario_key]
        self._print_banner()

        console.print(
            Rule(f"[bold]{scenario['name']}[/bold]", style="cyan")
        )
        console.print(f"[dim]{scenario['description']}[/dim]\n")

        # Load playbooks
        console.print("[bold]Loading playbooks...[/bold]")
        playbooks = self.runner.load_playbooks()
        console.print(f"[green]Loaded {len(playbooks)} playbooks[/green]\n")

        # Generate and process the alert
        alert = scenario["builder"]()
        result = self.runner.process_alert(alert)

        if result:
            # Generate reports
            console.print("\n[bold]Generating incident reports...[/bold]")
            reports = self.reporter.generate(result, alert, format="both")
            for fmt, path in reports.items():
                console.print(f"  [green]{fmt.upper()}:[/green] {path}")

        console.print()
        console.print(Rule(style="dim"))

    def run_all_scenarios(self) -> None:
        """Run all available demo scenarios in sequence."""
        self._print_banner()

        console.print("[bold]Loading playbooks...[/bold]")
        playbooks = self.runner.load_playbooks()
        console.print(f"[green]Loaded {len(playbooks)} playbooks[/green]\n")

        results = []

        for i, (key, scenario) in enumerate(SCENARIOS.items(), 1):
            console.print(
                Rule(
                    f"[bold]Scenario {i}/{len(SCENARIOS)}: {scenario['name']}[/bold]",
                    style="cyan",
                )
            )
            console.print(f"[dim]{scenario['description']}[/dim]\n")

            alert = scenario["builder"]()

            # Need a fresh matcher for each run to avoid double-loaded playbooks
            # but reuse the same runner since playbooks are already loaded
            result = self.runner.process_alert(alert)

            if result:
                results.append((result, alert))
                console.print("\n[bold]Generating incident reports...[/bold]")
                reports = self.reporter.generate(result, alert, format="both")
                for fmt, path in reports.items():
                    console.print(f"  [green]{fmt.upper()}:[/green] {path}")

            console.print()

        # Print aggregate summary
        if results:
            self._print_aggregate_summary(results)

    def _print_banner(self) -> None:
        """Print the AEGIS banner."""
        banner = """
[bold cyan]
     _    _____ ____ ___ ____
    / \\  | ____/ ___|_ _/ ___|
   / _ \\ |  _|| |  _ | |\\___ \\
  / ___ \\| |__| |_| || | ___) |
 /_/   \\_\\_____\\____|___|____/
[/bold cyan]
[dim]Automated Engagement & Guardian Incident System[/dim]
[dim]Incident Response Playbook Engine v1.0[/dim]
"""
        console.print(
            Panel(banner, border_style="cyan", padding=(0, 2))
        )

    def _print_aggregate_summary(
        self, results: list[tuple["ResponseResult", "Alert"]]
    ) -> None:
        """Print an aggregate summary of all scenario runs."""
        summary = self.reporter.generate_summary([r for r, _ in results])

        console.print(Rule("[bold]Aggregate Summary[/bold]", style="cyan"))

        table = Table(show_header=False, border_style="dim", padding=(0, 2))
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Total incidents processed", str(summary["total_incidents"]))
        table.add_row(
            "Successful responses",
            f"[green]{summary['successful_responses']}[/green]",
        )
        table.add_row(
            "Failed responses",
            f"[red]{summary['failed_responses']}[/red]",
        )
        table.add_row(
            "Escalated incidents",
            f"[yellow]{summary['escalated_incidents']}[/yellow]",
        )
        table.add_row(
            "Evidence artifacts collected",
            str(summary["total_evidence_artifacts"]),
        )

        console.print(table)
        console.print()
