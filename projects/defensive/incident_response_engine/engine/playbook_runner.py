"""Core playbook runner that orchestrates incident response workflows.

Loads playbook definitions, matches them to alerts, and executes
the response steps in sequence with progress tracking.
"""

from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.text import Text

from engine.action_executor import ActionExecutor
from engine.alert_matcher import AlertMatcher
from models.alert import Alert
from models.playbook import Playbook
from models.response import ResponseResult, StepResult, ExecutionStatus

console = Console()

# NIST 800-61 phase color mapping for terminal display
_NIST_COLORS: dict[str, str] = {
    "preparation": "blue",
    "detection": "yellow",
    "containment": "red",
    "eradication": "magenta",
    "recovery": "green",
    "post_incident": "cyan",
}


class PlaybookRunner:
    """Core engine that loads playbooks, matches alerts, and executes responses.

    The runner coordinates between the AlertMatcher and ActionExecutor
    to provide end-to-end incident response automation.

    Attributes:
        playbooks_dir: Path to the directory containing YAML playbooks.
        demo_mode: When True, all actions are simulated.
        playbooks: List of loaded playbook definitions.
        matcher: AlertMatcher instance for alert-to-playbook mapping.
        executor: ActionExecutor instance for step execution.
    """

    def __init__(
        self,
        playbooks_dir: str | Path = "playbooks",
        demo_mode: bool = True,
    ) -> None:
        self.playbooks_dir = Path(playbooks_dir)
        self.demo_mode = demo_mode
        self.playbooks: list[Playbook] = []
        self.matcher = AlertMatcher()
        self.executor = ActionExecutor(demo_mode=demo_mode)
        self._execution_history: list[ResponseResult] = []

    def load_playbooks(self) -> list[Playbook]:
        """Load all YAML playbook files from the playbooks directory.

        Returns:
            List of loaded Playbook objects.

        Raises:
            FileNotFoundError: If the playbooks directory does not exist.
        """
        if not self.playbooks_dir.exists():
            raise FileNotFoundError(
                f"Playbooks directory not found: {self.playbooks_dir}"
            )

        self.playbooks = []
        yaml_files = sorted(self.playbooks_dir.glob("*.yaml")) + sorted(
            self.playbooks_dir.glob("*.yml")
        )

        for yaml_path in yaml_files:
            try:
                playbook = Playbook.from_yaml(yaml_path)
                self.playbooks.append(playbook)
                self.matcher.add_playbook(playbook)
            except Exception as exc:
                console.print(
                    f"[yellow]Warning:[/yellow] Failed to load {yaml_path.name}: {exc}"
                )

        return self.playbooks

    def list_playbooks(self) -> None:
        """Display a formatted table of all loaded playbooks."""
        if not self.playbooks:
            console.print("[yellow]No playbooks loaded. Call load_playbooks() first.[/yellow]")
            return

        table = Table(
            title="AEGIS - Loaded Playbooks",
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        table.add_column("Name", style="bold white", min_width=25)
        table.add_column("NIST Phase", min_width=15)
        table.add_column("Steps", justify="center", min_width=7)
        table.add_column("Triggers", min_width=20)
        table.add_column("Version", justify="center", min_width=8)

        for pb in self.playbooks:
            phase_color = _NIST_COLORS.get(pb.nist_phase, "white")
            triggers = ", ".join(pb.trigger_conditions.alert_types) or "any"
            table.add_row(
                pb.name,
                f"[{phase_color}]{pb.nist_phase}[/{phase_color}]",
                str(len(pb.steps)),
                triggers,
                pb.version,
            )

        console.print()
        console.print(table)
        console.print()

    def process_alert(self, alert: Alert) -> ResponseResult | None:
        """Process an alert by matching it to a playbook and executing the response.

        Args:
            alert: The incoming security alert to process.

        Returns:
            A ResponseResult if a matching playbook was found and executed,
            or None if no playbook matched.
        """
        # Display alert info
        self._display_alert(alert)

        # Find matching playbook
        playbook = self.matcher.match_best(alert)
        if playbook is None:
            console.print(
                Panel(
                    "[yellow]No matching playbook found for this alert.[/yellow]\n"
                    "Consider creating a custom playbook for this alert type.",
                    title="No Match",
                    border_style="yellow",
                )
            )
            return None

        console.print(
            f"\n[bold green]Matched playbook:[/bold green] {playbook.name} "
            f"(v{playbook.version})"
        )

        # Execute the playbook
        result = self._execute_playbook(playbook, alert)
        self._execution_history.append(result)

        # Display summary
        self._display_result_summary(result)

        return result

    def _execute_playbook(self, playbook: Playbook, alert: Alert) -> ResponseResult:
        """Execute a playbook's steps in sequence against an alert.

        Args:
            playbook: The playbook to execute.
            alert: The alert that triggered this execution.

        Returns:
            A ResponseResult with the complete execution outcome.
        """
        result = ResponseResult(
            playbook_name=playbook.name,
            alert_id=alert.id,
            started_at=datetime.utcnow(),
            status=ExecutionStatus.RUNNING,
        )

        failure_count = 0
        total_steps = len(playbook.steps)

        console.print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[bold]Executing {playbook.name}...", total=total_steps
            )

            for i, step in enumerate(playbook.steps, 1):
                phase_color = _NIST_COLORS.get(step.nist_phase, "white")
                progress.update(
                    task,
                    description=(
                        f"[bold]Step {i}/{total_steps}:[/bold] "
                        f"[{phase_color}][{step.nist_phase}][/{phase_color}] "
                        f"{step.name}"
                    ),
                )

                # Inject alert context into step parameters
                params = {**step.parameters}
                params["step_name"] = step.name
                params["nist_phase"] = step.nist_phase
                params.setdefault("source_ip", alert.source_ip)
                params.setdefault("dest_ip", alert.dest_ip)
                params.setdefault("ip", alert.source_ip)

                # Execute the step
                step_result = self.executor.execute(
                    action=step.action,
                    parameters=params,
                    timeout=step.timeout,
                )
                step_result.nist_phase = step.nist_phase
                result.steps_executed.append(step_result)

                # Collect evidence
                if step_result.evidence:
                    result.evidence_collected.append(
                        {
                            "step": step.name,
                            "nist_phase": step.nist_phase,
                            **step_result.evidence,
                        }
                    )

                # Handle failures
                if step_result.status == ExecutionStatus.FAILED:
                    failure_count += 1
                    console.print(
                        f"  [red]Step failed:[/red] {step_result.error}"
                    )

                    # Attempt rollback if defined
                    if step.rollback_action:
                        rollback_result = self.executor.execute_rollback(
                            step.rollback_action, step.rollback_parameters
                        )
                        if rollback_result.status == ExecutionStatus.SUCCESS:
                            step_result.status = ExecutionStatus.ROLLED_BACK

                    # Check escalation threshold
                    if failure_count >= playbook.escalation_policy.escalation_threshold:
                        result.escalated = True
                        result.escalation_reason = (
                            f"Failure threshold reached: {failure_count} failures"
                        )
                        if not step.continue_on_failure:
                            break

                    if not step.continue_on_failure:
                        break

                progress.update(task, advance=1)

        # Check for auto-escalation on severity
        if (
            str(alert.severity)
            in playbook.escalation_policy.auto_escalate_severity
        ):
            result.escalated = True
            result.escalation_reason = (
                result.escalation_reason
                or f"Auto-escalation for {alert.severity} severity"
            )

        # Set final status
        result.completed_at = datetime.utcnow()
        if result.escalated:
            result.status = ExecutionStatus.ESCALATED
        elif failure_count > 0:
            result.status = ExecutionStatus.FAILED
        else:
            result.status = ExecutionStatus.SUCCESS

        return result

    def _display_alert(self, alert: Alert) -> None:
        """Render an alert panel in the terminal."""
        severity_colors = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red",
        }
        color = severity_colors.get(str(alert.severity), "white")

        alert_info = (
            f"[bold]ID:[/bold]          {alert.id}\n"
            f"[bold]Type:[/bold]        {alert.alert_type}\n"
            f"[bold]Severity:[/bold]    [{color}]{alert.severity}[/{color}]\n"
            f"[bold]Source IP:[/bold]   {alert.source_ip}\n"
            f"[bold]Dest IP:[/bold]     {alert.dest_ip}\n"
            f"[bold]Timestamp:[/bold]   {alert.timestamp.isoformat()}\n"
            f"[bold]Description:[/bold] {alert.description}\n"
            f"[bold]Tags:[/bold]        {', '.join(alert.tags) or 'none'}"
        )

        console.print()
        console.print(
            Panel(
                alert_info,
                title="[bold red]INCOMING ALERT[/bold red]",
                border_style=color,
                padding=(1, 2),
            )
        )

    def _display_result_summary(self, result: ResponseResult) -> None:
        """Render a summary panel for a completed playbook execution."""
        status_styles = {
            "success": ("bold green", "SUCCESS"),
            "failed": ("bold red", "FAILED"),
            "escalated": ("bold yellow", "ESCALATED"),
        }
        style, label = status_styles.get(
            str(result.status), ("white", str(result.status).upper())
        )

        table = Table(show_header=True, header_style="bold", border_style="dim")
        table.add_column("Step", min_width=25)
        table.add_column("Action", min_width=15)
        table.add_column("NIST Phase", min_width=14)
        table.add_column("Status", justify="center", min_width=10)
        table.add_column("Duration", justify="right", min_width=10)

        for step in result.steps_executed:
            step_status_colors = {
                "success": "green",
                "failed": "red",
                "rolled_back": "yellow",
                "skipped": "dim",
            }
            s_color = step_status_colors.get(str(step.status), "white")
            phase_color = _NIST_COLORS.get(step.nist_phase, "white")
            table.add_row(
                step.step_name,
                step.action,
                f"[{phase_color}]{step.nist_phase}[/{phase_color}]",
                f"[{s_color}]{step.status}[/{s_color}]",
                f"{step.duration_seconds:.2f}s",
            )

        console.print()
        console.print(table)

        summary = (
            f"[bold]Playbook:[/bold]  {result.playbook_name}\n"
            f"[bold]Alert:[/bold]     {result.alert_id}\n"
            f"[bold]Status:[/bold]    [{style}]{label}[/{style}]\n"
            f"[bold]Duration:[/bold]  {result.duration_seconds:.2f}s\n"
            f"[bold]Steps:[/bold]     {result.success_count}/{len(result.steps_executed)} successful\n"
            f"[bold]Evidence:[/bold]  {len(result.evidence_collected)} artifacts collected"
        )

        if result.escalated:
            summary += f"\n[bold yellow]Escalation:[/bold yellow] {result.escalation_reason}"

        console.print(
            Panel(
                summary,
                title="[bold]Execution Summary[/bold]",
                border_style=style.replace("bold ", ""),
                padding=(1, 2),
            )
        )

    @property
    def execution_history(self) -> list[ResponseResult]:
        """Access the history of all playbook executions."""
        return self._execution_history
