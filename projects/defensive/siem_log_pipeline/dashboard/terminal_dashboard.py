"""
dashboard.terminal_dashboard — Rich-powered live terminal dashboard.

Displays event counts by source, severity distribution, recent event
timeline, and top alerting sources in a continuously refreshing layout.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from storage.database import EventDatabase

# Severity → colour mapping used throughout the dashboard.
_SEV_COLORS: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


class TerminalDashboard:
    """Interactive terminal dashboard backed by Rich :class:`Live` display."""

    def __init__(self, db: EventDatabase, refresh_interval: int = 5) -> None:
        self.db = db
        self.refresh_interval = refresh_interval
        self.console = Console()

    # ── Widget builders ─────────────────────────────────────────────────

    def _build_header(self) -> Panel:
        total = self.db.get_event_count()
        header_text = Text.assemble(
            ("SENTINEL", "bold cyan"),
            " — SIEM Log Pipeline   ",
            (f"Total events: {total}", "bold green"),
        )
        return Panel(header_text, style="bold white", height=3)

    def _build_source_table(self) -> Panel:
        counts = self.db.get_event_counts_by_source()
        table = Table(title="Events by Source", expand=True)
        table.add_column("Source", style="cyan", ratio=2)
        table.add_column("Count", justify="right", style="green", ratio=1)
        table.add_column("Bar", ratio=4)

        max_count = max(counts.values(), default=1)
        for source, count in counts.items():
            bar_width = int((count / max_count) * 30) if max_count else 0
            bar = Text("█" * bar_width, style="cyan")
            table.add_row(source, str(count), bar)

        return Panel(table, title="Sources", border_style="blue")

    def _build_severity_chart(self) -> Panel:
        dist = self.db.get_severity_distribution()
        table = Table(title="Severity Distribution", expand=True)
        table.add_column("Severity", style="bold", ratio=2)
        table.add_column("Count", justify="right", ratio=1)
        table.add_column("Bar", ratio=4)

        max_count = max(dist.values(), default=1)
        ordered = ["critical", "high", "medium", "low", "info"]
        for sev in ordered:
            count = dist.get(sev, 0)
            color = _SEV_COLORS.get(sev, "white")
            bar_width = int((count / max_count) * 30) if max_count else 0
            bar = Text("█" * bar_width, style=color)
            table.add_row(Text(sev.upper(), style=color), str(count), bar)

        return Panel(table, title="Severity", border_style="red")

    def _build_timeline(self) -> Panel:
        timeline = self.db.get_timeline(hours=24)
        table = Table(title="Event Timeline (last 24 h)", expand=True)
        table.add_column("Hour", style="dim", ratio=2)
        table.add_column("Count", justify="right", style="green", ratio=1)
        table.add_column("Activity", ratio=4)

        max_count = max((t["count"] for t in timeline), default=1)
        for entry in timeline[-12:]:  # Show at most last 12 hours
            bar_width = int((entry["count"] / max_count) * 30) if max_count else 0
            bar = Text("▓" * bar_width, style="green")
            table.add_row(entry["hour"], str(entry["count"]), bar)

        return Panel(table, title="Timeline", border_style="green")

    def _build_recent_events(self) -> Panel:
        events = self.db.get_recent_events(limit=15)
        table = Table(title="Recent Events", expand=True)
        table.add_column("Time", style="dim", ratio=2, no_wrap=True)
        table.add_column("Sev", ratio=1, no_wrap=True)
        table.add_column("Source", style="cyan", ratio=2, no_wrap=True)
        table.add_column("Message", ratio=5)

        for ev in events:
            color = _SEV_COLORS.get(ev.severity, "white")
            short_ts = ev.timestamp[:19] if len(ev.timestamp) >= 19 else ev.timestamp
            table.add_row(
                short_ts,
                Text(ev.severity.upper(), style=color),
                ev.source,
                ev.message[:80],
            )

        return Panel(table, title="Recent", border_style="yellow")

    # ── Layout assembly ─────────────────────────────────────────────────

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="recent", size=20),
        )
        layout["body"].split_row(
            Layout(name="left"),
            Layout(name="right"),
        )
        layout["left"].split_column(
            Layout(name="sources"),
            Layout(name="timeline"),
        )
        layout["right"].split_column(
            Layout(name="severity"),
        )

        layout["header"].update(self._build_header())
        layout["sources"].update(self._build_source_table())
        layout["severity"].update(self._build_severity_chart())
        layout["timeline"].update(self._build_timeline())
        layout["recent"].update(self._build_recent_events())

        return layout

    # ── Public API ──────────────────────────────────────────────────────

    def run(self) -> None:
        """Launch the live dashboard.  Press Ctrl+C to exit."""
        try:
            with Live(
                self._build_layout(),
                console=self.console,
                refresh_per_second=1,
                screen=True,
            ) as live:
                import time

                while True:
                    time.sleep(self.refresh_interval)
                    live.update(self._build_layout())
        except KeyboardInterrupt:
            pass
