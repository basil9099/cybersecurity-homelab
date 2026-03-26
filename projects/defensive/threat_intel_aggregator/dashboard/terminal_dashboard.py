"""Rich terminal dashboard for WATCHTOWER threat intelligence."""

from __future__ import annotations

from typing import Any

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from correlation.ioc_database import IOCDatabase
from feeds.base_feed import FeedHealth
from models.enrichment import EnrichmentResult
from models.indicator import Indicator


class TerminalDashboard:
    """Renders a rich terminal dashboard summarising threat intelligence state.

    Sections:
      - IOC statistics (total, by type, by source)
      - Recent high-confidence threats
      - Correlation hits
      - Feed health status
    """

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    # ------------------------------------------------------------------
    # Full dashboard
    # ------------------------------------------------------------------

    def render(
        self,
        ioc_db: IOCDatabase,
        enrichment_results: list[EnrichmentResult],
        feed_health: list[FeedHealth],
    ) -> None:
        """Print the complete dashboard to the terminal."""
        self.console.clear()
        self.console.print()
        self._print_banner()
        self.console.print()
        self._print_ioc_stats(ioc_db)
        self.console.print()
        self._print_top_threats(ioc_db)
        self.console.print()
        self._print_correlation_hits(enrichment_results)
        self.console.print()
        self._print_feed_health(feed_health)
        self.console.print()

    # ------------------------------------------------------------------
    # Individual panels
    # ------------------------------------------------------------------

    def _print_banner(self) -> None:
        banner = Text.from_markup(
            "[bold cyan]"
            "  _    _  ___ _____ _____ _   _ _____ _____  _    _ _____ ____  \n"
            " | |  | |/ _ |_   _/ ____| | | |_   _/ _ \\ \\| |  | | ____|  _ \\ \n"
            " | |/\\| | |_| || || |    | |_| | | || | | | | |/\\| |  _| | |_) |\n"
            " \\  /\\  /  _  || || |___ |  _  | | || |_| | \\  /\\  / |___|  _ < \n"
            "  \\/  \\/\\_| |_/|_| \\____|_| |_| |_| \\___/ \\/  \\/  \\/_____|_| \\_\\\n"
            "[/bold cyan]"
            "\n[dim]Threat Intelligence Feed Aggregator[/dim]"
        )
        self.console.print(Panel(banner, border_style="cyan", expand=False))

    def _print_ioc_stats(self, ioc_db: IOCDatabase) -> None:
        stats = ioc_db.stats()
        table = Table(title="IOC Database Statistics", border_style="blue")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Total Indicators", str(stats["total_indicators"]))
        table.add_row("Avg Confidence", f"{stats['avg_confidence']:.3f}")
        table.add_row("", "")

        for ioc_type, count in sorted(stats.get("by_type", {}).items()):
            table.add_row(f"  Type: {ioc_type}", str(count))

        for source, count in sorted(stats.get("by_source", {}).items()):
            table.add_row(f"  Source: {source}", str(count))

        self.console.print(Panel(table, border_style="blue", title="Database"))

    def _print_top_threats(self, ioc_db: IOCDatabase, limit: int = 10) -> None:
        top = ioc_db.search(min_confidence=0.5, limit=limit)
        table = Table(title="Top Threats (by confidence)", border_style="red")
        table.add_column("IOC", style="bold", max_width=50)
        table.add_column("Type")
        table.add_column("Source")
        table.add_column("Confidence", justify="right")
        table.add_column("Severity")
        table.add_column("Tags", max_width=30)

        for ind in top:
            sev = ind.severity_label
            sev_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "green",
                "informational": "dim",
            }.get(sev, "")
            table.add_row(
                ind.value,
                ind.ioc_type.value,
                ind.source,
                f"{ind.confidence:.2f}",
                Text(sev.upper(), style=sev_style),
                ", ".join(ind.tags[:5]),
            )

        self.console.print(Panel(table, border_style="red", title="Threats"))

    def _print_correlation_hits(
        self, results: list[EnrichmentResult], limit: int = 10
    ) -> None:
        table = Table(title="Correlation Hits", border_style="magenta")
        table.add_column("#", justify="right")
        table.add_column("Score", justify="right")
        table.add_column("Severity")
        table.add_column("Matched IOCs", max_width=45)
        table.add_column("Action")
        table.add_column("Event Summary", max_width=40)

        sorted_results = sorted(
            results, key=lambda r: r.threat_score, reverse=True
        )[:limit]

        for idx, result in enumerate(sorted_results, start=1):
            sev = result.severity_label
            sev_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "green",
                "informational": "dim",
            }.get(sev, "")
            iocs = ", ".join(
                ind.value for ind in result.matched_indicators[:3]
            )
            actions = ", ".join(a.value for a in result.recommended_actions)
            event_msg = result.original_event.get("message", "")[:40]
            table.add_row(
                str(idx),
                f"{result.threat_score:.0f}",
                Text(sev.upper(), style=sev_style),
                iocs,
                actions,
                event_msg,
            )

        if not sorted_results:
            table.add_row("-", "-", "-", "No correlation hits", "-", "-")

        self.console.print(
            Panel(table, border_style="magenta", title="Correlations")
        )

    def _print_feed_health(self, health_list: list[FeedHealth]) -> None:
        table = Table(title="Feed Health Status", border_style="green")
        table.add_column("Feed", style="bold")
        table.add_column("Status")
        table.add_column("Last Fetch")
        table.add_column("Indicators", justify="right")
        table.add_column("Avg Latency", justify="right")
        table.add_column("Last Error", max_width=35)

        for h in health_list:
            status_text = Text(
                "ONLINE" if h.available else "OFFLINE",
                style="green" if h.available else "red",
            )
            last_fetch = (
                h.last_fetch.strftime("%H:%M:%S") if h.last_fetch else "never"
            )
            table.add_row(
                h.name,
                status_text,
                last_fetch,
                str(h.indicators_fetched),
                f"{h.avg_response_ms:.0f} ms",
                h.last_error or "-",
            )

        self.console.print(Panel(table, border_style="green", title="Feeds"))
