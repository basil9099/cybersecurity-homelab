"""
dashboard.html_report — Self-contained HTML report generator.

Produces a single HTML file with inline CSS (no external dependencies)
containing summary statistics, severity breakdown, event table,
timeline, and source analysis.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from storage.database import EventDatabase


class HTMLReportGenerator:
    """Generate a self-contained HTML security report."""

    def __init__(self, db: EventDatabase) -> None:
        self.db = db

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _esc(text: str) -> str:
        return html.escape(str(text))

    @staticmethod
    def _sev_color(severity: str) -> str:
        return {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
            "info": "#6c757d",
        }.get(severity.lower(), "#6c757d")

    # ── Section builders ────────────────────────────────────────────────

    def _summary_section(self) -> str:
        total = self.db.get_event_count()
        sources = self.db.get_event_counts_by_source()
        severity = self.db.get_severity_distribution()
        crit_high = severity.get("critical", 0) + severity.get("high", 0)

        return f"""
        <div class="summary-grid">
            <div class="card"><h3>{total}</h3><p>Total Events</p></div>
            <div class="card"><h3>{len(sources)}</h3><p>Sources</p></div>
            <div class="card card-alert"><h3>{crit_high}</h3><p>Critical / High</p></div>
            <div class="card"><h3>{len(severity)}</h3><p>Severity Levels</p></div>
        </div>
        """

    def _severity_pie_section(self) -> str:
        dist = self.db.get_severity_distribution()
        total = sum(dist.values()) or 1

        # Build CSS conic-gradient stops for a pie chart.
        stops: list[str] = []
        cumulative = 0.0
        ordered = ["critical", "high", "medium", "low", "info"]
        legend_items: list[str] = []

        for sev in ordered:
            count = dist.get(sev, 0)
            pct = (count / total) * 100
            color = self._sev_color(sev)
            start = cumulative
            cumulative += pct
            stops.append(f"{color} {start:.1f}% {cumulative:.1f}%")
            legend_items.append(
                f'<span class="legend-item">'
                f'<span class="legend-dot" style="background:{color}"></span>'
                f'{self._esc(sev.upper())} ({count})'
                f'</span>'
            )

        gradient = ", ".join(stops) if stops else "#ccc 0% 100%"

        return f"""
        <div class="severity-section">
            <div class="pie" style="background: conic-gradient({gradient});"></div>
            <div class="legend">{''.join(legend_items)}</div>
        </div>
        """

    def _source_breakdown_section(self) -> str:
        counts = self.db.get_event_counts_by_source()
        max_count = max(counts.values(), default=1)
        rows = ""
        for source, count in counts.items():
            pct = (count / max_count) * 100
            rows += f"""
            <div class="bar-row">
                <span class="bar-label">{self._esc(source)}</span>
                <div class="bar-track">
                    <div class="bar-fill" style="width:{pct:.0f}%"></div>
                </div>
                <span class="bar-value">{count}</span>
            </div>
            """
        return f'<div class="source-breakdown">{rows}</div>'

    def _timeline_section(self) -> str:
        timeline = self.db.get_timeline(hours=24)
        if not timeline:
            return "<p>No timeline data available.</p>"

        max_count = max(t["count"] for t in timeline) or 1
        bars = ""
        for entry in timeline:
            height = int((entry["count"] / max_count) * 120)
            label = entry["hour"][-5:] if len(entry["hour"]) >= 5 else entry["hour"]
            bars += f"""
            <div class="tl-bar-wrapper">
                <div class="tl-bar" style="height:{height}px;" title="{self._esc(entry['hour'])}: {entry['count']}"></div>
                <span class="tl-label">{self._esc(label)}</span>
            </div>
            """
        return f'<div class="timeline-chart">{bars}</div>'

    def _event_table_section(self, limit: int = 100) -> str:
        events = self.db.get_recent_events(limit=limit)
        rows = ""
        for ev in events:
            color = self._sev_color(ev.severity)
            short_ts = ev.timestamp[:19] if len(ev.timestamp) >= 19 else ev.timestamp
            rows += f"""
            <tr>
                <td class="mono">{self._esc(short_ts)}</td>
                <td><span class="badge" style="background:{color}">{self._esc(ev.severity.upper())}</span></td>
                <td>{self._esc(ev.source)}</td>
                <td>{self._esc(ev.category)}</td>
                <td>{self._esc(ev.message[:120])}</td>
            </tr>
            """
        return f"""
        <table class="event-table">
            <thead>
                <tr><th>Timestamp</th><th>Severity</th><th>Source</th><th>Category</th><th>Message</th></tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
        """

    # ── Full report ─────────────────────────────────────────────────────

    def generate(self, output_path: Path | str) -> Path:
        """Write the HTML report to *output_path* and return the path."""
        output_path = Path(output_path)
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SENTINEL — Security Report</title>
<style>
    :root {{
        --bg: #0d1117; --fg: #c9d1d9; --card-bg: #161b22;
        --border: #30363d; --accent: #58a6ff;
    }}
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
           background: var(--bg); color: var(--fg); padding: 2rem; }}
    h1 {{ color: var(--accent); margin-bottom: .25rem; }}
    h2 {{ color: var(--accent); margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: .5rem; }}
    .subtitle {{ color: #8b949e; margin-bottom: 2rem; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; }}
    .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px;
             padding: 1.5rem; text-align: center; }}
    .card h3 {{ font-size: 2rem; color: var(--accent); }}
    .card-alert h3 {{ color: #dc3545; }}
    .severity-section {{ display: flex; align-items: center; gap: 2rem; flex-wrap: wrap; }}
    .pie {{ width: 160px; height: 160px; border-radius: 50%; flex-shrink: 0; }}
    .legend {{ display: flex; flex-direction: column; gap: .4rem; }}
    .legend-item {{ display: flex; align-items: center; gap: .5rem; }}
    .legend-dot {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; }}
    .bar-row {{ display: flex; align-items: center; gap: .75rem; margin-bottom: .5rem; }}
    .bar-label {{ width: 180px; text-align: right; font-size: .9rem; }}
    .bar-track {{ flex: 1; background: var(--border); border-radius: 4px; height: 18px; }}
    .bar-fill {{ background: var(--accent); height: 100%; border-radius: 4px; transition: width .3s; }}
    .bar-value {{ width: 50px; font-size: .9rem; }}
    .timeline-chart {{ display: flex; align-items: flex-end; gap: 4px; height: 140px; padding-top: 10px; overflow-x: auto; }}
    .tl-bar-wrapper {{ display: flex; flex-direction: column; align-items: center; }}
    .tl-bar {{ width: 18px; background: var(--accent); border-radius: 3px 3px 0 0; min-height: 2px; }}
    .tl-label {{ font-size: .6rem; color: #8b949e; margin-top: 4px; writing-mode: vertical-rl; }}
    .event-table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
    .event-table th {{ background: var(--card-bg); padding: .6rem; text-align: left;
                       border-bottom: 2px solid var(--border); position: sticky; top: 0; }}
    .event-table td {{ padding: .5rem .6rem; border-bottom: 1px solid var(--border); }}
    .event-table tr:hover {{ background: rgba(88,166,255,0.05); }}
    .mono {{ font-family: monospace; white-space: nowrap; }}
    .badge {{ padding: 2px 8px; border-radius: 4px; color: #fff; font-size: .75rem;
              font-weight: 600; display: inline-block; }}
    footer {{ margin-top: 3rem; text-align: center; color: #484f58; font-size: .8rem; }}
</style>
</head>
<body>
    <h1>SENTINEL</h1>
    <p class="subtitle">Security Event Report — generated {self._esc(generated)}</p>

    <h2>Summary</h2>
    {self._summary_section()}

    <h2>Severity Distribution</h2>
    {self._severity_pie_section()}

    <h2>Sources</h2>
    {self._source_breakdown_section()}

    <h2>Timeline (24 h)</h2>
    {self._timeline_section()}

    <h2>Recent Events</h2>
    {self._event_table_section()}

    <footer>
        SENTINEL SIEM Log Pipeline &mdash; for authorised security monitoring only.
    </footer>
</body>
</html>"""

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report_html, encoding="utf-8")
        return output_path
