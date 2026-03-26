"""HTML threat intelligence report generator."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from correlation.ioc_database import IOCDatabase
from feeds.base_feed import FeedHealth
from models.enrichment import EnrichmentResult
from models.indicator import Indicator


class HTMLReportGenerator:
    """Generates a standalone HTML threat intelligence report.

    The report includes:
      - Executive summary with aggregate statistics
      - IOC table with risk scores
      - Correlation results with recommended actions
      - Feed health dashboard
    """

    def generate(
        self,
        ioc_db: IOCDatabase,
        enrichment_results: list[EnrichmentResult],
        feed_health: list[FeedHealth],
        output_path: str | Path = "watchtower_report.html",
    ) -> Path:
        """Write the HTML report and return its path."""
        out = Path(output_path)
        stats = ioc_db.stats()
        top_indicators = ioc_db.search(min_confidence=0.3, limit=50)
        sorted_results = sorted(
            enrichment_results, key=lambda r: r.threat_score, reverse=True
        )

        body = self._render(stats, top_indicators, sorted_results, feed_health)
        out.write_text(body, encoding="utf-8")
        return out.resolve()

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render(
        self,
        stats: dict[str, Any],
        indicators: list[Indicator],
        results: list[EnrichmentResult],
        health: list[FeedHealth],
    ) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        actionable = [r for r in results if r.is_actionable]

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WATCHTOWER - Threat Intelligence Report</title>
<style>
  :root {{
    --bg: #0d1117; --fg: #c9d1d9; --accent: #58a6ff;
    --red: #f85149; --orange: #d29922; --green: #3fb950;
    --card-bg: #161b22; --border: #30363d;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--fg); font-family: -apple-system, 'Segoe UI', sans-serif; padding: 2rem; }}
  h1 {{ color: var(--accent); font-size: 2rem; margin-bottom: .5rem; }}
  h2 {{ color: var(--accent); font-size: 1.3rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: .4rem; }}
  .meta {{ color: #8b949e; font-size: .85rem; margin-bottom: 2rem; }}
  .cards {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1rem; }}
  .card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; min-width: 160px; flex: 1; }}
  .card .label {{ font-size: .8rem; color: #8b949e; text-transform: uppercase; }}
  .card .value {{ font-size: 1.8rem; font-weight: bold; color: var(--accent); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card-bg); border-radius: 8px; overflow: hidden; margin-bottom: 1rem; }}
  th {{ background: #21262d; text-align: left; padding: .6rem .8rem; font-size: .8rem; text-transform: uppercase; color: #8b949e; }}
  td {{ padding: .5rem .8rem; border-top: 1px solid var(--border); font-size: .85rem; }}
  tr:hover td {{ background: #1c2128; }}
  .sev-critical {{ color: var(--red); font-weight: bold; }}
  .sev-high {{ color: #f0883e; }}
  .sev-medium {{ color: var(--orange); }}
  .sev-low {{ color: var(--green); }}
  .sev-informational {{ color: #8b949e; }}
  .status-online {{ color: var(--green); }}
  .status-offline {{ color: var(--red); }}
  .disclaimer {{ margin-top: 3rem; padding: 1rem; border: 1px solid var(--border); border-radius: 8px; font-size: .8rem; color: #8b949e; }}
</style>
</head>
<body>
<h1>WATCHTOWER Threat Intelligence Report</h1>
<p class="meta">Generated: {now}</p>

<h2>Executive Summary</h2>
<div class="cards">
  <div class="card"><div class="label">Total IOCs</div><div class="value">{stats['total_indicators']}</div></div>
  <div class="card"><div class="label">Avg Confidence</div><div class="value">{stats['avg_confidence']:.2f}</div></div>
  <div class="card"><div class="label">Correlation Hits</div><div class="value">{len(results)}</div></div>
  <div class="card"><div class="label">Actionable Alerts</div><div class="value" style="color:var(--red)">{len(actionable)}</div></div>
</div>

<h2>IOC Inventory</h2>
{self._ioc_table(indicators)}

<h2>Correlation Results</h2>
{self._correlation_table(results)}

<h2>Feed Health</h2>
{self._health_table(health)}

<div class="disclaimer">
<strong>Disclaimer:</strong> This report is generated for defensive security
purposes within an authorized homelab environment. All indicators of
compromise are sourced from publicly available threat intelligence feeds.
Do not use this data for offensive operations.
</div>
</body>
</html>"""

    def _ioc_table(self, indicators: list[Indicator]) -> str:
        if not indicators:
            return "<p>No indicators in database.</p>"
        rows = ""
        for ind in indicators:
            sev_cls = f"sev-{ind.severity_label}"
            tags = html.escape(", ".join(ind.tags[:5]))
            rows += (
                f"<tr>"
                f"<td>{html.escape(ind.value)}</td>"
                f"<td>{ind.ioc_type.value}</td>"
                f"<td>{html.escape(ind.source)}</td>"
                f"<td>{ind.confidence:.2f}</td>"
                f"<td class='{sev_cls}'>{ind.severity_label.upper()}</td>"
                f"<td>{tags}</td>"
                f"</tr>\n"
            )
        return (
            "<table><thead><tr>"
            "<th>IOC</th><th>Type</th><th>Source</th>"
            "<th>Confidence</th><th>Severity</th><th>Tags</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>"
        )

    def _correlation_table(self, results: list[EnrichmentResult]) -> str:
        if not results:
            return "<p>No correlation hits.</p>"
        rows = ""
        for idx, r in enumerate(results, 1):
            sev_cls = f"sev-{r.severity_label}"
            iocs = html.escape(
                ", ".join(ind.value for ind in r.matched_indicators[:3])
            )
            actions = ", ".join(a.value for a in r.recommended_actions)
            msg = html.escape(r.original_event.get("message", "")[:60])
            rows += (
                f"<tr>"
                f"<td>{idx}</td>"
                f"<td>{r.threat_score:.0f}</td>"
                f"<td class='{sev_cls}'>{r.severity_label.upper()}</td>"
                f"<td>{iocs}</td>"
                f"<td>{actions}</td>"
                f"<td>{msg}</td>"
                f"</tr>\n"
            )
        return (
            "<table><thead><tr>"
            "<th>#</th><th>Score</th><th>Severity</th>"
            "<th>Matched IOCs</th><th>Actions</th><th>Event</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>"
        )

    def _health_table(self, health: list[FeedHealth]) -> str:
        rows = ""
        for h in health:
            status_cls = "status-online" if h.available else "status-offline"
            status = "ONLINE" if h.available else "OFFLINE"
            last = h.last_fetch.strftime("%H:%M:%S") if h.last_fetch else "never"
            err = html.escape(h.last_error or "-")
            rows += (
                f"<tr>"
                f"<td>{html.escape(h.name)}</td>"
                f"<td class='{status_cls}'>{status}</td>"
                f"<td>{last}</td>"
                f"<td>{h.indicators_fetched}</td>"
                f"<td>{h.avg_response_ms:.0f} ms</td>"
                f"<td>{err}</td>"
                f"</tr>\n"
            )
        return (
            "<table><thead><tr>"
            "<th>Feed</th><th>Status</th><th>Last Fetch</th>"
            "<th>Indicators</th><th>Latency</th><th>Error</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>"
        )
