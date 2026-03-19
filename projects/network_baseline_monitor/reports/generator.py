#!/usr/bin/env python3
"""
reports/generator.py
=====================
Report generation: ASCII terminal dashboard and HTML/JSON anomaly reports.

Functions
---------
ascii_dashboard()   — Colorized terminal table comparing baseline vs. current traffic.
html_report()       — Standalone HTML file with timeline, tables, and severity badges.
json_report()       — Machine-readable JSON export of windows and alerts.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from collector.aggregator import TrafficWindow


# ── Colorama setup ────────────────────────────────────────────────────────────
try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    _COLORS = True
except ImportError:
    _COLORS = False


def _c(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}" if _COLORS else text


# ── ASCII Dashboard ───────────────────────────────────────────────────────────

def ascii_dashboard(
    windows: list[TrafficWindow],
    alerts: list[dict[str, Any]],
    baseline_means: dict[str, float] | None = None,
    max_rows: int = 20,
) -> None:
    """
    Print a colorized terminal dashboard showing recent traffic windows
    compared against baseline means, followed by a recent alerts summary.

    Args:
        windows:         Recent TrafficWindow objects (newest last).
        alerts:          Alert dicts from BaselineStorage.query_alerts().
        baseline_means:  Dict of metric_name -> mean for comparison column.
        max_rows:        Maximum number of window rows to display.
    """
    if _COLORS:
        print(_c("\n" + "=" * 78, Fore.CYAN))
        print(_c("  NETWORK BASELINE MONITOR — Traffic Dashboard", Fore.CYAN + Style.BRIGHT))
        print(_c("=" * 78, Fore.CYAN))
    else:
        print("\n" + "=" * 78)
        print("  NETWORK BASELINE MONITOR — Traffic Dashboard")
        print("=" * 78)

    if not windows:
        print(_c("  No traffic windows found.", Fore.YELLOW if _COLORS else ""))
        return

    # Header row
    col_w = [20, 10, 10, 12, 12, 12]
    headers = ["Timestamp", "Packets", "Bytes", "Ext Out KB", "Src IPs", "Dst IPs"]
    header_line = "  " + "".join(h.ljust(col_w[i]) for i, h in enumerate(headers))
    print(_c(header_line, Style.BRIGHT if _COLORS else ""))
    print("  " + "-" * 76)

    display_windows = windows[-max_rows:]
    bl_ext = baseline_means.get("external_bytes_out", 0) if baseline_means else 0
    bl_bytes = baseline_means.get("total_bytes", 0) if baseline_means else 0

    for w in display_windows:
        ts_str = datetime.fromtimestamp(w.timestamp).strftime("%m-%d %H:%M:%S")
        ext_kb = w.external_bytes_out / 1024
        anomalous = (
            (bl_ext > 0 and w.external_bytes_out > bl_ext * 3) or
            (bl_bytes > 0 and w.total_bytes > bl_bytes * 3)
        )
        row = "  " + "".join([
            ts_str.ljust(col_w[0]),
            str(w.total_packets).ljust(col_w[1]),
            _bytes_human(w.total_bytes).ljust(col_w[2]),
            f"{ext_kb:.1f}".ljust(col_w[3]),
            str(w.unique_src_ips).ljust(col_w[4]),
            str(w.unique_dst_ips).ljust(col_w[5]),
        ])
        if _COLORS and anomalous:
            print(_c(row + " ← ANOMALY", Fore.RED))
        elif _COLORS:
            print(row)
        else:
            suffix = " <- ANOMALY" if anomalous else ""
            print(row + suffix)

    # Baseline comparison summary
    if baseline_means:
        print()
        print(_c("  Baseline Means:", Style.BRIGHT if _COLORS else ""))
        for metric in ("total_bytes", "external_bytes_out", "unique_src_ips"):
            if metric in baseline_means:
                val = _bytes_human(baseline_means[metric]) if 'bytes' in metric else f"{baseline_means[metric]:.1f}"
                print(f"    {metric}: {val}")

    # Alerts summary
    print()
    if alerts:
        if _COLORS:
            print(_c("  Recent Alerts:", Style.BRIGHT + Fore.YELLOW))
        else:
            print("  Recent Alerts:")
        print("  " + "-" * 76)
        for a in alerts[:10]:
            ts_str = datetime.fromtimestamp(a["timestamp"]).strftime("%m-%d %H:%M:%S")
            level_color = Fore.RED if a["level"] == "high" else Fore.YELLOW if _COLORS else ""
            src = a["detail"].get("src_ip", "?")
            line = f"  [{ts_str}] {a['level'].upper():6s} {a['anomaly_type']:25s} score={a['score']:.1f}  src={src}"
            print(_c(line, level_color) if _COLORS else line)
    else:
        print(_c("  No alerts in selected time range.", Fore.GREEN if _COLORS else ""))

    print()


# ── HTML Report ───────────────────────────────────────────────────────────────

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Baseline Monitor Report</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
  h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
  h2 {{ color: #79c0ff; margin-top: 30px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.9em; }}
  th {{ background: #161b22; color: #58a6ff; padding: 8px 12px; text-align: left; border-bottom: 2px solid #30363d; }}
  td {{ padding: 6px 12px; border-bottom: 1px solid #21262d; }}
  tr:hover td {{ background: #161b22; }}
  .badge-high {{ background: #da3633; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
  .badge-medium {{ background: #d29922; color: #000; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
  .badge-low {{ background: #238636; color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
  .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 15px; }}
  .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 15px; }}
  .stat-label {{ font-size: 0.8em; color: #8b949e; }}
  .stat-value {{ font-size: 1.6em; font-weight: bold; color: #58a6ff; margin-top: 5px; }}
  .anomaly-row td {{ color: #f85149; }}
  footer {{ margin-top: 40px; color: #8b949e; font-size: 0.8em; border-top: 1px solid #30363d; padding-top: 10px; }}
  code {{ background: #161b22; padding: 1px 5px; border-radius: 3px; font-size: 0.85em; }}
</style>
</head>
<body>
<h1>Network Baseline Monitor — Anomaly Report</h1>
<p>Generated: {generated_at} &nbsp;|&nbsp; Windows analysed: {window_count} &nbsp;|&nbsp; Alerts: {alert_count}</p>

<h2>Summary</h2>
<div class="stat-grid">
  {stat_cards}
</div>

<h2>Anomaly Timeline</h2>
{alert_table}

<h2>Traffic Windows (last {max_windows})</h2>
{window_table}

<h2>Protocol Distribution</h2>
{protocol_table}

<footer>
  Network Baseline Monitor &mdash; Cybersecurity Homelab &nbsp;|&nbsp;
  <em>Educational tool. Use only on networks you own or have explicit permission to monitor.</em>
</footer>
</body>
</html>
"""


def html_report(
    windows: list[TrafficWindow],
    alerts: list[dict[str, Any]],
    output_path: str | Path,
    baseline_means: dict[str, float] | None = None,
    max_windows: int = 50,
) -> Path:
    """
    Generate a standalone HTML report.

    Args:
        windows:         List of TrafficWindow objects.
        alerts:          Alert dicts from BaselineStorage.query_alerts().
        output_path:     Where to write the .html file.
        baseline_means:  Optional baseline metric means for comparison.
        max_windows:     Maximum number of windows shown in the table.

    Returns:
        Path to the written HTML file.
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Summary stat cards
    total_bytes = sum(w.total_bytes for w in windows)
    total_pkts = sum(w.total_packets for w in windows)
    total_ext = sum(w.external_bytes_out for w in windows)
    high_alerts = sum(1 for a in alerts if a["level"] == "high")
    stat_cards = "\n  ".join([
        _stat_card("Total Traffic", _bytes_human(total_bytes)),
        _stat_card("Total Packets", f"{total_pkts:,}"),
        _stat_card("External Outbound", _bytes_human(total_ext)),
        _stat_card("High Alerts", str(high_alerts)),
        _stat_card("Windows", str(len(windows))),
        _stat_card("Total Alerts", str(len(alerts))),
    ])

    # Alert table
    if alerts:
        rows = []
        for a in alerts:
            ts_str = datetime.fromtimestamp(a["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            badge = f'<span class="badge-{a["level"]}">{a["level"].upper()}</span>'
            src = a["detail"].get("src_ip", "—")
            detail_str = _truncate(json.dumps(a["detail"]), 120)
            rows.append(
                f"<tr><td>{ts_str}</td><td>{badge}</td>"
                f"<td>{a['anomaly_type']}</td><td>{a['score']:.1f}</td>"
                f"<td><code>{src}</code></td><td>{detail_str}</td></tr>"
            )
        alert_table = (
            "<table><tr><th>Timestamp</th><th>Level</th><th>Type</th>"
            "<th>Score</th><th>Source IP</th><th>Detail</th></tr>"
            + "".join(rows) + "</table>"
        )
    else:
        alert_table = "<p>No alerts in this time range.</p>"

    # Window table
    bl_ext = baseline_means.get("external_bytes_out", 0) if baseline_means else 0
    bl_bytes = baseline_means.get("total_bytes", 0) if baseline_means else 0
    recent_windows = windows[-max_windows:]
    win_rows = []
    for w in recent_windows:
        ts_str = datetime.fromtimestamp(w.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        ext_kb = w.external_bytes_out / 1024
        anomalous = (
            (bl_ext > 0 and w.external_bytes_out > bl_ext * 3) or
            (bl_bytes > 0 and w.total_bytes > bl_bytes * 3)
        )
        css_class = ' class="anomaly-row"' if anomalous else ""
        win_rows.append(
            f"<tr{css_class}><td>{ts_str}</td><td>{w.total_packets:,}</td>"
            f"<td>{_bytes_human(w.total_bytes)}</td>"
            f"<td>{ext_kb:.1f} KB</td>"
            f"<td>{w.unique_src_ips}</td><td>{w.unique_dst_ips}</td>"
            f"<td>{'ANOMALY' if anomalous else '—'}</td></tr>"
        )
    window_table = (
        "<table><tr><th>Timestamp</th><th>Packets</th><th>Bytes</th>"
        "<th>Ext Outbound</th><th>Src IPs</th><th>Dst IPs</th><th>Status</th></tr>"
        + "".join(win_rows) + "</table>"
    )

    # Protocol distribution (aggregate over all windows)
    proto_totals: dict[str, int] = {}
    for w in windows:
        for proto, b in w.bytes_per_protocol.items():
            proto_totals[proto] = proto_totals.get(proto, 0) + b
    if proto_totals:
        total = sum(proto_totals.values()) or 1
        proto_rows = "".join(
            f"<tr><td>{p}</td><td>{_bytes_human(b)}</td>"
            f"<td>{b/total*100:.1f}%</td></tr>"
            for p, b in sorted(proto_totals.items(), key=lambda x: x[1], reverse=True)
        )
        protocol_table = (
            "<table><tr><th>Protocol</th><th>Bytes</th><th>Share</th></tr>"
            + proto_rows + "</table>"
        )
    else:
        protocol_table = "<p>No protocol data available.</p>"

    html = _HTML_TEMPLATE.format(
        generated_at=generated_at,
        window_count=len(windows),
        alert_count=len(alerts),
        stat_cards=stat_cards,
        alert_table=alert_table,
        window_table=window_table,
        max_windows=max_windows,
        protocol_table=protocol_table,
    )

    out.write_text(html, encoding="utf-8")
    return out


# ── JSON Report ───────────────────────────────────────────────────────────────

def json_report(
    windows: list[TrafficWindow],
    alerts: list[dict[str, Any]],
    output_path: str | Path,
) -> Path:
    """
    Generate a machine-readable JSON report.

    Returns:
        Path to the written JSON file.
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "window_count": len(windows),
            "alert_count": len(alerts),
            "total_bytes": sum(w.total_bytes for w in windows),
            "total_packets": sum(w.total_packets for w in windows),
            "external_bytes_out": sum(w.external_bytes_out for w in windows),
        },
        "alerts": alerts,
        "windows": [w.to_dict() for w in windows],
    }

    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return out


# ── Helpers ───────────────────────────────────────────────────────────────────

def _bytes_human(n: float) -> str:
    """Human-readable byte count."""
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _stat_card(label: str, value: str) -> str:
    return (
        f'<div class="stat-card">'
        f'<div class="stat-label">{label}</div>'
        f'<div class="stat-value">{value}</div>'
        f'</div>'
    )


def _truncate(s: str, max_len: int) -> str:
    return s if len(s) <= max_len else s[:max_len] + "…"
