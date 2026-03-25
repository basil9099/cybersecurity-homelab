"""
Report Generator Module
-----------------------
Produces HTML executive dashboards and JSON reports from cloud scan results.
HTML dashboard uses Chart.js for interactive charts with a dark theme.
"""

import json
import datetime
from html import escape
from typing import Any

from scanner.base_scanner import Finding
from rules_engine.evaluator import ScanReport, ComplianceScore


SEVERITY_COLORS = {
    "critical": "#d32f2f",
    "high": "#f57c00",
    "medium": "#f9a825",
    "low": "#388e3c",
    "info": "#757575",
}

STATUS_COLORS = {
    "PASS": "#388e3c",
    "FAIL": "#d32f2f",
    "ERROR": "#757575",
}

PROVIDER_COLORS = {
    "aws": "#ff9900",
    "azure": "#0078d4",
    "gcp": "#4285f4",
}


class ReportGenerator:
    def __init__(self, output_base: str = "cloud_security_report"):
        self.output_base = output_base

    def generate_json(self, report: ScanReport) -> str:
        """Write JSON report and return file path."""
        path = f"{self.output_base}.json"
        data = {
            "metadata": report.metadata,
            "overall_score": {
                "percentage": round(report.overall_score.percentage, 1),
                "passed": report.overall_score.passed,
                "failed": report.overall_score.failed,
                "errors": report.overall_score.errors,
                "total": report.overall_score.total_checks,
            },
            "provider_scores": {
                p: {
                    "percentage": round(s.percentage, 1),
                    "passed": s.passed,
                    "failed": s.failed,
                    "errors": s.errors,
                    "total": s.total_checks,
                }
                for p, s in report.provider_scores.items()
            },
            "findings": [f.to_dict() for f in report.findings],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def generate_html(self, report: ScanReport) -> str:
        """Write HTML executive dashboard and return file path."""
        path = f"{self.output_base}.html"
        html = self._build_html(report)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    # ------------------------------------------------------------------
    # Internal HTML builder
    # ------------------------------------------------------------------

    def _build_html(self, report: ScanReport) -> str:
        scan_time = report.metadata.get("scan_time", "N/A")
        providers = report.metadata.get("providers", [])
        demo_mode = report.metadata.get("demo_mode", False)
        version = report.metadata.get("version", "1.0.0")

        overall = report.overall_score
        findings = report.findings

        # Count severities for failed findings
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            if f.status == "FAIL":
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

        total_fail = sum(sev_counts.values())
        total_pass = sum(1 for f in findings if f.status == "PASS")

        # Overall score color
        overall_pct = overall.percentage
        if overall_pct >= 90:
            overall_color = "#388e3c"
        elif overall_pct >= 70:
            overall_color = "#f9a825"
        else:
            overall_color = "#d32f2f"

        # Provider data for charts
        provider_labels = json.dumps([p.upper() for p in sorted(report.provider_scores.keys())])
        provider_scores = json.dumps([round(report.provider_scores[p].percentage, 1) for p in sorted(report.provider_scores.keys())])
        provider_colors = json.dumps([PROVIDER_COLORS.get(p, "#666") for p in sorted(report.provider_scores.keys())])

        # Severity chart data
        sev_labels = json.dumps(["Critical", "High", "Medium", "Low", "Info"])
        sev_data = json.dumps([sev_counts["critical"], sev_counts["high"], sev_counts["medium"], sev_counts["low"], sev_counts["info"]])
        sev_colors = json.dumps([SEVERITY_COLORS["critical"], SEVERITY_COLORS["high"], SEVERITY_COLORS["medium"], SEVERITY_COLORS["low"], SEVERITY_COLORS["info"]])

        # Build provider sections
        provider_sections = ""
        for provider in sorted(report.provider_scores.keys()):
            provider_sections += self._build_provider_section(provider, report)

        # Build findings table
        fail_findings = [f for f in findings if f.status == "FAIL"]
        findings_rows = self._build_findings_rows(fail_findings)

        # Build CIS compliance matrix
        cis_matrix = self._build_cis_matrix(findings)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NIMBUS — Cloud Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: #1a1a2e;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}

        /* Header */
        .header {{
            text-align: center;
            padding: 30px 0;
            border-bottom: 2px solid #00e5ff;
            margin-bottom: 30px;
        }}
        .header h1 {{ color: #00e5ff; font-size: 2.2em; margin-bottom: 5px; }}
        .header .subtitle {{ color: #aaa; font-size: 1.1em; }}
        .header .meta {{ color: #888; font-size: 0.9em; margin-top: 10px; }}
        .demo-badge {{
            display: inline-block;
            background: #f57c00;
            color: #fff;
            padding: 2px 10px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            margin-left: 8px;
        }}

        /* Cards grid */
        .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .card {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            border: 1px solid #2a2a4a;
        }}
        .card .value {{ font-size: 2.2em; font-weight: bold; }}
        .card .label {{ color: #aaa; font-size: 0.9em; margin-top: 5px; }}
        .card.critical .value {{ color: #d32f2f; }}
        .card.high .value {{ color: #f57c00; }}
        .card.medium .value {{ color: #f9a825; }}
        .card.low .value {{ color: #388e3c; }}
        .card.pass .value {{ color: #388e3c; }}
        .card.total .value {{ color: #00e5ff; }}

        /* Charts section */
        .charts {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; margin-bottom: 30px; }}
        .chart-box {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            border: 1px solid #2a2a4a;
        }}
        .chart-box h3 {{ color: #00e5ff; margin-bottom: 15px; text-align: center; }}

        /* Provider sections */
        .provider-section {{
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #2a2a4a;
        }}
        .provider-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #2a2a4a;
        }}
        .provider-header h3 {{ color: #00e5ff; }}
        .provider-score {{ font-size: 1.5em; font-weight: bold; }}

        /* Section titles */
        .section-title {{
            color: #00e5ff;
            font-size: 1.4em;
            margin: 30px 0 15px 0;
            padding-bottom: 8px;
            border-bottom: 1px solid #2a2a4a;
        }}

        /* Tables */
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th {{
            background: #0f3460;
            color: #00e5ff;
            padding: 12px 10px;
            text-align: left;
            font-weight: 600;
            font-size: 0.85em;
            text-transform: uppercase;
        }}
        td {{ padding: 10px; border-bottom: 1px solid #2a2a4a; font-size: 0.9em; }}
        tr:hover {{ background: #1a2a4a; }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: #d32f2f; color: #fff; }}
        .badge-high {{ background: #f57c00; color: #fff; }}
        .badge-medium {{ background: #f9a825; color: #000; }}
        .badge-low {{ background: #388e3c; color: #fff; }}
        .badge-info {{ background: #757575; color: #fff; }}
        .badge-pass {{ background: #388e3c; color: #fff; }}
        .badge-fail {{ background: #d32f2f; color: #fff; }}
        .badge-error {{ background: #757575; color: #fff; }}

        /* Remediation */
        .remediation {{
            background: #0f3460;
            border-left: 3px solid #00e5ff;
            padding: 8px 12px;
            margin-top: 5px;
            font-size: 0.85em;
            color: #aaa;
            border-radius: 0 4px 4px 0;
        }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 20px 0;
            margin-top: 30px;
            border-top: 1px solid #2a2a4a;
            color: #666;
            font-size: 0.85em;
        }}

        /* Responsive */
        @media (max-width: 900px) {{
            .charts {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">

        <!-- Header -->
        <div class="header">
            <h1>NIMBUS{' <span class="demo-badge">DEMO</span>' if demo_mode else ''}</h1>
            <div class="subtitle">Cloud Security Posture Report</div>
            <div class="meta">
                Scanned: {escape(str(scan_time))} |
                Providers: {', '.join(p.upper() for p in providers)} |
                v{escape(version)}
            </div>
        </div>

        <!-- Summary Cards -->
        <div class="cards">
            <div class="card total">
                <div class="value">{overall.total_checks}</div>
                <div class="label">Total Checks</div>
            </div>
            <div class="card pass">
                <div class="value">{total_pass}</div>
                <div class="label">Passed</div>
            </div>
            <div class="card critical">
                <div class="value">{sev_counts['critical']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="card high">
                <div class="value">{sev_counts['high']}</div>
                <div class="label">High</div>
            </div>
            <div class="card medium">
                <div class="value">{sev_counts['medium']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="card low">
                <div class="value">{sev_counts['low']}</div>
                <div class="label">Low</div>
            </div>
        </div>

        <!-- Charts -->
        <div class="charts">
            <div class="chart-box">
                <h3>Overall Compliance</h3>
                <canvas id="overallChart"></canvas>
            </div>
            <div class="chart-box">
                <h3>Compliance by Provider</h3>
                <canvas id="providerChart"></canvas>
            </div>
            <div class="chart-box">
                <h3>Failed Findings by Severity</h3>
                <canvas id="severityChart"></canvas>
            </div>
        </div>

        <!-- Provider Breakdowns -->
        <h2 class="section-title">Provider Breakdown</h2>
        {provider_sections}

        <!-- CIS Benchmark Compliance Matrix -->
        <h2 class="section-title">CIS Benchmark Compliance</h2>
        {cis_matrix}

        <!-- Detailed Findings -->
        <h2 class="section-title">Failed Findings Detail</h2>
        {self._build_findings_table(fail_findings) if fail_findings else '<p style="color: #888;">No failed findings.</p>'}

        <!-- Footer -->
        <div class="footer">
            <p>Generated by NIMBUS v{escape(version)} — Cloud Security Scanner</p>
            <p>This report is for authorized security assessment purposes only.</p>
            <p>Report generated: {escape(str(datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')))}</p>
        </div>
    </div>

    <script>
        // Overall Compliance Doughnut
        new Chart(document.getElementById('overallChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['Passed', 'Failed'],
                datasets: [{{
                    data: [{overall.passed}, {overall.failed}],
                    backgroundColor: ['#388e3c', '#d32f2f'],
                    borderWidth: 0,
                }}]
            }},
            options: {{
                responsive: true,
                cutout: '70%',
                plugins: {{
                    legend: {{ display: true, position: 'bottom', labels: {{ color: '#e0e0e0' }} }},
                    tooltip: {{ enabled: true }},
                }},
            }},
            plugins: [{{
                id: 'centerText',
                afterDraw(chart) {{
                    const {{ ctx, chartArea: {{ width, height }} }} = chart;
                    ctx.save();
                    ctx.font = 'bold 28px Segoe UI';
                    ctx.fillStyle = '{overall_color}';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText('{overall.percentage:.0f}%', width / 2 + chart.chartArea.left / 2, height / 2 + chart.chartArea.top / 2);
                    ctx.restore();
                }}
            }}]
        }});

        // Provider Compliance Bar Chart
        new Chart(document.getElementById('providerChart'), {{
            type: 'bar',
            data: {{
                labels: {provider_labels},
                datasets: [{{
                    label: 'Compliance %',
                    data: {provider_scores},
                    backgroundColor: {provider_colors},
                    borderWidth: 0,
                    borderRadius: 4,
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    y: {{
                        beginAtZero: true,
                        max: 100,
                        ticks: {{ color: '#aaa', callback: v => v + '%' }},
                        grid: {{ color: '#2a2a4a' }},
                    }},
                    x: {{ ticks: {{ color: '#aaa' }}, grid: {{ display: false }} }},
                }},
                plugins: {{
                    legend: {{ display: false }},
                }},
            }},
        }});

        // Severity Distribution Chart
        new Chart(document.getElementById('severityChart'), {{
            type: 'bar',
            data: {{
                labels: {sev_labels},
                datasets: [{{
                    label: 'Count',
                    data: {sev_data},
                    backgroundColor: {sev_colors},
                    borderWidth: 0,
                    borderRadius: 4,
                }}]
            }},
            options: {{
                indexAxis: 'y',
                responsive: true,
                scales: {{
                    x: {{
                        beginAtZero: true,
                        ticks: {{ color: '#aaa', stepSize: 1 }},
                        grid: {{ color: '#2a2a4a' }},
                    }},
                    y: {{ ticks: {{ color: '#aaa' }}, grid: {{ display: false }} }},
                }},
                plugins: {{
                    legend: {{ display: false }},
                }},
            }},
        }});
    </script>
</body>
</html>"""

    def _build_provider_section(self, provider: str, report: ScanReport) -> str:
        score = report.provider_scores[provider]
        pct = score.percentage

        if pct >= 90:
            color = "#388e3c"
        elif pct >= 70:
            color = "#f9a825"
        else:
            color = "#d32f2f"

        provider_findings = [f for f in report.findings if f.provider == provider]

        # Group by resource type
        resource_types: dict[str, dict[str, int]] = {}
        for f in provider_findings:
            rt = f.resource_type
            if rt not in resource_types:
                resource_types[rt] = {"PASS": 0, "FAIL": 0, "ERROR": 0}
            resource_types[rt][f.status] = resource_types[rt].get(f.status, 0) + 1

        rows = ""
        for rt, counts in sorted(resource_types.items()):
            total = counts["PASS"] + counts["FAIL"]
            rt_pct = (counts["PASS"] / total * 100) if total > 0 else 0
            rows += f"""<tr>
                <td>{escape(rt)}</td>
                <td>{counts['PASS']}</td>
                <td>{counts['FAIL']}</td>
                <td>{counts['ERROR']}</td>
                <td><span style="color: {'#388e3c' if rt_pct >= 90 else '#f9a825' if rt_pct >= 70 else '#d32f2f'}">{rt_pct:.0f}%</span></td>
            </tr>"""

        return f"""
        <div class="provider-section">
            <div class="provider-header">
                <h3 style="color: {PROVIDER_COLORS.get(provider, '#666')}">{escape(provider.upper())}</h3>
                <span class="provider-score" style="color: {color}">{pct:.0f}% Compliant</span>
            </div>
            <table>
                <thead>
                    <tr><th>Resource Type</th><th>Passed</th><th>Failed</th><th>Errors</th><th>Score</th></tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    def _build_cis_matrix(self, findings: list[Finding]) -> str:
        """Build a CIS benchmark compliance matrix table."""
        # Group findings by CIS benchmark
        cis_map: dict[str, dict[str, Any]] = {}
        for f in findings:
            key = f.cis_benchmark
            if key not in cis_map:
                cis_map[key] = {"benchmark": key, "rule_id": f.rule_id, "title": f.title, "passed": 0, "failed": 0}
            if f.status == "PASS":
                cis_map[key]["passed"] += 1
            elif f.status == "FAIL":
                cis_map[key]["failed"] += 1

        rows = ""
        for key in sorted(cis_map.keys()):
            entry = cis_map[key]
            status = "PASS" if entry["failed"] == 0 else "FAIL"
            badge_class = "badge-pass" if status == "PASS" else "badge-fail"
            rows += f"""<tr>
                <td><code>{escape(entry['rule_id'])}</code></td>
                <td>{escape(entry['benchmark'])}</td>
                <td>{escape(entry['title'])}</td>
                <td>{entry['passed']}</td>
                <td>{entry['failed']}</td>
                <td><span class="badge {badge_class}">{status}</span></td>
            </tr>"""

        return f"""<table>
            <thead>
                <tr><th>Rule ID</th><th>CIS Benchmark</th><th>Check</th><th>Pass</th><th>Fail</th><th>Status</th></tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>"""

    def _build_findings_table(self, findings: list[Finding]) -> str:
        """Build detailed findings table for FAIL results."""
        rows = self._build_findings_rows(findings)
        return f"""<table>
            <thead>
                <tr><th>Rule</th><th>Provider</th><th>Resource</th><th>Severity</th><th>Description</th><th>CIS Ref</th></tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>"""

    def _build_findings_rows(self, findings: list[Finding]) -> str:
        """Build HTML table rows for findings."""
        rows = ""
        for f in sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5)):
            badge_class = f"badge-{f.severity}"
            rows += f"""<tr>
                <td><code>{escape(f.rule_id)}</code></td>
                <td>{escape(f.provider.upper())}</td>
                <td style="font-size: 0.8em; word-break: break-all;">{escape(f.resource_id)}</td>
                <td><span class="badge {badge_class}">{escape(f.severity.upper())}</span></td>
                <td>
                    {escape(f.description)}
                    <div class="remediation"><strong>Remediation:</strong> {escape(f.remediation)}</div>
                </td>
                <td style="font-size: 0.8em;">{escape(f.cis_benchmark)}</td>
            </tr>"""
        return rows
