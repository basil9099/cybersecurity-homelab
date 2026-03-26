"""Incident report generator producing JSON and HTML outputs.

Generates comprehensive incident response reports including timelines,
actions taken, evidence collected, and NIST 800-61 phase mapping.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Template

from models.alert import Alert
from models.response import ResponseResult

# HTML report template
_HTML_TEMPLATE = Template("""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AEGIS Incident Report - {{ report.response_id }}</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --border: #30363d;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-purple: #bc8cff;
            --accent-cyan: #39d2c0;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }
        .container { max-width: 1100px; margin: 0 auto; }
        .header {
            text-align: center;
            padding: 2rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 2rem;
        }
        .header h1 { color: var(--accent-blue); font-size: 1.8rem; }
        .header .subtitle { color: var(--text-secondary); margin-top: 0.5rem; }
        .header .report-id { color: var(--accent-cyan); font-family: monospace; margin-top: 0.5rem; }
        .section {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 8px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }
        .section-title {
            background: var(--bg-tertiary);
            padding: 0.8rem 1.2rem;
            font-weight: 600;
            border-bottom: 1px solid var(--border);
            color: var(--accent-blue);
        }
        .section-body { padding: 1.2rem; }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
        }
        .info-item label { color: var(--text-secondary); font-size: 0.85rem; display: block; }
        .info-item .value { font-weight: 500; margin-top: 0.2rem; }
        .status-badge {
            display: inline-block;
            padding: 0.2rem 0.8rem;
            border-radius: 12px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        .status-success { background: rgba(63,185,80,0.15); color: var(--accent-green); }
        .status-failed { background: rgba(248,81,73,0.15); color: var(--accent-red); }
        .status-escalated { background: rgba(210,153,34,0.15); color: var(--accent-yellow); }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        th {
            text-align: left;
            padding: 0.7rem;
            background: var(--bg-tertiary);
            color: var(--accent-blue);
            border-bottom: 1px solid var(--border);
        }
        td {
            padding: 0.7rem;
            border-bottom: 1px solid var(--border);
        }
        tr:last-child td { border-bottom: none; }
        .phase-tag {
            display: inline-block;
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
        }
        .phase-detection { background: rgba(210,153,34,0.2); color: var(--accent-yellow); }
        .phase-containment { background: rgba(248,81,73,0.2); color: var(--accent-red); }
        .phase-eradication { background: rgba(188,140,255,0.2); color: var(--accent-purple); }
        .phase-recovery { background: rgba(63,185,80,0.2); color: var(--accent-green); }
        .phase-post_incident { background: rgba(57,210,192,0.2); color: var(--accent-cyan); }
        .phase-preparation { background: rgba(88,166,255,0.2); color: var(--accent-blue); }
        .timeline-item {
            padding: 0.6rem 0;
            border-left: 2px solid var(--border);
            padding-left: 1.2rem;
            margin-left: 0.5rem;
            position: relative;
        }
        .timeline-item::before {
            content: '';
            position: absolute;
            left: -5px;
            top: 1rem;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent-blue);
        }
        .timeline-time { color: var(--text-secondary); font-size: 0.8rem; font-family: monospace; }
        .timeline-event { margin-top: 0.2rem; }
        .evidence-item {
            padding: 0.6rem;
            background: var(--bg-tertiary);
            border-radius: 4px;
            margin-bottom: 0.5rem;
            font-family: monospace;
            font-size: 0.85rem;
        }
        .footer {
            text-align: center;
            padding: 1.5rem;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AEGIS Incident Response Report</h1>
            <div class="subtitle">Automated Incident Response Execution Summary</div>
            <div class="report-id">{{ report.response_id }}</div>
        </div>

        <div class="section">
            <div class="section-title">Incident Overview</div>
            <div class="section-body">
                <div class="info-grid">
                    <div class="info-item">
                        <label>Playbook</label>
                        <div class="value">{{ report.playbook_name }}</div>
                    </div>
                    <div class="info-item">
                        <label>Alert ID</label>
                        <div class="value" style="font-family:monospace">{{ report.alert_id }}</div>
                    </div>
                    <div class="info-item">
                        <label>Status</label>
                        <div class="value">
                            <span class="status-badge status-{{ report.status }}">{{ report.status | upper }}</span>
                        </div>
                    </div>
                    <div class="info-item">
                        <label>Duration</label>
                        <div class="value">{{ "%.2f" | format(report.duration_seconds) }}s</div>
                    </div>
                    <div class="info-item">
                        <label>Alert Type</label>
                        <div class="value">{{ report.alert.alert_type }}</div>
                    </div>
                    <div class="info-item">
                        <label>Severity</label>
                        <div class="value">{{ report.alert.severity | upper }}</div>
                    </div>
                    <div class="info-item">
                        <label>Source IP</label>
                        <div class="value" style="font-family:monospace">{{ report.alert.source_ip }}</div>
                    </div>
                    <div class="info-item">
                        <label>Destination IP</label>
                        <div class="value" style="font-family:monospace">{{ report.alert.dest_ip }}</div>
                    </div>
                </div>
            </div>
        </div>

        {% if report.escalated %}
        <div class="section" style="border-color: var(--accent-yellow);">
            <div class="section-title" style="color: var(--accent-yellow);">Escalation</div>
            <div class="section-body">
                <p>{{ report.escalation_reason }}</p>
            </div>
        </div>
        {% endif %}

        <div class="section">
            <div class="section-title">Response Steps (NIST 800-61 Mapped)</div>
            <div class="section-body">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Step</th>
                            <th>Action</th>
                            <th>NIST Phase</th>
                            <th>Status</th>
                            <th>Duration</th>
                        </tr>
                    </thead>
                    <tbody>
                    {% for step in report.steps %}
                        <tr>
                            <td>{{ loop.index }}</td>
                            <td>{{ step.step_name }}</td>
                            <td><code>{{ step.action }}</code></td>
                            <td><span class="phase-tag phase-{{ step.nist_phase }}">{{ step.nist_phase }}</span></td>
                            <td><span class="status-badge status-{{ step.status }}">{{ step.status }}</span></td>
                            <td>{{ "%.2f" | format(step.duration_seconds) }}s</td>
                        </tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <div class="section-title">Execution Timeline</div>
            <div class="section-body">
                {% for entry in report.timeline %}
                <div class="timeline-item">
                    <div class="timeline-time">{{ entry.timestamp }}</div>
                    <div class="timeline-event">
                        {{ entry.event }}
                        <span class="phase-tag phase-{{ entry.nist_phase }}">{{ entry.nist_phase }}</span>
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>

        {% if report.evidence %}
        <div class="section">
            <div class="section-title">Evidence Collected ({{ report.evidence | length }} artifacts)</div>
            <div class="section-body">
                {% for item in report.evidence %}
                <div class="evidence-item">
                    <strong>{{ item.get('step', 'Unknown') }}</strong>
                    {% for key, val in item.items() %}
                    {% if key != 'step' %}
                    <br>&nbsp;&nbsp;{{ key }}: {{ val }}
                    {% endif %}
                    {% endfor %}
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        <div class="section">
            <div class="section-title">NIST 800-61 Phase Summary</div>
            <div class="section-body">
                <div class="info-grid">
                    {% for phase, count in report.nist_summary.items() %}
                    <div class="info-item">
                        <label><span class="phase-tag phase-{{ phase }}">{{ phase }}</span></label>
                        <div class="value">{{ count }} step(s)</div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>

        <div class="footer">
            <p>Generated by AEGIS Incident Response Engine</p>
            <p>Report generated at {{ report.generated_at }}</p>
            <p style="margin-top:0.5rem; color: var(--accent-yellow);">
                CONFIDENTIAL - FOR AUTHORIZED PERSONNEL ONLY
            </p>
        </div>
    </div>
</body>
</html>
""")


class IncidentReporter:
    """Generates incident response reports in JSON and HTML formats.

    Reports include the full execution timeline, actions taken,
    evidence collected, and NIST 800-61 phase mapping.

    Attributes:
        output_dir: Directory where reports are written.
    """

    def __init__(self, output_dir: str | Path = "reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        result: ResponseResult,
        alert: Alert,
        format: str = "both",
    ) -> dict[str, Path]:
        """Generate incident response report(s).

        Args:
            result: The playbook execution result.
            alert: The original alert that triggered the response.
            format: Output format - 'json', 'html', or 'both'.

        Returns:
            Dictionary mapping format names to output file paths.
        """
        report_data = self._build_report_data(result, alert)
        outputs: dict[str, Path] = {}

        if format in ("json", "both"):
            outputs["json"] = self._write_json(report_data)

        if format in ("html", "both"):
            outputs["html"] = self._write_html(report_data)

        return outputs

    def _build_report_data(
        self, result: ResponseResult, alert: Alert
    ) -> dict[str, Any]:
        """Build the complete report data structure.

        Args:
            result: The playbook execution result.
            alert: The original alert.

        Returns:
            A dictionary containing all report data.
        """
        # Calculate NIST phase summary
        nist_summary: dict[str, int] = {}
        for step in result.steps_executed:
            phase = step.nist_phase
            nist_summary[phase] = nist_summary.get(phase, 0) + 1

        return {
            "response_id": result.id,
            "playbook_name": result.playbook_name,
            "alert_id": result.alert_id,
            "status": str(result.status),
            "started_at": result.started_at.isoformat() if result.started_at else None,
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
            "duration_seconds": result.duration_seconds,
            "generated_at": datetime.utcnow().isoformat(),
            "alert": alert.to_dict(),
            "steps": [s.to_dict() for s in result.steps_executed],
            "timeline": result.timeline,
            "evidence": result.evidence_collected,
            "escalated": result.escalated,
            "escalation_reason": result.escalation_reason,
            "nist_summary": nist_summary,
            "summary": {
                "total_steps": len(result.steps_executed),
                "successful": result.success_count,
                "failed": result.failure_count,
            },
        }

    def _write_json(self, report_data: dict[str, Any]) -> Path:
        """Write the report as a JSON file.

        Args:
            report_data: The report data dictionary.

        Returns:
            Path to the generated JSON file.
        """
        filename = f"incident_{report_data['response_id']}.json"
        path = self.output_dir / filename

        with open(path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)

        return path

    def _write_html(self, report_data: dict[str, Any]) -> Path:
        """Write the report as an HTML file.

        Args:
            report_data: The report data dictionary.

        Returns:
            Path to the generated HTML file.
        """
        filename = f"incident_{report_data['response_id']}.html"
        path = self.output_dir / filename

        html_content = _HTML_TEMPLATE.render(report=report_data)

        with open(path, "w") as f:
            f.write(html_content)

        return path

    def generate_summary(self, results: list[ResponseResult]) -> dict[str, Any]:
        """Generate a summary report across multiple incident responses.

        Args:
            results: List of playbook execution results.

        Returns:
            A summary dictionary with aggregate statistics.
        """
        total = len(results)
        successful = sum(1 for r in results if str(r.status) == "success")
        failed = sum(1 for r in results if str(r.status) == "failed")
        escalated = sum(1 for r in results if r.escalated)

        all_evidence: list[dict[str, Any]] = []
        for r in results:
            all_evidence.extend(r.evidence_collected)

        return {
            "total_incidents": total,
            "successful_responses": successful,
            "failed_responses": failed,
            "escalated_incidents": escalated,
            "total_evidence_artifacts": len(all_evidence),
            "generated_at": datetime.utcnow().isoformat(),
        }
