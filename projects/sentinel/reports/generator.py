"""
Report generator — writes HTML (Jinja2) and/or JSON output.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models import NormalizedFinding, Campaign, AttackPath
from core.constants import PHASE_ORDER

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    _JINJA2 = True
except ImportError:
    _JINJA2 = False

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_TEMPLATE_NAME = "sentinel_report.j2"


def _phase_counts(campaigns: list[Campaign]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for c in campaigns:
        counts[c.kill_chain_phase] = counts.get(c.kill_chain_phase, 0) + 1
    return counts


def generate_reports(
    findings: list[NormalizedFinding],
    campaigns: list[Campaign],
    attack_paths: list[AttackPath],
    finding_phases: dict[str, tuple[str, float]],
    finding_scores: dict[str, float],
    coverage: list[dict],          # [{"tool": str, "count": int, "warnings": list[str]}]
    output_dir: str,
    fmt: str = "both",             # "html" | "json" | "both"
) -> list[str]:
    """
    Write reports to *output_dir*.  Returns list of written file paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    written: list[str] = []
    now = datetime.now(timezone.utc).isoformat()

    if fmt in ("html", "both"):
        html_path = _write_html(findings, campaigns, attack_paths, finding_phases,
                                finding_scores, coverage, output_dir, now)
        if html_path:
            written.append(html_path)

    if fmt in ("json", "both"):
        json_path = _write_json(findings, campaigns, attack_paths, finding_phases,
                                finding_scores, coverage, output_dir, now)
        written.append(json_path)

    return written


def _write_html(
    findings, campaigns, attack_paths, finding_phases, finding_scores, coverage,
    output_dir, generated_at
) -> str | None:
    if not _JINJA2:
        return None

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    # Make dict.get available in templates
    env.globals["dict"] = dict

    template = env.get_template(_TEMPLATE_NAME)

    findings_detail = []
    for f in sorted(findings, key=lambda x: finding_scores.get(x.finding_id, 0), reverse=True):
        phase, _ = finding_phases.get(f.finding_id, ("Unknown", 0.0))
        findings_detail.append({
            "source_tool": f.source_tool,
            "severity": f.severity,
            "title": f.title,
            "phase": phase,
            "risk_score": finding_scores.get(f.finding_id, 0.0),
            "entities": f.entities,
        })

    max_risk = max((c.risk_score for c in campaigns), default=0.0)

    html = template.render(
        generated_at=generated_at,
        total_findings=len(findings),
        campaigns=[_campaign_to_tmpl(c) for c in campaigns],
        attack_paths=[p.to_dict() for p in attack_paths],
        findings_detail=findings_detail,
        coverage=coverage,
        phase_order=PHASE_ORDER,
        phase_counts=_phase_counts(campaigns),
        max_risk=max_risk,
    )

    out_path = os.path.join(output_dir, "sentinel_report.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return out_path


def _campaign_to_tmpl(c: Campaign) -> dict:
    d = c.to_dict()
    return d


def _write_json(
    findings, campaigns, attack_paths, finding_phases, finding_scores, coverage,
    output_dir, generated_at
) -> str:
    data = {
        "generated_at": generated_at,
        "summary": {
            "total_findings": len(findings),
            "total_campaigns": len(campaigns),
            "total_attack_paths": len(attack_paths),
            "max_risk_score": max((c.risk_score for c in campaigns), default=0.0),
        },
        "coverage": coverage,
        "campaigns": [c.to_dict() for c in campaigns],
        "attack_paths": [p.to_dict() for p in attack_paths],
        "findings": [_finding_to_json(f, finding_phases, finding_scores) for f in findings],
    }

    out_path = os.path.join(output_dir, "sentinel_report.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    return out_path


def _finding_to_json(
    f: NormalizedFinding,
    finding_phases: dict[str, tuple[str, float]],
    finding_scores: dict[str, float],
) -> dict:
    d = f.to_dict()
    phase, conf = finding_phases.get(f.finding_id, ("Unknown", 0.0))
    d["kill_chain_phase"] = phase
    d["kill_chain_confidence"] = conf
    d["risk_score"] = finding_scores.get(f.finding_id, 0.0)
    return d
