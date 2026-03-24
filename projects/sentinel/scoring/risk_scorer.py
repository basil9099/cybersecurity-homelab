"""
Composite risk scoring for findings and campaigns.
Follows the _METRIC_WEIGHTS pattern from network-baseline-monitor.

Optional IsolationForest re-ranking when n_findings >= 10.
"""

from __future__ import annotations

import math
from typing import Any

from core.models import NormalizedFinding, Campaign
from core.constants import SEVERITY_BASE, TOOL_WEIGHTS, PHASE_MULTIPLIERS

try:
    import numpy as np
    _NUMPY = True
except ImportError:
    _NUMPY = False


def score_finding(finding: NormalizedFinding, kill_chain_phase: str) -> float:
    """
    Composite score = severity_base × tool_weight × phase_multiplier.
    Normalised to [0, 10].
    """
    sev_base = SEVERITY_BASE.get(finding.severity, 2.0)
    tool_w = TOOL_WEIGHTS.get(finding.source_tool, 0.7)
    phase_mult = PHASE_MULTIPLIERS.get(kill_chain_phase, 0.5)
    raw = sev_base * tool_w * phase_mult
    # Normalise: max possible = 10 × 1.0 × 1.0 = 10
    return min(10.0, raw)


def score_campaign(campaign: Campaign, findings_by_id: dict[str, NormalizedFinding]) -> float:
    """
    Aggregate score:
      base = mean(finding_scores)
      breadth_bonus = 0.5 per additional tool beyond the first (max +2)
      volume_factor = log(1 + n_findings)
    Normalised to [0, 10].
    """
    member_findings = [findings_by_id[fid] for fid in campaign.finding_ids if fid in findings_by_id]
    if not member_findings:
        return 0.0

    phase_mult = PHASE_MULTIPLIERS.get(campaign.kill_chain_phase, 0.5)
    finding_scores = [score_finding(f, campaign.kill_chain_phase) for f in member_findings]
    mean_score = sum(finding_scores) / len(finding_scores)

    n_tools = len(set(f.source_tool for f in member_findings))
    breadth_bonus = min(2.0, (n_tools - 1) * 0.5)

    volume_factor = math.log1p(len(member_findings))

    raw = (mean_score + breadth_bonus) * phase_mult * volume_factor
    return min(10.0, raw)


class RiskScorer:
    """
    Orchestrates finding + campaign scoring and optional IsolationForest re-ranking.
    """

    def __init__(self, use_isolation_forest: bool = True) -> None:
        self.use_isolation_forest = use_isolation_forest and _NUMPY
        self._iforest = None

    def score_all(
        self,
        findings: list[NormalizedFinding],
        finding_phases: dict[str, tuple[str, float]],  # finding_id → (phase, confidence)
        campaigns: list[Campaign],
    ) -> tuple[dict[str, float], list[Campaign]]:
        """
        Score all findings, optionally apply IsolationForest re-ranking,
        then score campaigns.

        Returns
        -------
        finding_scores : dict[finding_id → score]
        campaigns : list[Campaign] with risk_score filled in, sorted desc
        """
        # ------------------------------------------------------------------
        # 1. Score individual findings
        # ------------------------------------------------------------------
        finding_scores: dict[str, float] = {}
        for f in findings:
            phase, _ = finding_phases.get(f.finding_id, ("Reconnaissance", 0.0))
            finding_scores[f.finding_id] = score_finding(f, phase)

        # ------------------------------------------------------------------
        # 2. IsolationForest re-ranking (optional, requires n >= 10)
        # ------------------------------------------------------------------
        if self.use_isolation_forest and len(findings) >= 10:
            finding_scores = self._isolation_forest_rerank(findings, finding_phases, finding_scores)

        # ------------------------------------------------------------------
        # 3. Build finding_id → NormalizedFinding lookup
        # ------------------------------------------------------------------
        findings_by_id = {f.finding_id: f for f in findings}

        # ------------------------------------------------------------------
        # 4. Score campaigns
        # ------------------------------------------------------------------
        for campaign in campaigns:
            campaign.risk_score = score_campaign(campaign, findings_by_id)

        campaigns.sort(key=lambda c: c.risk_score, reverse=True)
        return finding_scores, campaigns

    def _isolation_forest_rerank(
        self,
        findings: list[NormalizedFinding],
        finding_phases: dict[str, tuple[str, float]],
        base_scores: dict[str, float],
    ) -> dict[str, float]:
        """Adjust base scores using IsolationForest outlier scores."""
        try:
            from sklearn.ensemble import IsolationForest
            import numpy as np
        except ImportError:
            return base_scores

        try:
            rows = []
            for f in findings:
                phase, conf = finding_phases.get(f.finding_id, ("Reconnaissance", 0.0))
                phase_mult = PHASE_MULTIPLIERS.get(phase, 0.5)
                tool_w = TOOL_WEIGHTS.get(f.source_tool, 0.7)
                n_entities = sum(len(v) for v in f.entities.values())
                rows.append([
                    f.raw_severity_score,
                    tool_w,
                    phase_mult,
                    float(conf),
                    float(n_entities),
                ])

            X = np.array(rows, dtype=float)
            iforest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
            iforest.fit(X)
            # decision_function returns scores in [-1, 0]; higher = more normal
            raw_scores = iforest.decision_function(X)  # shape (n,)
            # Normalise to [0, 1] where 1 = most anomalous (highest priority)
            min_s, max_s = raw_scores.min(), raw_scores.max()
            if max_s > min_s:
                outlier_boost = 1.0 - (raw_scores - min_s) / (max_s - min_s)
            else:
                outlier_boost = np.zeros(len(findings))

            adjusted = {}
            for i, f in enumerate(findings):
                base = base_scores[f.finding_id]
                # Boost by up to 20% based on outlier rank
                adjusted[f.finding_id] = min(10.0, base * (1.0 + 0.2 * float(outlier_boost[i])))
            return adjusted
        except Exception:
            return base_scores
