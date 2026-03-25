#!/usr/bin/env python3
"""
correlation/scoring.py
======================
Bayesian attack chain scoring engine.

Calculates the posterior probability that a sequence of alerts for an entity
represents a real attack chain versus coincidental noise. Uses configurable
prior probabilities for kill chain stage transitions.

The score combines:
  1. Chain completeness — more kill chain stages → higher score
  2. Temporal velocity — faster progression → higher score (attacks compress time)
  3. Progression order — correct kill chain order → higher score
  4. Alert quality — higher severity/confidence alerts → higher score
  5. Source diversity — alerts from multiple tools → higher score
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from correlation.attack_graph import EntityState
from mappings.mitre_attack import TACTIC_ORDER


@dataclass
class ScoringConfig:
    """Tunable weights and priors for Bayesian scoring."""

    # Prior probability that any entity is under active attack
    prior_attack: float = 0.01

    # Probability of observing tactic N+1 given attack is real
    p_transition_given_attack: float = 0.70

    # Probability of observing tactic N+1 given NOT an attack (noise)
    p_transition_given_noise: float = 0.05

    # Weight factors for composite score (must sum to 1.0)
    w_completeness: float = 0.30
    w_velocity: float = 0.20
    w_order: float = 0.20
    w_quality: float = 0.15
    w_diversity: float = 0.15

    # Time window for "fast" attacks (seconds) — faster than this gets max velocity score
    fast_attack_window: float = 1800.0  # 30 minutes

    # Maximum chain stages possible in the model
    max_chain_stages: int = 14


@dataclass
class ChainScore:
    """Detailed scoring breakdown for an entity's attack chain."""
    entity_id: str
    posterior: float = 0.0          # Bayesian posterior P(attack | evidence)
    composite: float = 0.0         # Weighted composite score (0–10)
    completeness: float = 0.0      # Kill chain coverage (0–1)
    velocity: float = 0.0          # Temporal compression (0–1)
    order_score: float = 0.0       # Kill chain ordering correctness (0–1)
    quality: float = 0.0           # Average alert quality (0–1)
    diversity: float = 0.0         # Source diversity (0–1)
    stages_observed: int = 0
    escalation_level: str = "none"  # none | watch | alert | critical


class BayesianScorer:
    """
    Scores entity states using Bayesian probability and weighted composites.

    Usage:
        scorer = BayesianScorer()
        score = scorer.score_entity(entity_state)
        if score.escalation_level == "critical":
            # Sound the alarm
    """

    def __init__(self, config: ScoringConfig | None = None):
        self.cfg = config or ScoringConfig()

    def score_entity(self, state: EntityState) -> ChainScore:
        """
        Compute full scoring breakdown for an entity.

        Args:
            state: EntityState from the attack graph.

        Returns:
            ChainScore with all sub-scores and escalation level.
        """
        result = ChainScore(entity_id=state.entity_id)
        result.stages_observed = state.chain_length

        if state.chain_length == 0:
            return result

        # 1. Bayesian posterior
        result.posterior = self._bayesian_posterior(state)

        # 2. Component scores
        result.completeness = self._completeness(state)
        result.velocity = self._velocity(state)
        result.order_score = self._order_score(state)
        result.quality = self._quality(state)
        result.diversity = self._diversity(state)

        # 3. Weighted composite (0–10 scale)
        raw = (
            self.cfg.w_completeness * result.completeness
            + self.cfg.w_velocity * result.velocity
            + self.cfg.w_order * result.order_score
            + self.cfg.w_quality * result.quality
            + self.cfg.w_diversity * result.diversity
        )
        result.composite = round(raw * 10.0, 2)

        # 4. Assign escalation level
        state.chain_score = result.composite
        result.escalation_level = self._escalation_level(result)

        return result

    def _bayesian_posterior(self, state: EntityState) -> float:
        """
        Calculate P(attack | observed_transitions) using Bayes' theorem.

        Each additional kill chain stage is treated as independent evidence.
        """
        n_transitions = max(state.chain_length - 1, 0)
        if n_transitions == 0:
            return self.cfg.prior_attack

        # Likelihood of evidence given attack
        p_evidence_attack = self.cfg.p_transition_given_attack ** n_transitions
        # Likelihood of evidence given noise
        p_evidence_noise = self.cfg.p_transition_given_noise ** n_transitions

        # Bayes' theorem
        numerator = p_evidence_attack * self.cfg.prior_attack
        denominator = (
            numerator
            + p_evidence_noise * (1 - self.cfg.prior_attack)
        )

        if denominator < 1e-15:
            return 0.0
        return numerator / denominator

    def _completeness(self, state: EntityState) -> float:
        """Fraction of kill chain stages observed."""
        return min(state.chain_length / self.cfg.max_chain_stages, 1.0)

    def _velocity(self, state: EntityState) -> float:
        """
        Score based on temporal compression.

        Real attacks tend to move through stages faster than random noise
        would. Score is higher when the chain progresses quickly.
        """
        if state.time_span <= 0 or state.chain_length < 2:
            return 0.5  # No temporal signal — neutral

        # Seconds per stage
        secs_per_stage = state.time_span / max(state.chain_length - 1, 1)

        # Normalize: faster than fast_attack_window → 1.0, much slower → 0.0
        if secs_per_stage <= self.cfg.fast_attack_window:
            return 1.0
        # Exponential decay for slower chains
        decay = math.exp(-(secs_per_stage - self.cfg.fast_attack_window) / self.cfg.fast_attack_window)
        return max(decay, 0.0)

    def _order_score(self, state: EntityState) -> float:
        """
        Score based on kill chain ordering correctness.

        Measures how well the temporal order of observations matches the
        expected ATT&CK tactic sequence.
        """
        ordered = state.tactics_in_order
        if len(ordered) < 2:
            return 0.5  # Neutral

        # Count correctly ordered pairs (by first_seen time)
        correct = 0
        total = 0
        for i in range(len(ordered) - 1):
            for j in range(i + 1, len(ordered)):
                total += 1
                if ordered[i].first_seen <= ordered[j].first_seen:
                    correct += 1

        return correct / total if total > 0 else 0.5

    def _quality(self, state: EntityState) -> float:
        """Average max alert score across all observed tactics, normalized to 0–1."""
        if not state.tactics_observed:
            return 0.0
        total = sum(obs.max_score for obs in state.tactics_observed.values())
        avg = total / len(state.tactics_observed)
        return min(avg / 10.0, 1.0)

    def _diversity(self, state: EntityState) -> float:
        """
        Score based on how many distinct alert sources contributed.

        Multi-source correlation is much harder to fake — if network, SIEM,
        and cloud all flag the same entity, confidence should be high.
        """
        # Count unique sources from alert IDs in observations
        # Since we don't store source per alert_id here, we use technique
        # diversity as a proxy — different techniques imply different detections
        all_techniques = set()
        for obs in state.tactics_observed.values():
            all_techniques.update(obs.technique_ids)

        # Normalize: 1 technique → 0.2, 5+ → 1.0
        return min(len(all_techniques) / 5.0, 1.0)

    @staticmethod
    def _escalation_level(score: ChainScore) -> str:
        """Map composite score to escalation level."""
        if score.composite >= 7.0:
            return "critical"
        if score.composite >= 4.5:
            return "alert"
        if score.composite >= 2.5:
            return "watch"
        return "none"
