"""Tests for the Bayesian attack chain scoring engine."""

import time

import pytest

from correlation.attack_graph import EntityState, TacticObservation
from correlation.scoring import BayesianScorer, ChainScore, ScoringConfig


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_entity(
    entity_id: str = "10.0.1.50",
    tactics: list[tuple[str, int]] | None = None,
    time_span_secs: float = 600.0,
    score_per_tactic: float = 7.0,
    techniques_per_tactic: int = 1,
) -> EntityState:
    """Build an EntityState with the given tactics observed.

    Args:
        tactics: List of (tactic_name, stage_number) tuples.
        time_span_secs: Total time window across all observations.
    """
    state = EntityState(entity_id=entity_id)
    if not tactics:
        return state

    now = time.time()
    interval = time_span_secs / max(len(tactics) - 1, 1)

    for i, (tactic, stage) in enumerate(tactics):
        t = now - time_span_secs + i * interval
        if i == 0:
            state.first_seen = t
        state.last_seen = t

        tech_ids = [f"T{1000 + stage + j}" for j in range(techniques_per_tactic)]
        state.tactics_observed[tactic] = TacticObservation(
            tactic=tactic,
            stage=stage,
            first_seen=t,
            last_seen=t,
            alert_count=1,
            technique_ids=tech_ids,
            max_score=score_per_tactic,
            alert_ids=[f"alert-{entity_id}-{i}"],
        )
        state.alert_ids.append(f"alert-{entity_id}-{i}")

    return state


KILL_CHAIN_3_STAGES = [
    ("discovery", 9),
    ("lateral_movement", 10),
    ("exfiltration", 13),
]

KILL_CHAIN_5_STAGES = [
    ("initial_access", 3),
    ("execution", 4),
    ("persistence", 5),
    ("command_and_control", 12),
    ("exfiltration", 13),
]


# ── Tests ────────────────────────────────────────────────────────────────────

class TestBayesianPosterior:
    """Tests for the Bayesian posterior calculation."""

    def test_empty_entity_returns_zero(self):
        scorer = BayesianScorer()
        state = _make_entity(tactics=[])
        result = scorer.score_entity(state)
        assert result.posterior == 0.0
        assert result.composite == 0.0

    def test_single_tactic_returns_prior(self):
        scorer = BayesianScorer()
        state = _make_entity(tactics=[("discovery", 9)])
        result = scorer.score_entity(state)
        assert result.posterior == pytest.approx(0.01, abs=1e-6)

    def test_more_transitions_increase_posterior(self):
        scorer = BayesianScorer()
        score_3 = scorer.score_entity(_make_entity(tactics=KILL_CHAIN_3_STAGES))
        score_5 = scorer.score_entity(_make_entity(tactics=KILL_CHAIN_5_STAGES))
        assert score_5.posterior > score_3.posterior

    def test_posterior_bounded_0_to_1(self):
        scorer = BayesianScorer()
        # Many stages should approach 1.0 but never exceed it
        many_tactics = [(t, s) for t, s in [
            ("reconnaissance", 1), ("initial_access", 3), ("execution", 4),
            ("persistence", 5), ("privilege_escalation", 6), ("defense_evasion", 7),
            ("credential_access", 8), ("discovery", 9), ("lateral_movement", 10),
            ("command_and_control", 12), ("exfiltration", 13),
        ]]
        result = scorer.score_entity(_make_entity(tactics=many_tactics))
        assert 0.0 <= result.posterior <= 1.0
        assert result.posterior > 0.99  # Should be very high

    def test_high_noise_prior_reduces_posterior(self):
        config = ScoringConfig(p_transition_given_noise=0.60)
        scorer = BayesianScorer(config)
        result = scorer.score_entity(_make_entity(tactics=KILL_CHAIN_3_STAGES))
        # High noise probability should reduce confidence
        default_scorer = BayesianScorer()
        default_result = default_scorer.score_entity(_make_entity(tactics=KILL_CHAIN_3_STAGES))
        assert result.posterior < default_result.posterior


class TestCompleteness:
    """Tests for kill chain completeness scoring."""

    def test_empty_is_zero(self):
        scorer = BayesianScorer()
        state = _make_entity(tactics=[])
        result = scorer.score_entity(state)
        assert result.completeness == 0.0

    def test_partial_coverage(self):
        scorer = BayesianScorer()
        result = scorer.score_entity(_make_entity(tactics=KILL_CHAIN_3_STAGES))
        assert result.completeness == pytest.approx(3 / 14, abs=1e-6)

    def test_capped_at_one(self):
        scorer = BayesianScorer(ScoringConfig(max_chain_stages=3))
        result = scorer.score_entity(_make_entity(tactics=KILL_CHAIN_5_STAGES))
        assert result.completeness == 1.0


class TestVelocity:
    """Tests for temporal velocity scoring."""

    def test_single_tactic_neutral(self):
        scorer = BayesianScorer()
        result = scorer.score_entity(_make_entity(tactics=[("discovery", 9)]))
        assert result.velocity == 0.5

    def test_fast_chain_scores_high(self):
        scorer = BayesianScorer()
        # 60 second chain — well under 30-minute fast_attack_window
        result = scorer.score_entity(
            _make_entity(tactics=KILL_CHAIN_3_STAGES, time_span_secs=60.0)
        )
        assert result.velocity == 1.0

    def test_slow_chain_scores_lower(self):
        scorer = BayesianScorer()
        fast = scorer.score_entity(
            _make_entity(tactics=KILL_CHAIN_3_STAGES, time_span_secs=60.0)
        )
        slow = scorer.score_entity(
            _make_entity(tactics=KILL_CHAIN_3_STAGES, time_span_secs=36000.0)
        )
        assert fast.velocity > slow.velocity


class TestOrderScore:
    """Tests for kill chain ordering correctness."""

    def test_single_tactic_neutral(self):
        scorer = BayesianScorer()
        result = scorer.score_entity(_make_entity(tactics=[("discovery", 9)]))
        assert result.order_score == 0.5

    def test_correctly_ordered_chain(self):
        scorer = BayesianScorer()
        # Tactics created in kill-chain order with ascending timestamps
        result = scorer.score_entity(_make_entity(tactics=KILL_CHAIN_5_STAGES))
        assert result.order_score == 1.0

    def test_reversed_chain_scores_zero(self):
        scorer = BayesianScorer()
        reversed_tactics = list(reversed(KILL_CHAIN_5_STAGES))
        result = scorer.score_entity(_make_entity(tactics=reversed_tactics))
        assert result.order_score == 0.0


class TestQuality:
    """Tests for alert quality scoring."""

    def test_high_score_alerts(self):
        scorer = BayesianScorer()
        result = scorer.score_entity(
            _make_entity(tactics=KILL_CHAIN_3_STAGES, score_per_tactic=10.0)
        )
        assert result.quality == 1.0

    def test_low_score_alerts(self):
        scorer = BayesianScorer()
        result = scorer.score_entity(
            _make_entity(tactics=KILL_CHAIN_3_STAGES, score_per_tactic=2.0)
        )
        assert result.quality == pytest.approx(0.2, abs=1e-6)


class TestDiversity:
    """Tests for source diversity scoring."""

    def test_single_technique_low_diversity(self):
        scorer = BayesianScorer()
        result = scorer.score_entity(
            _make_entity(tactics=KILL_CHAIN_3_STAGES, techniques_per_tactic=1)
        )
        # 3 techniques (one per tactic) → 3/5 = 0.6
        assert result.diversity == pytest.approx(0.6, abs=1e-6)

    def test_many_techniques_capped(self):
        scorer = BayesianScorer()
        result = scorer.score_entity(
            _make_entity(tactics=KILL_CHAIN_5_STAGES, techniques_per_tactic=3)
        )
        # 15 techniques → capped at 1.0
        assert result.diversity == 1.0


class TestEscalationLevel:
    """Tests for escalation level thresholds."""

    def test_low_composite_is_none_or_watch(self):
        scorer = BayesianScorer()
        state = _make_entity(tactics=[("discovery", 9)], score_per_tactic=1.0)
        result = scorer.score_entity(state)
        # Single tactic with low score — should not be alert or critical
        assert result.escalation_level in ("none", "watch")
        assert result.composite < 4.5

    def test_critical_threshold(self):
        scorer = BayesianScorer()
        many_tactics = [
            ("initial_access", 3), ("execution", 4), ("persistence", 5),
            ("privilege_escalation", 6), ("defense_evasion", 7),
            ("credential_access", 8), ("discovery", 9), ("lateral_movement", 10),
            ("command_and_control", 12), ("exfiltration", 13),
        ]
        result = scorer.score_entity(
            _make_entity(tactics=many_tactics, time_span_secs=120.0, score_per_tactic=9.0)
        )
        assert result.escalation_level == "critical"
        assert result.composite >= 7.0

    def test_escalation_levels_ordered(self):
        # Verify the thresholds: none < 2.5, watch < 4.5, alert < 7.0, critical
        score = ChainScore(entity_id="test")

        score.composite = 1.0
        assert BayesianScorer._escalation_level(score) == "none"

        score.composite = 3.0
        assert BayesianScorer._escalation_level(score) == "watch"

        score.composite = 5.0
        assert BayesianScorer._escalation_level(score) == "alert"

        score.composite = 8.0
        assert BayesianScorer._escalation_level(score) == "critical"


class TestCompositeScore:
    """Tests for the weighted composite score."""

    def test_composite_range_0_to_10(self):
        scorer = BayesianScorer()
        result = scorer.score_entity(_make_entity(tactics=KILL_CHAIN_5_STAGES))
        assert 0.0 <= result.composite <= 10.0

    def test_weights_sum_to_one(self):
        cfg = ScoringConfig()
        total = (
            cfg.w_completeness + cfg.w_velocity + cfg.w_order
            + cfg.w_quality + cfg.w_diversity
        )
        assert total == pytest.approx(1.0, abs=1e-6)

    def test_entity_score_updated(self):
        scorer = BayesianScorer()
        state = _make_entity(tactics=KILL_CHAIN_3_STAGES)
        result = scorer.score_entity(state)
        assert state.chain_score == result.composite
