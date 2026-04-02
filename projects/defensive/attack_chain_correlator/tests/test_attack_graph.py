"""Tests for the ATT&CK kill chain state machine."""

import time

import pytest

from correlation.attack_graph import AttackGraph, EntityState, TacticObservation
from ingestion.schema import NormalizedAlert, AlertSource, Severity


# ── Helpers ──────────────────────────────────────────────────────────────────

def _alert(
    src_entity: str = "10.0.1.50",
    tactic: str = "discovery",
    anomaly_type: str = "port_scan",
    score: float = 6.0,
    technique_ids: list[str] | None = None,
    timestamp: float | None = None,
    alert_id: str | None = None,
) -> NormalizedAlert:
    return NormalizedAlert(
        alert_id=alert_id or f"a-{src_entity}-{tactic}-{time.time()}",
        timestamp=timestamp or time.time(),
        source=AlertSource.NETWORK_BASELINE,
        anomaly_type=anomaly_type,
        severity=Severity.HIGH,
        score=score,
        src_entity=src_entity,
        dst_entity="10.0.1.1",
        technique_ids=technique_ids or ["T1046"],
        tactic=tactic,
    )


# ── EntityState Tests ────────────────────────────────────────────────────────

class TestEntityState:
    def test_chain_length(self):
        state = EntityState(entity_id="host-1")
        assert state.chain_length == 0

        state.tactics_observed["discovery"] = TacticObservation(
            tactic="discovery", stage=9, first_seen=1.0, last_seen=1.0,
        )
        assert state.chain_length == 1

    def test_tactics_in_order(self):
        state = EntityState(entity_id="host-1")
        state.tactics_observed["exfiltration"] = TacticObservation(
            tactic="exfiltration", stage=13, first_seen=3.0, last_seen=3.0,
        )
        state.tactics_observed["discovery"] = TacticObservation(
            tactic="discovery", stage=9, first_seen=1.0, last_seen=1.0,
        )
        ordered = state.tactics_in_order
        assert ordered[0].tactic == "discovery"
        assert ordered[1].tactic == "exfiltration"

    def test_chain_span(self):
        state = EntityState(entity_id="host-1")
        state.tactics_observed["discovery"] = TacticObservation(
            tactic="discovery", stage=9, first_seen=1.0, last_seen=1.0,
        )
        state.tactics_observed["exfiltration"] = TacticObservation(
            tactic="exfiltration", stage=13, first_seen=2.0, last_seen=2.0,
        )
        assert state.chain_span == 4

    def test_time_span(self):
        state = EntityState(entity_id="host-1", first_seen=100.0, last_seen=200.0)
        assert state.time_span == 100.0

    def test_time_span_zero_when_same(self):
        state = EntityState(entity_id="host-1", first_seen=100.0, last_seen=100.0)
        assert state.time_span == 0.0

    def test_has_progression_requires_two_tactics(self):
        state = EntityState(entity_id="host-1")
        state.tactics_observed["discovery"] = TacticObservation(
            tactic="discovery", stage=9, first_seen=1.0, last_seen=1.0,
        )
        assert state.has_progression() is False

    def test_has_progression_true_with_ordered_timestamps(self):
        state = EntityState(entity_id="host-1")
        state.tactics_observed["discovery"] = TacticObservation(
            tactic="discovery", stage=9, first_seen=1.0, last_seen=1.0,
        )
        state.tactics_observed["exfiltration"] = TacticObservation(
            tactic="exfiltration", stage=13, first_seen=2.0, last_seen=2.0,
        )
        assert state.has_progression() is True


# ── AttackGraph Tests ────────────────────────────────────────────────────────

class TestAttackGraphProcessing:
    def test_process_alert_creates_entity(self):
        graph = AttackGraph()
        alert = _alert(src_entity="10.0.1.50", tactic="discovery")
        state = graph.process_alert(alert)
        assert state is not None
        assert state.entity_id == "10.0.1.50"
        assert "discovery" in state.tactics_observed

    def test_process_alert_ignores_unknown_entity(self):
        graph = AttackGraph()
        alert = _alert(src_entity="unknown", tactic="discovery")
        assert graph.process_alert(alert) is None

    def test_process_alert_ignores_empty_entity(self):
        graph = AttackGraph()
        alert = _alert(src_entity="", tactic="discovery")
        assert graph.process_alert(alert) is None

    def test_multiple_alerts_same_tactic_increment_count(self):
        graph = AttackGraph()
        now = time.time()
        graph.process_alert(_alert(
            src_entity="host-1", tactic="discovery", alert_id="a1", timestamp=now,
        ))
        graph.process_alert(_alert(
            src_entity="host-1", tactic="discovery", alert_id="a2", timestamp=now + 1,
        ))
        state = graph.entities["host-1"]
        assert state.tactics_observed["discovery"].alert_count == 2
        assert len(state.tactics_observed["discovery"].alert_ids) == 2

    def test_multiple_tactics_build_chain(self):
        graph = AttackGraph()
        now = time.time()
        tactics = ["discovery", "lateral_movement", "exfiltration"]
        for i, tactic in enumerate(tactics):
            graph.process_alert(_alert(
                src_entity="host-1", tactic=tactic,
                alert_id=f"a-{i}", timestamp=now + i * 60,
            ))
        state = graph.entities["host-1"]
        assert state.chain_length == 3

    def test_invalid_tactic_ignored(self):
        graph = AttackGraph()
        alert = _alert(src_entity="host-1", tactic="not_a_real_tactic")
        state = graph.process_alert(alert)
        assert state.chain_length == 0

    def test_max_score_updated(self):
        graph = AttackGraph()
        now = time.time()
        graph.process_alert(_alert(
            src_entity="host-1", tactic="discovery", score=3.0,
            alert_id="a1", timestamp=now,
        ))
        graph.process_alert(_alert(
            src_entity="host-1", tactic="discovery", score=8.0,
            alert_id="a2", timestamp=now + 1,
        ))
        assert graph.entities["host-1"].tactics_observed["discovery"].max_score == 8.0


class TestAttackGraphProgressions:
    def test_new_progression_detected(self):
        graph = AttackGraph(min_chain_stages=3)
        now = time.time()
        tactics = ["discovery", "lateral_movement", "exfiltration"]
        for i, tactic in enumerate(tactics):
            graph.process_alert(_alert(
                src_entity="host-1", tactic=tactic,
                alert_id=f"a-{i}", timestamp=now + i * 60,
            ))
        progressions = graph.get_new_progressions()
        assert "host-1" in progressions

    def test_progression_cleared_after_get(self):
        graph = AttackGraph(min_chain_stages=2)
        now = time.time()
        graph.process_alert(_alert(
            src_entity="host-1", tactic="discovery", alert_id="a1", timestamp=now,
        ))
        graph.process_alert(_alert(
            src_entity="host-1", tactic="exfiltration", alert_id="a2", timestamp=now + 60,
        ))
        assert len(graph.get_new_progressions()) == 1
        assert len(graph.get_new_progressions()) == 0

    def test_below_threshold_no_progression(self):
        graph = AttackGraph(min_chain_stages=5)
        now = time.time()
        for i, tactic in enumerate(["discovery", "lateral_movement"]):
            graph.process_alert(_alert(
                src_entity="host-1", tactic=tactic,
                alert_id=f"a-{i}", timestamp=now + i * 60,
            ))
        assert len(graph.get_new_progressions()) == 0


class TestAttackGraphActiveChains:
    def test_get_active_chains(self):
        graph = AttackGraph(min_chain_stages=2)
        now = time.time()
        graph.process_alert(_alert(
            src_entity="host-1", tactic="discovery", alert_id="a1", timestamp=now,
        ))
        graph.process_alert(_alert(
            src_entity="host-1", tactic="exfiltration", alert_id="a2", timestamp=now + 60,
        ))
        chains = graph.get_active_chains()
        assert len(chains) == 1
        assert chains[0].entity_id == "host-1"

    def test_sorted_by_chain_score(self):
        graph = AttackGraph(min_chain_stages=2)
        now = time.time()
        # Entity A: score 5.0
        for i, tactic in enumerate(["discovery", "exfiltration"]):
            graph.process_alert(_alert(
                src_entity="host-a", tactic=tactic,
                alert_id=f"aa-{i}", timestamp=now + i * 60,
            ))
        graph.entities["host-a"].chain_score = 5.0
        # Entity B: score 9.0
        for i, tactic in enumerate(["discovery", "exfiltration"]):
            graph.process_alert(_alert(
                src_entity="host-b", tactic=tactic,
                alert_id=f"bb-{i}", timestamp=now + i * 60,
            ))
        graph.entities["host-b"].chain_score = 9.0

        chains = graph.get_active_chains()
        assert chains[0].entity_id == "host-b"

    def test_expire_stale_removes_old(self):
        graph = AttackGraph(chain_window_seconds=60)
        old_time = time.time() - 120
        graph.process_alert(_alert(
            src_entity="host-old", tactic="discovery",
            alert_id="old-1", timestamp=old_time,
        ))
        removed = graph.expire_stale()
        assert removed == 1
        assert "host-old" not in graph.entities
