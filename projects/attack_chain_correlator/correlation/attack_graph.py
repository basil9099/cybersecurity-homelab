#!/usr/bin/env python3
"""
correlation/attack_graph.py
===========================
ATT&CK kill chain state machine that tracks per-entity progression through
attack stages.

Each entity (IP, hostname, user) gets an EntityState that records which
ATT&CK tactics have been observed, when, and with what confidence. The
state machine detects when an entity progresses through sequential kill
chain stages — the hallmark of an active attack chain.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from ingestion.schema import NormalizedAlert
from mappings.mitre_attack import TACTIC_ORDER, is_progression, tactic_stage


@dataclass
class TacticObservation:
    """A single observation of a tactic for an entity."""
    tactic: str
    stage: int
    first_seen: float
    last_seen: float
    alert_count: int = 1
    technique_ids: list[str] = field(default_factory=list)
    max_score: float = 0.0
    alert_ids: list[str] = field(default_factory=list)


@dataclass
class EntityState:
    """
    Tracks the kill chain state for a single entity.

    An entity is identified by its primary identifier (IP, hostname, etc.).
    The state records all observed ATT&CK tactics and the alerts that
    contributed to each observation.
    """
    entity_id: str
    first_seen: float = 0.0
    last_seen: float = 0.0
    tactics_observed: dict[str, TacticObservation] = field(default_factory=dict)
    alert_ids: list[str] = field(default_factory=list)
    chain_score: float = 0.0

    @property
    def tactics_in_order(self) -> list[TacticObservation]:
        """Return observed tactics sorted by kill chain stage."""
        return sorted(
            self.tactics_observed.values(),
            key=lambda t: t.stage,
        )

    @property
    def chain_length(self) -> int:
        """Number of distinct kill chain stages observed."""
        return len(self.tactics_observed)

    @property
    def chain_span(self) -> int:
        """Kill chain stages between earliest and latest tactic."""
        if not self.tactics_observed:
            return 0
        stages = [t.stage for t in self.tactics_observed.values()]
        return max(stages) - min(stages)

    @property
    def time_span(self) -> float:
        """Seconds between first and last alert."""
        if self.last_seen <= self.first_seen:
            return 0.0
        return self.last_seen - self.first_seen

    def has_progression(self) -> bool:
        """True if entity shows sequential kill chain progression."""
        ordered = self.tactics_in_order
        if len(ordered) < 2:
            return False
        # Check if observations arrived in roughly kill-chain order
        for i in range(len(ordered) - 1):
            if ordered[i].first_seen <= ordered[i + 1].first_seen:
                return True
        return False


class AttackGraph:
    """
    Maintains entity states and detects attack chain progressions.

    The graph processes incoming NormalizedAlerts and updates entity states.
    When an entity accumulates observations across multiple kill chain stages,
    the graph flags it as a potential attack chain.
    """

    def __init__(
        self,
        chain_window_seconds: int = 3600,
        min_chain_stages: int = 3,
    ):
        self.chain_window = chain_window_seconds
        self.min_chain_stages = min_chain_stages
        self.entities: dict[str, EntityState] = {}
        self._new_progressions: list[str] = []

    def process_alert(self, alert: NormalizedAlert) -> EntityState | None:
        """
        Process an alert and update the entity's kill chain state.

        Returns:
            The updated EntityState, or None if alert had no entity.
        """
        entity_id = alert.src_entity
        if not entity_id or entity_id in ("unknown", "multiple", "statistical"):
            return None

        state = self._get_or_create(entity_id, alert.timestamp)
        prev_chain_length = state.chain_length

        # Update tactic observation
        tactic = alert.tactic
        if tactic and tactic in TACTIC_ORDER:
            if tactic in state.tactics_observed:
                obs = state.tactics_observed[tactic]
                obs.last_seen = alert.timestamp
                obs.alert_count += 1
                obs.max_score = max(obs.max_score, alert.score)
                if alert.alert_id not in obs.alert_ids:
                    obs.alert_ids.append(alert.alert_id)
                for tid in alert.technique_ids:
                    if tid not in obs.technique_ids:
                        obs.technique_ids.append(tid)
            else:
                state.tactics_observed[tactic] = TacticObservation(
                    tactic=tactic,
                    stage=tactic_stage(tactic),
                    first_seen=alert.timestamp,
                    last_seen=alert.timestamp,
                    alert_count=1,
                    technique_ids=list(alert.technique_ids),
                    max_score=alert.score,
                    alert_ids=[alert.alert_id],
                )

        state.last_seen = max(state.last_seen, alert.timestamp)
        if alert.alert_id not in state.alert_ids:
            state.alert_ids.append(alert.alert_id)

        # Detect new chain progression
        if state.chain_length > prev_chain_length and state.chain_length >= self.min_chain_stages:
            if entity_id not in self._new_progressions:
                self._new_progressions.append(entity_id)

        return state

    def get_active_chains(self, min_stages: int | None = None) -> list[EntityState]:
        """
        Return entities with active attack chain progressions.

        Args:
            min_stages: Minimum number of kill chain stages (default: self.min_chain_stages).

        Returns:
            List of EntityState objects meeting the threshold, sorted by chain_score desc.
        """
        threshold = min_stages or self.min_chain_stages
        now = time.time()

        chains = []
        for state in self.entities.values():
            if state.chain_length >= threshold:
                # Only include chains within the time window
                if now - state.last_seen <= self.chain_window:
                    chains.append(state)

        return sorted(chains, key=lambda s: s.chain_score, reverse=True)

    def get_new_progressions(self) -> list[str]:
        """Return and clear list of entity IDs that just crossed the chain threshold."""
        progressions = list(self._new_progressions)
        self._new_progressions.clear()
        return progressions

    def expire_stale(self, max_age_seconds: int | None = None) -> int:
        """Remove entities not seen within the time window. Returns count removed."""
        cutoff = time.time() - (max_age_seconds or self.chain_window)
        stale = [eid for eid, s in self.entities.items() if s.last_seen < cutoff]
        for eid in stale:
            del self.entities[eid]
        return len(stale)

    def _get_or_create(self, entity_id: str, timestamp: float) -> EntityState:
        if entity_id not in self.entities:
            self.entities[entity_id] = EntityState(
                entity_id=entity_id,
                first_seen=timestamp,
                last_seen=timestamp,
            )
        return self.entities[entity_id]
