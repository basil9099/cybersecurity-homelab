#!/usr/bin/env python3
"""
correlation/chains.py
=====================
Attack chain detection and lifecycle management.

Orchestrates the full correlation pipeline:
  1. Accept normalized alerts from any source
  2. Feed them into the ATT&CK state machine (attack_graph)
  3. Score entities with the Bayesian scorer
  4. Track chain lifecycle (new → active → escalated → resolved)
  5. Generate human-readable chain summaries
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from correlation.attack_graph import AttackGraph, EntityState
from correlation.scoring import BayesianScorer, ChainScore, ScoringConfig
from ingestion.schema import NormalizedAlert
from mappings.mitre_attack import TACTIC_ORDER


@dataclass
class AttackChain:
    """A detected attack chain with full context."""
    chain_id: str
    entity_id: str
    status: str = "active"          # active | escalated | resolved
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    score: ChainScore | None = None
    state: EntityState | None = None
    alert_count: int = 0
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        score_dict = {}
        if self.score:
            score_dict = {
                "posterior": self.score.posterior,
                "composite": self.score.composite,
                "completeness": self.score.completeness,
                "velocity": self.score.velocity,
                "order_score": self.score.order_score,
                "quality": self.score.quality,
                "diversity": self.score.diversity,
                "escalation_level": self.score.escalation_level,
            }

        tactics = []
        if self.state:
            for obs in self.state.tactics_in_order:
                tactics.append({
                    "tactic": obs.tactic,
                    "stage": obs.stage,
                    "alert_count": obs.alert_count,
                    "max_score": obs.max_score,
                    "technique_ids": obs.technique_ids,
                    "first_seen": obs.first_seen,
                    "last_seen": obs.last_seen,
                })

        return {
            "chain_id": self.chain_id,
            "entity_id": self.entity_id,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "score": score_dict,
            "tactics": tactics,
            "alert_count": self.alert_count,
            "summary": self.summary,
        }


class ChainManager:
    """
    Orchestrates attack chain detection and lifecycle.

    Usage:
        manager = ChainManager()
        for alert in incoming_alerts:
            chains = manager.process_alert(alert)
            for chain in chains:
                if chain.score.escalation_level == "critical":
                    notify_soc(chain)
    """

    def __init__(
        self,
        chain_window_seconds: int = 3600,
        min_chain_stages: int = 3,
        scoring_config: ScoringConfig | None = None,
    ):
        self.graph = AttackGraph(
            chain_window_seconds=chain_window_seconds,
            min_chain_stages=min_chain_stages,
        )
        self.scorer = BayesianScorer(scoring_config)
        self.chains: dict[str, AttackChain] = {}
        self._chain_counter = 0
        self._alert_log: list[NormalizedAlert] = []

    def process_alert(self, alert: NormalizedAlert) -> list[AttackChain]:
        """
        Process a single alert through the correlation pipeline.

        Returns:
            List of AttackChain objects that were created or updated.
        """
        self._alert_log.append(alert)

        # Update attack graph
        state = self.graph.process_alert(alert)
        if state is None:
            return []

        # Check for new progressions
        new_entities = self.graph.get_new_progressions()

        updated_chains: list[AttackChain] = []

        # Create chains for newly-qualifying entities
        for entity_id in new_entities:
            if entity_id not in self.chains:
                chain = self._create_chain(entity_id)
                updated_chains.append(chain)

        # Update existing chain for this entity
        entity_id = alert.src_entity
        if entity_id in self.chains:
            chain = self._update_chain(entity_id)
            if chain not in updated_chains:
                updated_chains.append(chain)

        return updated_chains

    def process_batch(self, alerts: list[NormalizedAlert]) -> list[AttackChain]:
        """Process a batch of alerts sorted by timestamp."""
        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
        all_chains: list[AttackChain] = []
        seen: set[str] = set()

        for alert in sorted_alerts:
            chains = self.process_alert(alert)
            for chain in chains:
                if chain.chain_id not in seen:
                    all_chains.append(chain)
                    seen.add(chain.chain_id)

        return all_chains

    def get_active_chains(self) -> list[AttackChain]:
        """Return all active/escalated chains sorted by score descending."""
        active = [
            c for c in self.chains.values()
            if c.status in ("active", "escalated")
        ]
        return sorted(
            active,
            key=lambda c: c.score.composite if c.score else 0,
            reverse=True,
        )

    def resolve_chain(self, chain_id: str) -> bool:
        """Mark a chain as resolved. Returns True if found."""
        if chain_id in self.chains:
            self.chains[chain_id].status = "resolved"
            self.chains[chain_id].updated_at = time.time()
            return True
        return False

    def get_chain(self, chain_id: str) -> AttackChain | None:
        return self.chains.get(chain_id)

    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics."""
        active = [c for c in self.chains.values() if c.status == "active"]
        escalated = [c for c in self.chains.values() if c.status == "escalated"]
        resolved = [c for c in self.chains.values() if c.status == "resolved"]
        return {
            "total_alerts_processed": len(self._alert_log),
            "tracked_entities": len(self.graph.entities),
            "active_chains": len(active),
            "escalated_chains": len(escalated),
            "resolved_chains": len(resolved),
        }

    def expire_stale(self) -> int:
        """Expire stale entities and resolve their chains."""
        expired = self.graph.expire_stale()
        for chain_id, chain in list(self.chains.items()):
            if chain.entity_id not in self.graph.entities and chain.status != "resolved":
                chain.status = "resolved"
                chain.updated_at = time.time()
        return expired

    # ── Internal ──────────────────────────────────────────────────────────────

    def _create_chain(self, entity_id: str) -> AttackChain:
        self._chain_counter += 1
        chain_id = f"CHAIN-{self._chain_counter:04d}"

        state = self.graph.entities.get(entity_id)
        score = self.scorer.score_entity(state) if state else None

        chain = AttackChain(
            chain_id=chain_id,
            entity_id=entity_id,
            status="escalated" if score and score.escalation_level == "critical" else "active",
            score=score,
            state=state,
            alert_count=len(state.alert_ids) if state else 0,
            summary=self._generate_summary(entity_id, state, score),
        )
        self.chains[entity_id] = chain
        return chain

    def _update_chain(self, entity_id: str) -> AttackChain:
        chain = self.chains[entity_id]
        state = self.graph.entities.get(entity_id)
        score = self.scorer.score_entity(state) if state else chain.score

        chain.score = score
        chain.state = state
        chain.updated_at = time.time()
        chain.alert_count = len(state.alert_ids) if state else chain.alert_count
        chain.summary = self._generate_summary(entity_id, state, score)

        if score and score.escalation_level == "critical" and chain.status == "active":
            chain.status = "escalated"

        return chain

    @staticmethod
    def _generate_summary(
        entity_id: str,
        state: EntityState | None,
        score: ChainScore | None,
    ) -> str:
        """Generate a human-readable chain summary."""
        if not state or not score:
            return f"Tracking entity {entity_id}"

        tactics = [obs.tactic.replace("_", " ").title() for obs in state.tactics_in_order]
        chain_str = " → ".join(tactics)

        time_span = state.time_span
        if time_span < 60:
            time_str = f"{time_span:.0f}s"
        elif time_span < 3600:
            time_str = f"{time_span / 60:.1f}m"
        else:
            time_str = f"{time_span / 3600:.1f}h"

        return (
            f"Entity {entity_id} observed progressing through {state.chain_length} "
            f"ATT&CK stages ({chain_str}) over {time_str}. "
            f"Bayesian posterior: {score.posterior:.1%}. "
            f"Composite score: {score.composite:.1f}/10. "
            f"Escalation: {score.escalation_level.upper()}."
        )
