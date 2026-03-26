#!/usr/bin/env python3
"""
api/server.py
=============
FastAPI server for the attack chain correlator.

Provides:
  - REST endpoints for querying chains, alerts, and stats
  - SSE streaming for real-time chain updates
  - Alert ingestion endpoint for external tools to push alerts
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from correlation.chains import ChainManager
from correlation.scoring import ScoringConfig
from ingestion.schema import NormalizedAlert, Severity, AlertSource
from storage.database import ChainStorage

app = FastAPI(
    title="Attack Chain Correlator",
    description="AI-powered ATT&CK kill chain correlation with Bayesian scoring",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Global state ─────────────────────────────────────────────────────────────

_manager: ChainManager | None = None
_storage: ChainStorage | None = None
_sse_queues: list[asyncio.Queue] = []


def get_manager() -> ChainManager:
    global _manager
    if _manager is None:
        _manager = ChainManager(
            chain_window_seconds=3600,
            min_chain_stages=3,
            scoring_config=ScoringConfig(),
        )
    return _manager


def get_storage() -> ChainStorage:
    global _storage
    if _storage is None:
        _storage = ChainStorage()
    return _storage


# ── SSE streaming ────────────────────────────────────────────────────────────

async def _broadcast_event(event_type: str, data: dict[str, Any]) -> None:
    """Send an event to all connected SSE clients."""
    message = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    dead: list[asyncio.Queue] = []
    for queue in _sse_queues:
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            dead.append(queue)
    for q in dead:
        _sse_queues.remove(q)


@app.get("/api/stream")
async def stream_events():
    """SSE endpoint for real-time attack chain updates."""
    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    _sse_queues.append(queue)

    async def event_generator():
        try:
            # Send initial heartbeat
            yield f"event: connected\ndata: {json.dumps({'status': 'ok'})}\n\n"
            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield message
                except asyncio.TimeoutError:
                    yield f"event: heartbeat\ndata: {json.dumps({'ts': time.time()})}\n\n"
        finally:
            if queue in _sse_queues:
                _sse_queues.remove(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Alert ingestion ──────────────────────────────────────────────────────────

@app.post("/api/alerts")
async def ingest_alert(alert_data: dict[str, Any]):
    """
    Ingest a single alert from any source.

    Accepts a JSON body matching the NormalizedAlert schema.
    """
    manager = get_manager()
    storage = get_storage()

    alert = NormalizedAlert.from_dict(alert_data)
    storage.insert_alert(alert.to_dict())

    chains = manager.process_alert(alert)

    # Persist and broadcast chain updates
    for chain in chains:
        chain_dict = chain.to_dict()
        storage.upsert_chain(chain_dict)
        if chain.score:
            storage.record_score(chain.chain_id, {
                "composite": chain.score.composite,
                "posterior": chain.score.posterior,
                "stages_observed": chain.score.stages_observed,
                "escalation_level": chain.score.escalation_level,
            })
        await _broadcast_event("chain_update", chain_dict)

    return {
        "status": "ok",
        "alert_id": alert.alert_id,
        "chains_updated": len(chains),
    }


@app.post("/api/alerts/batch")
async def ingest_batch(alerts: list[dict[str, Any]]):
    """Ingest a batch of alerts."""
    manager = get_manager()
    storage = get_storage()

    normalized = [NormalizedAlert.from_dict(a) for a in alerts]
    for alert in normalized:
        storage.insert_alert(alert.to_dict())

    chains = manager.process_batch(normalized)

    for chain in chains:
        chain_dict = chain.to_dict()
        storage.upsert_chain(chain_dict)
        await _broadcast_event("chain_update", chain_dict)

    return {
        "status": "ok",
        "alerts_processed": len(normalized),
        "chains_updated": len(chains),
    }


# ── Chain queries ────────────────────────────────────────────────────────────

@app.get("/api/chains")
async def list_chains(
    status: str | None = Query(None, description="Filter by status: active, escalated, resolved"),
):
    """List all attack chains."""
    manager = get_manager()
    if status:
        chains = [c for c in manager.chains.values() if c.status == status]
    else:
        chains = list(manager.chains.values())

    sorted_chains = sorted(
        chains,
        key=lambda c: c.score.composite if c.score else 0,
        reverse=True,
    )
    return [c.to_dict() for c in sorted_chains]


@app.get("/api/chains/{entity_id}")
async def get_chain(entity_id: str):
    """Get details for a specific entity's attack chain."""
    manager = get_manager()
    chain = manager.chains.get(entity_id)
    if not chain:
        return {"error": "Chain not found"}, 404
    return chain.to_dict()


@app.post("/api/chains/{entity_id}/resolve")
async def resolve_chain(entity_id: str):
    """Mark an attack chain as resolved."""
    manager = get_manager()
    if entity_id in manager.chains:
        manager.chains[entity_id].status = "resolved"
        manager.chains[entity_id].updated_at = time.time()
        chain_dict = manager.chains[entity_id].to_dict()
        get_storage().upsert_chain(chain_dict)
        await _broadcast_event("chain_resolved", chain_dict)
        return {"status": "resolved", "chain_id": manager.chains[entity_id].chain_id}
    return {"error": "Chain not found"}


# ── Stats & health ───────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats():
    """Get correlator statistics."""
    manager = get_manager()
    db_stats = get_storage().get_stats()
    engine_stats = manager.get_stats()
    return {**db_stats, **engine_stats}


@app.get("/api/health")
async def health():
    return {"status": "healthy", "timestamp": time.time()}


@app.get("/api/alerts")
async def list_alerts(
    entity: str | None = Query(None),
    tactic: str | None = Query(None),
    limit: int = Query(100, le=500),
):
    """Query normalized alerts from the database."""
    return get_storage().query_alerts(entity=entity, tactic=tactic, limit=limit)
