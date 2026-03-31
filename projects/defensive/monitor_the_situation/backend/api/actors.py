"""Threat actor REST endpoints."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from backend.services.actor_ranking import get_leaderboard

router = APIRouter(prefix="/api/actors", tags=["actors"])


def _db(request: Request):
    return request.app.state.db


@router.get("")
def list_actors(
    db=Depends(_db),
    limit: int = Query(10, le=50),
) -> list[dict[str, Any]]:
    return get_leaderboard(db, limit)


@router.get("/{actor_id}")
def get_actor(actor_id: str, db=Depends(_db)) -> dict[str, Any]:
    actors = db.query("SELECT * FROM threat_actors WHERE id = ?", (actor_id,))
    if not actors:
        return {"error": "Actor not found"}

    actor = actors[0]
    for field in ("aliases", "target_sectors", "target_countries"):
        if isinstance(actor.get(field), str):
            try:
                actor[field] = json.loads(actor[field])
            except (json.JSONDecodeError, TypeError):
                pass

    ttps = db.query(
        "SELECT * FROM actor_ttps WHERE actor_id = ? ORDER BY usage_count DESC",
        (actor_id,),
    )
    actor["ttps"] = ttps
    return actor


@router.get("/{actor_id}/ttps")
def get_actor_ttps(actor_id: str, db=Depends(_db)) -> list[dict[str, Any]]:
    return db.query(
        "SELECT * FROM actor_ttps WHERE actor_id = ? ORDER BY usage_count DESC",
        (actor_id,),
    )
