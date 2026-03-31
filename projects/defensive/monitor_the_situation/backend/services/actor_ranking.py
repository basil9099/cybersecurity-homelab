"""Threat actor ranking and leaderboard computation."""

from __future__ import annotations

import json
from typing import Any

from backend.database import Database

_SOPHISTICATION_MAP = {"low": 2.0, "medium": 5.0, "high": 7.5, "advanced": 10.0}


def compute_rankings(db: Database) -> None:
    """Recompute rank_score for all actors and update the DB."""
    actors = db.query("SELECT id, campaign_count, technique_count, sophistication FROM threat_actors")
    for a in actors:
        soph = _SOPHISTICATION_MAP.get(a["sophistication"] or "medium", 5.0)
        score = round(
            (a["campaign_count"] or 0) * 0.4
            + (a["technique_count"] or 0) * 0.3
            + soph * 0.3,
            2,
        )
        db.execute(
            "UPDATE threat_actors SET rank_score = ?, technique_count = "
            "(SELECT COUNT(*) FROM actor_ttps WHERE actor_id = ?) WHERE id = ?",
            (score, a["id"], a["id"]),
        )


def get_leaderboard(db: Database, limit: int = 10) -> list[dict[str, Any]]:
    """Get ranked list of threat actors with their TTPs."""
    actors = db.query(
        "SELECT * FROM threat_actors ORDER BY rank_score DESC LIMIT ?",
        (limit,),
    )
    result = []
    for i, actor in enumerate(actors):
        ttps = db.query(
            "SELECT * FROM actor_ttps WHERE actor_id = ? ORDER BY usage_count DESC",
            (actor["id"],),
        )
        # Parse JSON fields
        for field in ("aliases", "target_sectors", "target_countries"):
            val = actor.get(field)
            if isinstance(val, str):
                try:
                    actor[field] = json.loads(val)
                except (json.JSONDecodeError, TypeError):
                    actor[field] = []

        result.append({
            "rank": i + 1,
            "actor": actor,
            "ttps": ttps,
        })
    return result
