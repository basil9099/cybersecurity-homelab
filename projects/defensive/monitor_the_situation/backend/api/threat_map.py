"""Threat map REST endpoints."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

router = APIRouter(prefix="/api/threat-map", tags=["threat-map"])


def _db(request: Request):
    return request.app.state.db


@router.get("")
def get_threat_events(
    db=Depends(_db),
    since: str | None = None,
    category: str | None = None,
    country: str | None = None,
    limit: int = Query(200, le=1000),
) -> list[dict[str, Any]]:
    conditions = []
    params: list = []
    if since:
        conditions.append("last_seen >= ?")
        params.append(since)
    if category:
        conditions.append("category = ?")
        params.append(category)
    if country:
        conditions.append("country = ?")
        params.append(country)

    where = " AND ".join(conditions) if conditions else "1=1"
    rows = db.query(
        f"SELECT * FROM threat_events WHERE {where} ORDER BY last_seen DESC LIMIT ?",
        (*params, limit),
    )
    for r in rows:
        if isinstance(r.get("tags"), str):
            r["tags"] = json.loads(r["tags"])
    return rows


@router.get("/countries")
def get_country_aggregation(db=Depends(_db)) -> list[dict[str, Any]]:
    return db.query(
        """
        SELECT country, COUNT(*) as count,
               GROUP_CONCAT(DISTINCT category) as categories
        FROM threat_events
        WHERE country IS NOT NULL
        GROUP BY country
        ORDER BY count DESC
        LIMIT 50
        """
    )


@router.get("/stats")
def get_threat_map_stats(db=Depends(_db)) -> dict[str, Any]:
    total = db.count("threat_events")
    unique_ips = db.query("SELECT COUNT(DISTINCT ip) as cnt FROM threat_events")[0]["cnt"]
    events_24h = db.query(
        "SELECT COUNT(*) as cnt FROM threat_events WHERE last_seen >= datetime('now', '-1 day')"
    )[0]["cnt"]

    top_countries = db.query(
        "SELECT country, COUNT(*) as count FROM threat_events "
        "WHERE country IS NOT NULL GROUP BY country ORDER BY count DESC LIMIT 10"
    )
    top_categories = db.query(
        "SELECT category, COUNT(*) as count FROM threat_events "
        "WHERE category IS NOT NULL GROUP BY category ORDER BY count DESC"
    )

    return {
        "total_events": total,
        "unique_ips": unique_ips,
        "events_last_24h": events_24h,
        "top_countries": top_countries,
        "top_categories": {r["category"]: r["count"] for r in top_categories},
    }
