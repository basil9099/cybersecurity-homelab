"""Social media intelligence REST endpoints."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

router = APIRouter(prefix="/api/social", tags=["social"])


def _db(request: Request):
    return request.app.state.db


@router.get("/feed")
def social_feed(
    db=Depends(_db),
    source: str | None = None,
    limit: int = Query(30, le=100),
) -> list[dict[str, Any]]:
    conditions = []
    params: list = []
    if source:
        conditions.append("source = ?")
        params.append(source)

    where = " AND ".join(conditions) if conditions else "1=1"
    rows = db.query(
        f"SELECT * FROM social_posts WHERE {where} ORDER BY published_date DESC LIMIT ?",
        (*params, limit),
    )
    for r in rows:
        for field in ("keywords", "related_cves"):
            if isinstance(r.get(field), str):
                try:
                    r[field] = json.loads(r[field])
                except (json.JSONDecodeError, TypeError):
                    pass
    return rows


@router.get("/trending")
def trending_topics(db=Depends(_db)) -> list[dict[str, Any]]:
    """Get trending keywords from recent posts."""
    rows = db.query(
        "SELECT keywords FROM social_posts ORDER BY published_date DESC LIMIT 50"
    )
    keyword_counts: dict[str, int] = {}
    for r in rows:
        kws = r.get("keywords", "[]")
        if isinstance(kws, str):
            try:
                kws = json.loads(kws)
            except (json.JSONDecodeError, TypeError):
                kws = []
        for kw in kws:
            keyword_counts[kw] = keyword_counts.get(kw, 0) + 1

    trending = sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    return [{"keyword": kw, "count": cnt} for kw, cnt in trending]
