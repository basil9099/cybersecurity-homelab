"""CVE REST endpoints."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from backend.services.cve_velocity import compute_velocity, get_critical_cves, get_cve_stats

router = APIRouter(prefix="/api/cves", tags=["cves"])


def _db(request: Request):
    return request.app.state.db


@router.get("")
def list_cves(
    db=Depends(_db),
    severity: str | None = None,
    min_cvss: float | None = None,
    has_exploit: bool | None = None,
    since: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
) -> list[dict[str, Any]]:
    conditions = []
    params: list = []
    if severity:
        conditions.append("cvss_severity = ?")
        params.append(severity.upper())
    if min_cvss is not None:
        conditions.append("cvss_score >= ?")
        params.append(min_cvss)
    if has_exploit is not None:
        conditions.append("has_exploit = ?")
        params.append(1 if has_exploit else 0)
    if since:
        conditions.append("published_date >= ?")
        params.append(since)

    where = " AND ".join(conditions) if conditions else "1=1"
    rows = db.query(
        f"SELECT * FROM cves WHERE {where} ORDER BY published_date DESC LIMIT ? OFFSET ?",
        (*params, limit, offset),
    )
    for r in rows:
        for field in ("cwe_ids", "affected_products", "references_"):
            if isinstance(r.get(field), str):
                try:
                    r[field] = json.loads(r[field])
                except (json.JSONDecodeError, TypeError):
                    pass
    return rows


@router.get("/velocity")
def cve_velocity(
    db=Depends(_db),
    days: int = Query(30, le=90),
) -> list[dict[str, Any]]:
    return compute_velocity(db, days)


@router.get("/critical")
def critical_cves(
    db=Depends(_db),
    min_cvss: float = 9.0,
    limit: int = Query(20, le=50),
) -> list[dict[str, Any]]:
    return get_critical_cves(db, min_cvss, limit)


@router.get("/stats")
def cve_stats(db=Depends(_db)) -> dict[str, Any]:
    return get_cve_stats(db)


@router.get("/{cve_id}")
def get_cve_detail(cve_id: str, db=Depends(_db)) -> dict[str, Any]:
    cves = db.query("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
    if not cves:
        return {"error": "CVE not found"}

    cve = cves[0]
    for field in ("cwe_ids", "affected_products", "references_"):
        if isinstance(cve.get(field), str):
            try:
                cve[field] = json.loads(cve[field])
            except (json.JSONDecodeError, TypeError):
                pass

    exploits = db.query(
        "SELECT * FROM exploits WHERE cve_id = ? ORDER BY published_date DESC",
        (cve_id,),
    )
    cve["exploits"] = exploits
    return cve
