"""Health and alerts REST endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request

router = APIRouter(tags=["health"])


def _db(request: Request):
    return request.app.state.db


@router.get("/api/health")
def system_health(db=Depends(_db)) -> dict[str, Any]:
    collectors = db.query("SELECT * FROM collector_health")
    ok_count = sum(1 for c in collectors if c["status"] == "ok")
    total = len(collectors)
    return {
        "status": "healthy" if ok_count == total else "degraded",
        "collectors_ok": ok_count,
        "collectors_total": total,
    }


@router.get("/api/health/collectors")
def collector_health(db=Depends(_db)) -> list[dict[str, Any]]:
    return db.query("SELECT * FROM collector_health ORDER BY collector_name")


@router.get("/api/alerts")
def list_alerts(
    db=Depends(_db),
    severity: str | None = None,
    acknowledged: bool | None = None,
    limit: int = Query(20, le=100),
) -> list[dict[str, Any]]:
    conditions = []
    params: list = []
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if acknowledged is not None:
        conditions.append("acknowledged = ?")
        params.append(1 if acknowledged else 0)

    where = " AND ".join(conditions) if conditions else "1=1"
    return db.query(
        f"SELECT * FROM alerts WHERE {where} ORDER BY created_at DESC LIMIT ?",
        (*params, limit),
    )


@router.post("/api/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str, db=Depends(_db)) -> dict[str, str]:
    db.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
    return {"status": "acknowledged"}
