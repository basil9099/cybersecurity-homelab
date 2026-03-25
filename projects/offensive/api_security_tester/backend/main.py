#!/usr/bin/env python3
"""
API Security Tester — FastAPI Backend
======================================
Exposes three endpoints:

  POST /scan          — queues a new scan job, returns job_id immediately
  GET  /scan/{job_id} — returns the current status / full results of a scan
  GET  /scan/{job_id}/stream — Server-Sent Events stream for live progress

The scan runs four independent modules concurrently:
  1. Rate Limit Scanner
  2. Auth Bypass Scanner
  3. SQL Injection Scanner
  4. Authorization Flaw Scanner

Usage:
  uvicorn main:app --reload --port 8000

Legal notice:
  Only scan APIs you own or have explicit written permission to test.
  Unauthorised scanning may violate the Computer Fraud and Abuse Act
  (CFAA), the Computer Misuse Act (CMA), or equivalent local laws.
"""

import asyncio
import json
import uuid
from typing import AsyncGenerator

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import AnyHttpUrl, BaseModel, Field

from scanner import (
    AuthBypassScanner,
    AuthzFlawScanner,
    RateLimitScanner,
    SQLInjectionScanner,
)
from scanner.base import ScanResult

# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="API Security Tester",
    description="Educational tool for testing common API security vulnerabilities.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in production
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory job store (replace with Redis for production) ───────────────────

class JobStatus:
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"

jobs: dict[str, dict] = {}
job_events: dict[str, asyncio.Queue] = {}

# ── Request / response models ─────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: AnyHttpUrl = Field(..., description="Full URL of the API endpoint to test")
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Optional HTTP headers to include (e.g. Authorization, Cookie)",
    )
    modules: list[str] = Field(
        default=["rate_limit", "auth_bypass", "sql_injection", "authz_flaws"],
        description="Scanner modules to run",
    )

class ScanResponse(BaseModel):
    job_id: str
    status: str
    message: str

# ── Background scan task ───────────────────────────────────────────────────────

async def _run_scan(job_id: str, target: str, headers: dict[str, str], modules: list[str]) -> None:
    jobs[job_id]["status"] = JobStatus.RUNNING
    q = job_events[job_id]

    scanner_map = {
        "rate_limit": RateLimitScanner,
        "auth_bypass": AuthBypassScanner,
        "sql_injection": SQLInjectionScanner,
        "authz_flaws": AuthzFlawScanner,
    }

    selected = {k: v for k, v in scanner_map.items() if k in modules}

    async def _run_one(key: str, cls) -> tuple[str, ScanResult]:
        await q.put({"event": "module_start", "module": key})
        try:
            scanner = cls(target=target, headers=headers)
            result = await scanner.run()
        except Exception as exc:
            from scanner.base import ScanResult
            result = ScanResult(scanner=key, target=target, error=str(exc))
        await q.put({"event": "module_done", "module": key, "result": result.to_dict()})
        return key, result

    tasks = [_run_one(k, cls) for k, cls in selected.items()]
    results = await asyncio.gather(*tasks, return_exceptions=False)

    jobs[job_id]["results"] = {k: r.to_dict() for k, r in results}
    jobs[job_id]["status"] = JobStatus.DONE
    await q.put({"event": "done"})


# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/scan", response_model=ScanResponse, status_code=202)
async def start_scan(req: ScanRequest) -> ScanResponse:
    """
    Start a security scan against the given API endpoint.
    Returns a job_id you can poll or stream.

    ⚠️  Only target APIs you own or have explicit written permission to test.
    """
    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": JobStatus.PENDING, "target": str(req.target), "results": {}}
    job_events[job_id] = asyncio.Queue()

    asyncio.create_task(_run_scan(job_id, str(req.target), req.headers, req.modules))

    return ScanResponse(
        job_id=job_id,
        status=JobStatus.PENDING,
        message="Scan started. Poll /scan/{job_id} or stream /scan/{job_id}/stream.",
    )


@app.get("/scan/{job_id}")
async def get_scan(job_id: str) -> dict:
    """Poll a scan job for current status and results."""
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]


@app.get("/scan/{job_id}/stream")
async def stream_scan(job_id: str) -> StreamingResponse:
    """
    Server-Sent Events stream.  The client receives events as each
    scanner module completes, allowing real-time progress display.
    """
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    async def _event_generator() -> AsyncGenerator[str, None]:
        q = job_events[job_id]
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=60)
            except asyncio.TimeoutError:
                yield "event: keepalive\ndata: {}\n\n"
                continue

            yield f"data: {json.dumps(event)}\n\n"

            if event.get("event") == "done":
                break

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/")
async def root() -> dict:
    return {
        "name": "API Security Tester",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
    }
