"""FastAPI application factory for Monitor the Situation."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import Settings
from backend.database import Database
from backend.scheduler import setup_scheduler


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start the APScheduler on startup and shut it down on teardown."""
    ws_hub = getattr(app.state, "ws_hub", None)
    scheduler = setup_scheduler(app.state.settings, app.state.db, ws_hub)
    if scheduler is not None:
        scheduler.start()
        app.state.scheduler = scheduler
    try:
        yield
    finally:
        if scheduler is not None:
            scheduler.shutdown(wait=False)


def create_app(settings: Settings, db: Database) -> FastAPI:
    """Build and return the configured FastAPI application."""
    app = FastAPI(
        title="Monitor the Situation",
        description="Cybersecurity threat intelligence dashboard API",
        version="0.1.0",
        lifespan=_lifespan,
    )

    # Store dependencies on app state for access in routes / lifespan
    app.state.settings = settings
    app.state.db = db

    # Wire up WebSocket hub
    from backend.api.websocket import hub
    app.state.ws_hub = hub

    # CORS -- permissive for homelab use.
    # Note: allow_credentials=True requires explicit origins (not "*").
    # Default to localhost variants; override via CORS_ORIGINS env var.
    cors_origins = settings.cors_origins or [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:3000",
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Import and include routers
    from backend.api import (
        actors,
        cves,
        exploits,
        health,
        social,
        threat_map,
        websocket,
    )

    app.include_router(threat_map.router)
    app.include_router(cves.router)
    app.include_router(actors.router)
    app.include_router(exploits.router)
    app.include_router(social.router)
    app.include_router(health.router)
    app.include_router(websocket.router)

    @app.get("/")
    async def root() -> dict:
        return {
            "project": "Monitor the Situation",
            "version": "0.1.0",
            "demo_mode": settings.demo_mode,
            "docs": "/docs",
        }

    return app
