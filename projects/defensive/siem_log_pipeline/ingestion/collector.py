"""
ingestion.collector — Log collection backends.

* **DirectoryCollector** — polls a directory for ``.json`` / ``.jsonl``
  files, reads new entries, normalizes them, and stores in the database.
* **HTTPCollector** — exposes a FastAPI ``POST /ingest`` endpoint that
  accepts JSON events over HTTP.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ingestion.normalizer import EventNormalizer, NormalizedEvent
from storage.database import EventDatabase


class DirectoryCollector:
    """Watch a directory for new/modified log files and ingest them."""

    def __init__(
        self,
        db: EventDatabase,
        normalizer: EventNormalizer,
        watch_dir: Path,
        poll_interval: float = 2.0,
    ) -> None:
        self._db = db
        self._normalizer = normalizer
        self._watch_dir = Path(watch_dir)
        self._poll_interval = poll_interval
        self._running = False
        # Track file positions so we only read new lines.
        self._offsets: dict[Path, int] = {}

    # ------------------------------------------------------------------

    def run(self) -> None:
        """Start the blocking poll loop."""
        self._running = True
        while self._running:
            self._poll()
            time.sleep(self._poll_interval)

    def stop(self) -> None:
        """Signal the poll loop to exit."""
        self._running = False

    # ------------------------------------------------------------------

    def _poll(self) -> None:
        """Scan the watch directory for log files and process new data."""
        if not self._watch_dir.is_dir():
            return

        for path in sorted(self._watch_dir.iterdir()):
            if path.suffix in (".json", ".jsonl"):
                self._process_file(path)

    def _process_file(self, path: Path) -> None:
        """Read new content from a single log file."""
        offset = self._offsets.get(path, 0)
        try:
            size = path.stat().st_size
        except OSError:
            return

        if size <= offset:
            return

        try:
            with open(path, "r", encoding="utf-8") as fh:
                fh.seek(offset)
                new_data = fh.read()
                self._offsets[path] = fh.tell()
        except OSError:
            return

        events = self._parse_raw(path, new_data)
        for source_type, raw in events:
            normalized = self._normalizer.normalize(source_type, raw)
            if normalized is not None:
                self._db.insert_event(normalized)
                print(
                    f"  [+] {normalized.source}: {normalized.message[:80]}"
                )

    def _parse_raw(
        self, path: Path, data: str
    ) -> list[tuple[str, dict[str, Any]]]:
        """Attempt to parse *data* as JSON or JSONL and detect source type."""
        results: list[tuple[str, dict[str, Any]]] = []

        # Try JSONL first (one JSON object per line).
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            source_type = self._normalizer.detect_source_type(obj)
            if source_type is None:
                # Fall back to filename heuristic.
                source_type = self._guess_source_from_filename(path)
            if source_type:
                results.append((source_type, obj))

        # If JSONL yielded nothing, try treating the whole blob as JSON.
        if not results:
            try:
                obj = json.loads(data)
                if isinstance(obj, list):
                    for item in obj:
                        source_type = self._normalizer.detect_source_type(item)
                        if source_type is None:
                            source_type = self._guess_source_from_filename(path)
                        if source_type:
                            results.append((source_type, item))
                elif isinstance(obj, dict):
                    source_type = self._normalizer.detect_source_type(obj)
                    if source_type is None:
                        source_type = self._guess_source_from_filename(path)
                    if source_type:
                        results.append((source_type, obj))
            except json.JSONDecodeError:
                pass

        return results

    @staticmethod
    def _guess_source_from_filename(path: Path) -> str | None:
        """Use the filename to guess the source type."""
        name = path.stem.lower()
        if "honeypot" in name:
            return "honeypot"
        if "network" in name or "baseline" in name:
            return "network_baseline"
        if "attack" in name or "correlat" in name:
            return "attack_correlator"
        if "cloud" in name or "scanner" in name:
            return "cloud_scanner"
        return None


class HTTPCollector:
    """FastAPI-based HTTP endpoint for log ingestion.

    Accepts ``POST /ingest`` with a JSON body containing either a single
    event dict or a list of event dicts.
    """

    def __init__(
        self,
        db: EventDatabase,
        normalizer: EventNormalizer,
        host: str = "0.0.0.0",
        port: int = 8000,
    ) -> None:
        self._db = db
        self._normalizer = normalizer
        self._host = host
        self._port = port

    def _build_app(self) -> Any:
        """Construct the FastAPI application."""
        from fastapi import FastAPI, HTTPException
        from fastapi.responses import JSONResponse

        app = FastAPI(title="SENTINEL Ingestion API", version="1.0.0")

        @app.post("/ingest")
        async def ingest_event(payload: dict[str, Any] | list[dict[str, Any]]) -> JSONResponse:
            """Accept one or more raw events and store them."""
            events: list[dict[str, Any]] = (
                payload if isinstance(payload, list) else [payload]
            )
            stored = 0
            for raw in events:
                source_type = self._normalizer.detect_source_type(raw)
                if source_type is None:
                    continue
                normalized = self._normalizer.normalize(source_type, raw)
                if normalized is not None:
                    self._db.insert_event(normalized)
                    stored += 1

            return JSONResponse(
                content={"status": "ok", "stored": stored, "received": len(events)},
                status_code=200,
            )

        @app.get("/health")
        async def health() -> dict[str, str]:
            return {"status": "healthy"}

        return app

    def run(self) -> None:
        """Start the Uvicorn server (blocking)."""
        import uvicorn

        app = self._build_app()
        uvicorn.run(app, host=self._host, port=self._port, log_level="info")
