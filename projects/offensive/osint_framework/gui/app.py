"""
OSINT Framework — Web GUI
===========================
FastAPI application that provides a browser-based interface for running OSINT
reconnaissance scans.  Streams real-time progress via Server-Sent Events (SSE)
and renders results in an interactive dashboard.

Launch via the CLI:
    python osint_framework.py --gui [--gui-port 8080]
"""

import asyncio
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from pydantic import BaseModel, field_validator

# Ensure project root is importable
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from osint_framework import (  # noqa: E402
    _DOMAIN_RE,
    _IPV4_RE,
    _IPV6_RE,
    collect_all_emails,
    resolve_target_ips,
    run_breach,
    run_crtsh,
    run_dns,
    run_dorks,
    run_github,
    run_shodan,
    run_wayback,
    run_whois,
)
from modules import reporter  # noqa: E402

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="OSINT Framework GUI", version="1.0.0")

TEMPLATE_DIR = Path(__file__).parent / "templates"

# In-memory job store  (sufficient for single-user / local usage)
_jobs: dict[str, dict[str, Any]] = {}
_job_events: dict[str, asyncio.Queue] = {}  # type: ignore[type-arg]


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    target: str
    modules: list[str] = [
        "whois", "dns", "github", "breach",
        "shodan", "crtsh", "wayback", "dorks",
    ]
    api_keys: dict[str, str] = {}
    options: dict[str, Any] = {}

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip().lower()
        if _DOMAIN_RE.match(v) or _IPV4_RE.match(v) or _IPV6_RE.match(v):
            return v
        raise ValueError(
            f"Invalid target '{v}'. Provide a valid domain or IP address."
        )


class ScanResponse(BaseModel):
    job_id: str
    status: str


# ---------------------------------------------------------------------------
# Adapter: argparse.Namespace replacement
# ---------------------------------------------------------------------------

class GUINamespace:
    """Drop-in replacement for ``argparse.Namespace`` populated from a
    :class:`ScanRequest` so existing runner functions work unchanged."""

    def __init__(self, req: ScanRequest) -> None:
        self.target = req.target
        self.ip: str | None = req.options.get("ip")

        # Module flags
        for mod in ("whois", "dns", "github", "breach",
                     "shodan", "crtsh", "wayback", "dorks"):
            setattr(self, mod, mod in req.modules)

        # API keys
        self.hibp_key = req.api_keys.get("hibp_key")
        self.shodan_key = req.api_keys.get("shodan_key")
        self.github_token = req.api_keys.get("github_token")
        self.google_key = req.api_keys.get("google_key")
        self.google_cse_id = req.api_keys.get("google_cse_id")
        self.bing_key = req.api_keys.get("bing_key")
        self.dehashed_email = req.api_keys.get("dehashed_email")
        self.dehashed_key = req.api_keys.get("dehashed_key")

        # Target details
        self.github_org = req.options.get("github_org")
        self.github_users = req.options.get("github_users")
        self.emails = req.options.get("emails")
        self.subdomain_wordlist = None  # wordlist upload not supported in GUI

        # DNS options
        self.dns_threads = int(req.options.get("dns_threads", 20))
        self.skip_zone_transfer = bool(req.options.get("skip_zone_transfer", False))

        # Shodan options
        self.shodan_query = req.options.get("shodan_query")

        # Wayback options
        self.wayback_from = req.options.get("wayback_from")
        self.wayback_to = req.options.get("wayback_to")
        self.wayback_limit = int(req.options.get("wayback_limit", 50))

        # Misc
        self.all = False
        self.quiet = False
        self.verbose = False


# ---------------------------------------------------------------------------
# Adapter: Progress → SSE queue
# ---------------------------------------------------------------------------

class SSEProgress:
    """Drop-in replacement for the CLI ``Progress`` class that pushes
    messages into an :class:`asyncio.Queue` for SSE streaming."""

    def __init__(self, queue: asyncio.Queue) -> None:  # type: ignore[type-arg]
        self._queue = queue
        self.quiet = False

    def _put(self, payload: dict) -> None:
        self._queue.put_nowait(payload)

    def info(self, msg: str) -> None:
        self._put({"event": "progress", "level": "info", "message": msg})

    def ok(self, msg: str) -> None:
        self._put({"event": "progress", "level": "ok", "message": msg})

    def warn(self, msg: str) -> None:
        self._put({"event": "progress", "level": "warn", "message": msg})

    def section(self, title: str) -> None:
        self._put({"event": "section", "title": title})


# ---------------------------------------------------------------------------
# Scan orchestration (runs in a thread)
# ---------------------------------------------------------------------------

def _sync_scan(args: GUINamespace, prog: SSEProgress) -> tuple[dict, dict[str, str]]:
    """Execute the scan synchronously — mirrors ``osint_framework.main()``."""

    whois_result: dict = {}
    ip_whois_result: dict = {}
    dns_result: dict = {}
    github_org: dict = {}
    github_users: list = []
    breach_results: list = []
    breach_summary: dict = {}
    shodan_results: list = []
    crtsh_result: dict = {}
    wayback_history: dict = {}
    wayback_urls: dict = {}
    search_dorks: dict = {}
    linkedin_dorks: dict = {}

    from modules import social_recon  # noqa: E402 — deferred import

    if args.whois:
        whois_result, ip_whois_result = run_whois(args, prog)

    if args.dns:
        dns_result = run_dns(args, prog)

    if args.github:
        github_org, github_users = run_github(args, prog)
        linkedin_dorks = social_recon.generate_linkedin_dorks(
            args.github_org or args.target.split(".")[0], domain=args.target,
        )

    all_emails = collect_all_emails(
        whois_result, github_org, github_users, args.emails or [],
    )
    if all_emails:
        prog.ok(f"Total emails collected: {len(all_emails)}: {all_emails[:5]}")

    if args.breach:
        if not args.emails and all_emails:
            args.emails = all_emails
        breach_results, breach_summary = run_breach(args, prog)

    target_ips: list[str] = []
    if args.ip:
        target_ips = [args.ip]
    elif dns_result.get("records", {}).get("A"):
        target_ips = dns_result["records"]["A"]
    else:
        target_ips = resolve_target_ips(args.target)

    if args.shodan:
        shodan_results = run_shodan(args, prog, target_ips)

    if args.crtsh:
        crtsh_result = run_crtsh(args, prog)

    if args.wayback:
        wayback_history, wayback_urls = run_wayback(args, prog)

    if args.dorks:
        search_dorks = run_dorks(args, prog)

    # Build profile
    prog.section("Building Target Profile")
    profile = reporter.build_target_profile(
        target=args.target,
        whois_result=whois_result or None,
        ip_whois=ip_whois_result or None,
        dns_result=dns_result or None,
        github_org=github_org or None,
        github_users=github_users or None,
        breach_results=breach_results or None,
        breach_summary=breach_summary or None,
        shodan_results=shodan_results or None,
        crtsh_result=crtsh_result or None,
        wayback_urls=wayback_urls or None,
        wayback_history=wayback_history or None,
        search_dorks=search_dorks or None,
        linkedin_dorks=linkedin_dorks or None,
        emails_found=all_emails or None,
    )

    # Risk summary
    risk = profile["risk_assessment"]
    prog.section("Risk Assessment")
    prog.info(f"Overall risk: {risk['overall_risk']}")
    counts = risk["counts"]
    prog.info(
        f"  Critical:{counts['CRITICAL']}  High:{counts['HIGH']}  "
        f"Medium:{counts['MEDIUM']}  Low:{counts['LOW']}  Info:{counts['INFO']}"
    )

    # Generate reports into a temp directory
    output_dir = tempfile.mkdtemp(prefix="osint_gui_")
    report_paths = reporter.generate_all_reports(profile, output_dir)
    prog.section("Complete")
    prog.ok(f"OSINT reconnaissance finished for {args.target}")

    return profile, report_paths


async def _run_scan(job_id: str, req: ScanRequest) -> None:
    """Kick off the scan in a worker thread and push SSE events."""
    queue = _job_events[job_id]
    _jobs[job_id]["status"] = "running"
    args = GUINamespace(req)
    prog = SSEProgress(queue)

    try:
        profile, paths = await asyncio.to_thread(_sync_scan, args, prog)
        _jobs[job_id]["profile"] = profile
        _jobs[job_id]["report_paths"] = paths
        _jobs[job_id]["status"] = "done"
        queue.put_nowait({"event": "done", "profile": profile})
    except Exception as exc:
        _jobs[job_id]["status"] = "error"
        _jobs[job_id]["error"] = str(exc)
        queue.put_nowait({"event": "error", "message": str(exc)})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = TEMPLATE_DIR / "index.html"
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(req: ScanRequest):
    job_id = uuid.uuid4().hex[:12]
    _jobs[job_id] = {"status": "pending", "request": req.model_dump()}
    _job_events[job_id] = asyncio.Queue()
    asyncio.create_task(_run_scan(job_id, req))
    return ScanResponse(job_id=job_id, status="pending")


@app.get("/api/scan/{job_id}")
async def get_scan(job_id: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    job = _jobs[job_id]
    resp: dict[str, Any] = {"job_id": job_id, "status": job["status"]}
    if job["status"] == "done":
        resp["profile"] = job.get("profile")
    elif job["status"] == "error":
        resp["error"] = job.get("error")
    return resp


@app.get("/api/scan/{job_id}/stream")
async def stream_scan(job_id: str):
    if job_id not in _job_events:
        raise HTTPException(status_code=404, detail="Job not found")

    async def _event_generator():
        queue = _job_events[job_id]
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30)
            except asyncio.TimeoutError:
                yield "event: keepalive\ndata: {}\n\n"
                continue
            yield f"data: {json.dumps(event, default=str)}\n\n"
            if event.get("event") in ("done", "error"):
                break

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/scan/{job_id}/report/{fmt}")
async def download_report(job_id: str, fmt: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    if fmt not in ("json", "text", "html"):
        raise HTTPException(status_code=400, detail="Format must be json, text, or html")

    paths = _jobs[job_id].get("report_paths", {})
    path = paths.get(fmt)
    if not path or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Report not yet available")

    media_types = {
        "json": "application/json",
        "text": "text/plain",
        "html": "text/html",
    }
    return FileResponse(
        path,
        media_type=media_types[fmt],
        filename=os.path.basename(path),
    )


# ---------------------------------------------------------------------------
# Entry point called from osint_framework.py --gui
# ---------------------------------------------------------------------------

def launch_gui(host: str = "0.0.0.0", port: int = 8080) -> None:
    """Start the Uvicorn server for the OSINT Framework GUI."""
    import uvicorn

    print(f"\n  [*] OSINT Framework GUI starting on http://localhost:{port}")
    print("  [*] Press Ctrl+C to stop.\n")
    uvicorn.run(app, host=host, port=port, log_level="info")
