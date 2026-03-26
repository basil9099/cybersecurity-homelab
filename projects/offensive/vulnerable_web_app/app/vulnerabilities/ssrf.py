"""Server-Side Request Forgery - OWASP A10:2021 SSRF.

Challenges:
  - Fetch arbitrary URLs from the server
  - Access internal services and metadata endpoints
"""

import httpx

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

router = APIRouter()
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates")
)

# Simulated internal service response
INTERNAL_SERVICES: dict[str, str] = {
    "http://127.0.0.1:8080/internal/secret": (
        '{"service": "internal-api", "flag": "FLAG{ssrf_internal_service_accessed}", '
        '"credentials": {"db_user": "root", "db_pass": "s3cretP@ss"}}'
    ),
    "http://localhost:8080/internal/secret": (
        '{"service": "internal-api", "flag": "FLAG{ssrf_internal_service_accessed}", '
        '"credentials": {"db_user": "root", "db_pass": "s3cretP@ss"}}'
    ),
    "http://169.254.169.254/latest/meta-data/": (
        "ami-id\nami-launch-index\nami-manifest-path\nhostname\n"
        "instance-id\nlocal-ipv4\npublic-ipv4\niam/"
    ),
}


@router.get("/fetch", response_class=HTMLResponse)
async def ssrf_fetch_page(request: Request) -> HTMLResponse:
    """Render the URL fetcher page."""
    return templates.TemplateResponse(
        "ssrf_fetch.html",
        {"request": request, "response_data": None, "url": ""},
    )


@router.post("/fetch", response_class=HTMLResponse)
async def ssrf_fetch(
    request: Request,
    url: str = Form(...),
) -> HTMLResponse:
    """VULNERABLE: Fetches arbitrary URLs without restriction.

    No URL validation or allowlisting allows access to internal services:
        http://127.0.0.1:8080/internal/secret
        http://169.254.169.254/latest/meta-data/
        file:///etc/passwd
    """
    response_data = None

    # Check simulated internal services first
    if url in INTERNAL_SERVICES:
        response_data = {
            "status": 200,
            "body": INTERNAL_SERVICES[url],
            "url": url,
        }
    else:
        # VULN: No URL validation - fetches arbitrary URLs
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=5.0) as client:
                resp = await client.get(url)
                response_data = {
                    "status": resp.status_code,
                    "body": resp.text[:5000],
                    "url": url,
                }
        except Exception as e:
            response_data = {
                "status": "error",
                "body": f"Request failed: {e}",
                "url": url,
            }

    return templates.TemplateResponse(
        "ssrf_fetch.html",
        {"request": request, "response_data": response_data, "url": url},
    )


@router.get("/internal/secret")
async def internal_secret() -> JSONResponse:
    """Simulated internal service - should not be directly accessible."""
    return JSONResponse({
        "service": "internal-api",
        "flag": "FLAG{ssrf_internal_service_accessed}",
        "credentials": {"db_user": "root", "db_pass": "s3cretP@ss"},
    })
