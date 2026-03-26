"""Path Traversal - OWASP A01:2021 Broken Access Control.

Challenges:
  - Read arbitrary files using ../ directory traversal
  - Escape the sandbox directory to access system files
"""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.config import settings

router = APIRouter()
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates")
)


@router.get("/read", response_class=HTMLResponse)
async def path_traversal_read(
    request: Request, filename: str = "welcome.txt"
) -> HTMLResponse:
    """VULNERABLE: Read files using directory traversal.

    The filename parameter is joined with the base directory without
    sanitization, allowing traversal with ../:
        /files/read?filename=../../../etc/passwd
        /files/read?filename=secret.txt
        /files/read?filename=../../main.py
    """
    # VULN: No path sanitization - allows directory traversal
    file_path = Path(settings.FILES_DIR) / filename
    file_content = None
    error = None
    flag = None

    try:
        # VULN: No check that resolved path is within sandbox
        with open(str(file_path), "r") as f:
            file_content = f.read()

        # Check if user traversed outside the sandbox
        sandbox_resolved = Path(settings.FILES_DIR).resolve()
        target_resolved = file_path.resolve()
        if not str(target_resolved).startswith(str(sandbox_resolved)):
            flag = "FLAG{path_traversal_file_read}"

        # Also award flag if they read the secret file
        if "secret.txt" in filename:
            flag = "FLAG{path_traversal_file_read}"

    except FileNotFoundError:
        error = f"File not found: {filename}"
    except PermissionError:
        error = f"Permission denied: {filename}"
    except Exception as e:
        error = f"Error reading file: {e}"

    return templates.TemplateResponse(
        "path_traversal.html",
        {
            "request": request,
            "filename": filename,
            "content": file_content,
            "error": error,
            "flag": flag,
        },
    )


@router.get("/list", response_class=HTMLResponse)
async def path_traversal_list(request: Request) -> HTMLResponse:
    """List available files in the sandbox directory."""
    sandbox = Path(settings.FILES_DIR)
    files = [f.name for f in sandbox.iterdir() if f.is_file()] if sandbox.exists() else []

    html_content = f"""
    <h3>Available Files</h3>
    <ul>
    {"".join(f'<li><a href="/files/read?filename={f}">{f}</a></li>' for f in files)}
    </ul>
    <p class="hint-box">Hint: Are there files outside this directory you could read?</p>
    """
    return HTMLResponse(html_content)
