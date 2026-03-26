"""OS Command Injection - OWASP A03:2021 Injection.

Challenges:
  - Inject OS commands through ping target parameter
  - Chain commands using ;, |, &&, or $() syntax
"""

import subprocess

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

router = APIRouter()
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates")
)


@router.get("/ping", response_class=HTMLResponse)
async def cmd_ping_page(request: Request) -> HTMLResponse:
    """Render the ping utility page."""
    return templates.TemplateResponse(
        "cmd_ping.html", {"request": request, "output": None, "target": ""}
    )


@router.post("/ping", response_class=HTMLResponse)
async def cmd_ping(
    request: Request,
    target: str = Form(...),
) -> HTMLResponse:
    """VULNERABLE: OS command injection via unsanitized input to subprocess.

    User input is passed directly to the shell, allowing command chaining:
        127.0.0.1; cat /etc/passwd
        127.0.0.1 && whoami
        $(whoami)
        127.0.0.1 | id
    """
    # VULN: Unsanitized user input passed directly to shell
    command = f"ping -c 2 -W 2 {target}"

    try:
        # VULN: shell=True allows command injection
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr

        # Check if user injected additional commands
        injection_indicators = [";", "&&", "||", "|", "$(", "`"]
        flag = None
        if any(ind in target for ind in injection_indicators):
            flag = "FLAG{command_injection_rce_achieved}"

    except subprocess.TimeoutExpired:
        output = "Command timed out."
        flag = None
    except Exception as e:
        output = f"Error: {e}"
        flag = None

    return templates.TemplateResponse(
        "cmd_ping.html",
        {"request": request, "output": output, "target": target, "flag": flag},
    )
