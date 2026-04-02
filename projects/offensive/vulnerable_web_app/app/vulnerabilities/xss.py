"""Cross-Site Scripting vulnerabilities - OWASP A03:2021 Injection.

Challenges:
  - Reflected XSS in search parameter
  - Stored XSS in guestbook/comments
"""

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.database import get_db

router = APIRouter()
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates")
)


@router.get("/search", response_class=HTMLResponse)
async def xss_search(request: Request, q: str = "") -> HTMLResponse:
    """VULNERABLE: Reflected XSS via unsanitized search parameter.

    The query parameter is reflected directly into the HTML response
    without escaping, allowing injection of arbitrary scripts:
        /xss/search?q=<script>alert('XSS')</script>
    """
    # VULN: User input reflected without sanitization
    flag_found = "<script>" in q.lower() or "onerror" in q.lower()
    flag = "FLAG{xss_reflected_script_executed}" if flag_found else None

    return templates.TemplateResponse(
        "xss_search.html",
        {"request": request, "query": q, "flag": flag},
    )


@router.get("/guestbook", response_class=HTMLResponse)
async def xss_guestbook_page(request: Request) -> HTMLResponse:
    """Render the guestbook page with all stored entries."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM messages ORDER BY created_at DESC")
        messages = [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

    return templates.TemplateResponse(
        "xss_guestbook.html",
        {"request": request, "messages": messages, "result": None},
    )


@router.post("/guestbook", response_class=HTMLResponse)
async def xss_guestbook_post(
    request: Request,
    author: str = Form(...),
    content: str = Form(...),
) -> HTMLResponse:
    """VULNERABLE: Stored XSS via guestbook entries.

    User input is stored directly in the database and rendered without
    escaping, allowing persistent script injection:
        author: hacker
        content: <script>alert(document.cookie)</script>
    """
    conn = get_db()
    try:
        cursor = conn.cursor()

        # VULN: Storing user input without sanitization
        cursor.execute(
            "INSERT INTO messages (author, content) VALUES (?, ?)",
            (author, content),
        )
        conn.commit()

        # Check if XSS payload was submitted
        flag_found = "<script>" in content.lower() or "onerror" in content.lower()
        result = None
        if flag_found:
            result = {
                "success": True,
                "message": "XSS payload stored! FLAG{xss_stored_in_guestbook}",
            }

        cursor.execute("SELECT * FROM messages ORDER BY created_at DESC")
        messages = [dict(row) for row in cursor.fetchall()]
    finally:
        conn.close()

    return templates.TemplateResponse(
        "xss_guestbook.html",
        {"request": request, "messages": messages, "result": result},
    )
