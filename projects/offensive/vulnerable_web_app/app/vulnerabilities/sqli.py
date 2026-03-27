"""SQL Injection vulnerabilities - OWASP A03:2021 Injection.

Challenges:
  - Login bypass via SQLi
  - UNION-based data extraction
  - Search with injectable parameter
"""

import sqlite3

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.config import settings
from app.database import get_db

router = APIRouter()
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates")
)


@router.get("/login", response_class=HTMLResponse)
async def sqli_login_page(request: Request) -> HTMLResponse:
    """Render the SQL injection login page."""
    return templates.TemplateResponse(
        "sqli_login.html", {"request": request, "result": None}
    )


@router.post("/login")
async def sqli_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> HTMLResponse:
    """VULNERABLE: Login endpoint susceptible to SQL injection.

    The username and password are interpolated directly into the SQL query
    without parameterization, allowing classic bypass payloads like:
        username: admin' OR '1'='1' --
        password: anything
    """
    conn = get_db()
    cursor = conn.cursor()

    # VULN: String concatenation in SQL query - classic SQL injection
    query = (
        f"SELECT * FROM users WHERE username = '{username}' "
        f"AND password = '{password}'"
    )

    try:
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            result = {
                "success": True,
                "message": f"Welcome back, {user['username']}!",
                "role": user["role"],
                "secret_note": user["secret_note"],
                "flag": "FLAG{sql_injection_login_bypassed}"
                if user["role"] == "admin"
                else None,
            }
        else:
            result = {
                "success": False,
                "message": "Invalid username or password.",
            }
    except sqlite3.OperationalError as e:
        conn.close()
        # VULN: Detailed error messages leak information
        result = {
            "success": False,
            "message": f"SQL Error: {e}",
        }

    return templates.TemplateResponse(
        "sqli_login.html", {"request": request, "result": result}
    )


@router.get("/search", response_class=HTMLResponse)
async def sqli_search(request: Request, q: str = "") -> HTMLResponse:
    """VULNERABLE: Search endpoint with SQL injection in query parameter.

    Supports UNION-based injection to extract data from other tables:
        /sqli/search?q=' UNION SELECT 1,username,password,4,5,6 FROM users--
    """
    conn = get_db()
    cursor = conn.cursor()

    results = []
    error = None

    if q:
        # VULN: Direct string interpolation in SQL query
        query = f"SELECT * FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
        try:
            cursor.execute(query)
            results = [dict(row) for row in cursor.fetchall()]
        except sqlite3.OperationalError as e:
            # VULN: Verbose error output aids attacker
            error = f"SQL Error: {e}"

    conn.close()

    return templates.TemplateResponse(
        "sqli_search.html",
        {"request": request, "query": q, "results": results, "error": error},
    )
