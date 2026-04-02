"""Insecure Direct Object Reference - OWASP A01:2021 Broken Access Control.

Challenges:
  - Access any user profile by changing the sequential ID
  - No authorization checks on profile access
"""

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.database import get_db

router = APIRouter()
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates")
)


@router.get("/profile/{user_id}", response_class=HTMLResponse)
async def idor_profile(request: Request, user_id: int) -> HTMLResponse:
    """VULNERABLE: Access any user's profile without authorization.

    Sequential integer IDs and no session/auth checks allow enumeration
    of all user profiles:
        /idor/profile/1  -> admin profile
        /idor/profile/4  -> jane's profile with flag
    """
    conn = get_db()
    try:
        cursor = conn.cursor()

        # VULN: No authorization check - any user can view any profile
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
    finally:
        conn.close()

    if user:
        profile = {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "secret_note": user["secret_note"],
        }
    else:
        profile = None

    return templates.TemplateResponse(
        "idor_profile.html",
        {"request": request, "profile": profile, "user_id": user_id},
    )


@router.get("/profiles", response_class=JSONResponse)
async def idor_list_profiles() -> JSONResponse:
    """VULNERABLE: Endpoint leaks user count for enumeration."""
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total FROM users")
        count = cursor.fetchone()["total"]
    finally:
        conn.close()

    return JSONResponse({
        "total_users": count,
        "message": "Use /idor/profile/{id} to view profiles.",
        "hint": "Try IDs from 1 to the total count.",
    })
