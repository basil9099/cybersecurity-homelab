"""Broken Authentication - OWASP A07:2021 Identification and Authentication Failures.

Challenges:
  - JWT algorithm none attack
  - Default/weak credentials
  - No rate limiting on login
"""

import json
import base64
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request, Form, Header
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from jose import jwt
from pathlib import Path

from app.config import settings
from app.database import get_db

router = APIRouter()
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates")
)


def create_jwt_token(payload: dict) -> str:
    """Create a JWT token with the configured secret."""
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=1)
    payload["iat"] = datetime.now(timezone.utc)
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_jwt_token(token: str) -> dict | None:
    """VULNERABLE: Decode JWT allowing algorithm none attack.

    This implementation checks the token header and if alg is 'none',
    it decodes without verification - a classic JWT vulnerability.
    """
    try:
        # VULN: Check if alg:none is used - accept it without verification
        parts = token.split(".")
        if len(parts) >= 2:
            # Decode header to check algorithm
            header_padded = parts[0] + "=" * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))

            if header.get("alg", "").lower() == "none":
                # VULN: Accept tokens with alg:none without signature verification
                payload_padded = parts[1] + "=" * (-len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_padded))
                return payload

        # Normal JWT verification
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except Exception:
        return None


@router.get("/login", response_class=HTMLResponse)
async def auth_login_page(request: Request) -> HTMLResponse:
    """Render the authentication login page."""
    return templates.TemplateResponse(
        "auth_login.html", {"request": request, "result": None}
    )


@router.post("/login")
async def auth_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> HTMLResponse:
    """VULNERABLE: Login with no rate limiting, weak credentials accepted.

    Default credentials:
      - admin / admin123
      - guest / guest
      - test / test
    """
    conn = get_db()
    try:
        cursor = conn.cursor()

        # VULN: No rate limiting, no account lockout
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password),
        )
        user = cursor.fetchone()
    finally:
        conn.close()

    if user:
        token = create_jwt_token({
            "sub": user["username"],
            "role": user["role"],
            "user_id": user["id"],
        })
        result = {
            "success": True,
            "message": f"Authenticated as {user['username']}.",
            "token": token,
            "hint": "Try manipulating the JWT token. What if the algorithm was 'none'?",
        }
    else:
        result = {
            "success": False,
            "message": "Invalid credentials.",
        }

    return templates.TemplateResponse(
        "auth_login.html", {"request": request, "result": result}
    )


@router.get("/profile")
async def auth_profile(
    request: Request,
    authorization: str = Header(default=""),
) -> JSONResponse:
    """VULNERABLE: Profile endpoint that accepts alg:none JWT tokens.

    Send a crafted JWT with alg:none and role:admin to access the flag:
        Header: {"alg": "none", "typ": "JWT"}
        Payload: {"sub": "admin", "role": "admin"}
        Token: base64(header).base64(payload).

    Usage: GET /auth/profile -H "Authorization: Bearer <token>"
    """
    token = authorization.replace("Bearer ", "").strip()

    if not token:
        return JSONResponse(
            {"error": "Authorization header with Bearer token required."},
            status_code=401,
        )

    payload = decode_jwt_token(token)
    if not payload:
        return JSONResponse(
            {"error": "Invalid or expired token."},
            status_code=401,
        )

    response = {
        "username": payload.get("sub"),
        "role": payload.get("role"),
    }

    # If the user forged a token with admin role via alg:none
    if payload.get("role") == "admin":
        response["flag"] = "FLAG{auth_bypass_jwt_none_attack}"
        response["secret"] = "Admin panel credentials: root:toor"

    return JSONResponse(response)
