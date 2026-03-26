"""CTF Flag Manager - Tracks and validates flag captures."""

from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.database import get_db
from app.models import FlagSubmission

router = APIRouter()
flag_router = router
templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parent.parent / "templates")
)

# Master flag registry - maps challenge names to their flags
FLAG_REGISTRY: dict[str, str] = {
    "sqli_login": "FLAG{sql_injection_login_bypassed}",
    "sqli_search": "FLAG{sqli_search_extraction_complete}",
    "sqli_union": "FLAG{sql_injection_union_master}",
    "xss_reflected": "FLAG{xss_reflected_script_executed}",
    "xss_stored": "FLAG{xss_stored_in_guestbook}",
    "idor_access": "FLAG{idor_profile_access_granted}",
    "auth_bypass": "FLAG{auth_bypass_jwt_none_attack}",
    "cmd_injection": "FLAG{command_injection_rce_achieved}",
    "ssrf_internal": "FLAG{ssrf_internal_service_accessed}",
    "path_traversal": "FLAG{path_traversal_file_read}",
    "xxe_file_read": "FLAG{xxe_external_entity_expansion}",
}


def validate_flag(challenge: str, submitted_flag: str) -> bool:
    """Validate a submitted flag against the registry."""
    expected = FLAG_REGISTRY.get(challenge)
    if expected is None:
        return False
    return submitted_flag.strip() == expected


def capture_flag(challenge: str) -> bool:
    """Mark a flag as captured in the database."""
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE flags SET captured = 1, captured_at = ? WHERE challenge = ?",
            (datetime.now(timezone.utc).isoformat(), challenge),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def get_scoreboard() -> list[dict]:
    """Get the current scoreboard showing all flags and their capture status."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT challenge, captured, captured_at FROM flags ORDER BY id")
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()

    scoreboard = []
    for row in rows:
        scoreboard.append({
            "challenge": row["challenge"],
            "captured": bool(row["captured"]),
            "captured_at": row["captured_at"],
        })
    return scoreboard


@router.get("/scoreboard", response_class=HTMLResponse)
async def scoreboard_page(request: Request) -> HTMLResponse:
    """Display the CTF scoreboard."""
    scores = get_scoreboard()
    total = len(scores)
    captured = sum(1 for s in scores if s["captured"])

    return templates.TemplateResponse(
        "scoreboard.html",
        {
            "request": request,
            "scores": scores,
            "total": total,
            "captured": captured,
        },
    )


@router.post("/submit")
async def submit_flag(submission: FlagSubmission) -> JSONResponse:
    """Validate and record a flag submission."""
    if submission.challenge not in FLAG_REGISTRY:
        return JSONResponse(
            {"correct": False, "message": f"Unknown challenge: {submission.challenge}"},
            status_code=400,
        )

    if validate_flag(submission.challenge, submission.flag):
        capture_flag(submission.challenge)
        return JSONResponse({
            "correct": True,
            "message": f"Correct! Flag for '{submission.challenge}' captured!",
        })
    else:
        return JSONResponse({
            "correct": False,
            "message": "Incorrect flag. Keep trying!",
        })


@router.get("/challenges")
async def list_challenges() -> JSONResponse:
    """List all available challenges and their capture status."""
    scores = get_scoreboard()
    return JSONResponse({
        "challenges": [
            {
                "name": s["challenge"],
                "captured": s["captured"],
            }
            for s in scores
        ],
        "total": len(scores),
        "captured": sum(1 for s in scores if s["captured"]),
    })


@router.post("/reset")
async def reset_flags() -> JSONResponse:
    """Reset all captured flags."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE flags SET captured = 0, captured_at = NULL")
    conn.commit()
    conn.close()
    return JSONResponse({"message": "All flags have been reset."})
