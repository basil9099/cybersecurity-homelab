"""Progressive hint system - 3 hints per challenge, increasingly specific."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.models import HintRequest

router = APIRouter()

# Three progressive hints per challenge: vague -> moderate -> specific
HINTS: dict[str, list[str]] = {
    "sqli_login": [
        "Think about how the application constructs its SQL query with your input.",
        "Try inserting a single quote (') in the username field and observe the error.",
        "Use the payload: admin' OR '1'='1' --  with any password to bypass login.",
    ],
    "sqli_search": [
        "The search parameter is embedded directly in a SQL query.",
        "Try a UNION SELECT to combine results from another table. How many columns does the products table have?",
        "Payload: ' UNION SELECT 1,username,password,4,5,6 FROM users--",
    ],
    "sqli_union": [
        "UNION injection requires matching the number of columns in the original query.",
        "First determine column count: ' ORDER BY 6-- (works) vs ' ORDER BY 7-- (fails).",
        "Extract secrets: ' UNION SELECT 1,username,secret_note,email,role,password FROM users--",
    ],
    "xss_reflected": [
        "The search parameter is reflected in the page without sanitization.",
        "Try injecting an HTML tag in the search query parameter.",
        "Payload: <script>alert('XSS')</script> in the search box or URL parameter.",
    ],
    "xss_stored": [
        "Guestbook entries are stored and displayed to all visitors.",
        "The content field is rendered as raw HTML without escaping.",
        "Post a guestbook entry with content: <script>alert(document.cookie)</script>",
    ],
    "idor_access": [
        "User profiles are accessed with sequential integer IDs.",
        "There is no authorization check - try accessing other user IDs.",
        "Visit /idor/profile/4 to find jane's profile containing the flag.",
    ],
    "auth_bypass": [
        "The JWT implementation has a well-known vulnerability related to algorithms.",
        "Research the JWT 'alg:none' attack. Craft a token without a signature.",
        (
            "Create a JWT with header {\"alg\":\"none\",\"typ\":\"JWT\"} and payload "
            "{\"sub\":\"admin\",\"role\":\"admin\"}, base64url-encode both, join with "
            "dots (add trailing dot), send as Bearer token to /auth/profile."
        ),
    ],
    "cmd_injection": [
        "The ping target is passed directly to the operating system shell.",
        "Shell metacharacters like ;, |, &&, and $() can chain commands.",
        "Payload: 127.0.0.1; cat /etc/passwd  or  127.0.0.1 && whoami",
    ],
    "ssrf_internal": [
        "The URL fetcher makes server-side requests without validation.",
        "Try making the server request internal addresses (127.0.0.1, localhost).",
        "Fetch: http://127.0.0.1:8080/internal/secret to access the internal API.",
    ],
    "path_traversal": [
        "The filename parameter is joined to a base path without sanitization.",
        "Use ../ sequences to traverse out of the sandbox directory.",
        "Payload: /files/read?filename=secret.txt or /files/read?filename=../../../etc/passwd",
    ],
    "xxe_file_read": [
        "The XML parser processes external entity declarations.",
        "Define a DOCTYPE with an ENTITY that references a local file.",
        (
            'Payload: <?xml version="1.0"?><!DOCTYPE foo '
            '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<user><name>&xxe;</name></user>"
        ),
    ],
}


def get_hint(challenge: str, level: int) -> dict:
    """Get a hint for a challenge at the specified level (1-3).

    Level 1: Vague nudge in the right direction
    Level 2: Moderate hint about the technique
    Level 3: Near-complete solution walkthrough
    """
    if challenge not in HINTS:
        return {"error": f"Unknown challenge: {challenge}"}

    hints = HINTS[challenge]
    level = max(1, min(level, len(hints)))

    return {
        "challenge": challenge,
        "level": level,
        "max_level": len(hints),
        "hint": hints[level - 1],
    }


@router.post("/hint")
async def request_hint(hint_req: HintRequest) -> JSONResponse:
    """Get a progressive hint for a challenge."""
    result = get_hint(hint_req.challenge, hint_req.level)
    if "error" in result:
        return JSONResponse(result, status_code=404)
    return JSONResponse(result)


@router.get("/hint/{challenge}")
async def get_hints_for_challenge(challenge: str, level: int = 1) -> JSONResponse:
    """Get a hint for a specific challenge via GET request."""
    result = get_hint(challenge, level)
    if "error" in result:
        return JSONResponse(result, status_code=404)
    return JSONResponse(result)


@router.get("/challenges")
async def list_hint_challenges() -> JSONResponse:
    """List all challenges that have hints available."""
    return JSONResponse({
        "challenges": [
            {"name": name, "hints_available": len(hints)}
            for name, hints in HINTS.items()
        ]
    })
