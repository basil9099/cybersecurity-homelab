"""
BREACH - Broken, Risky, and Exploitable Application for Cybersecurity Hacking
An intentionally vulnerable web application for security training.

WARNING: This application contains intentional security vulnerabilities.
         NEVER deploy this on a network accessible to the internet.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.config import settings
from app.database import init_db
from app.vulnerabilities.sqli import router as sqli_router
from app.vulnerabilities.xss import router as xss_router
from app.vulnerabilities.idor import router as idor_router
from app.vulnerabilities.auth_bypass import router as auth_router
from app.vulnerabilities.command_injection import router as cmd_router
from app.vulnerabilities.ssrf import router as ssrf_router, internal_router
from app.vulnerabilities.path_traversal import router as path_traversal_router
from app.vulnerabilities.xxe import router as xxe_router
from app.flags.flag_manager import flag_router
from app.hints.hint_system import router as hints_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the database with seed data on application startup."""
    init_db()
    yield


app = FastAPI(
    title="BREACH",
    description="Broken, Risky, and Exploitable Application for Cybersecurity Hacking",
    version="1.0.0",
    debug=settings.DEBUG,
    lifespan=lifespan,
)

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))

# Include vulnerability routers
app.include_router(sqli_router, prefix="/sqli", tags=["SQL Injection"])
app.include_router(xss_router, prefix="/xss", tags=["Cross-Site Scripting"])
app.include_router(idor_router, prefix="/idor", tags=["IDOR"])
app.include_router(auth_router, prefix="/auth", tags=["Broken Authentication"])
app.include_router(cmd_router, prefix="/cmd", tags=["Command Injection"])
app.include_router(ssrf_router, prefix="/ssrf", tags=["SSRF"])
app.include_router(internal_router, tags=["Internal Services"])
app.include_router(path_traversal_router, prefix="/files", tags=["Path Traversal"])
app.include_router(xxe_router, prefix="/xxe", tags=["XXE"])
app.include_router(flag_router, prefix="/flags", tags=["Flag Management"])
app.include_router(hints_router, prefix="/hints", tags=["Hint System"])


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Main page listing all available challenges."""
    challenges = [
        {
            "name": "SQL Injection",
            "category": "A03:2021 - Injection",
            "difficulty": "Easy",
            "difficulty_color": "#00ff41",
            "description": "Bypass authentication and extract data via SQL injection.",
            "endpoints": ["/sqli/login", "/sqli/search"],
            "link": "/sqli/login",
        },
        {
            "name": "Cross-Site Scripting (XSS)",
            "category": "A03:2021 - Injection",
            "difficulty": "Easy",
            "difficulty_color": "#00ff41",
            "description": "Inject scripts via reflected and stored XSS vectors.",
            "endpoints": ["/xss/search", "/xss/guestbook"],
            "link": "/xss/search?q=test",
        },
        {
            "name": "Insecure Direct Object Reference",
            "category": "A01:2021 - Broken Access Control",
            "difficulty": "Easy",
            "difficulty_color": "#00ff41",
            "description": "Access other users' profiles by manipulating object references.",
            "endpoints": ["/idor/profile/{id}"],
            "link": "/idor/profile/1",
        },
        {
            "name": "Broken Authentication",
            "category": "A07:2021 - Identification Failures",
            "difficulty": "Medium",
            "difficulty_color": "#ffaf00",
            "description": "Exploit weak JWT implementation and default credentials.",
            "endpoints": ["/auth/login", "/auth/profile"],
            "link": "/auth/login",
        },
        {
            "name": "OS Command Injection",
            "category": "A03:2021 - Injection",
            "difficulty": "Medium",
            "difficulty_color": "#ffaf00",
            "description": "Execute arbitrary OS commands through unsanitized input.",
            "endpoints": ["/cmd/ping"],
            "link": "/cmd/ping",
        },
        {
            "name": "Server-Side Request Forgery",
            "category": "A10:2021 - SSRF",
            "difficulty": "Medium",
            "difficulty_color": "#ffaf00",
            "description": "Force the server to make requests to internal resources.",
            "endpoints": ["/ssrf/fetch"],
            "link": "/ssrf/fetch",
        },
        {
            "name": "Path Traversal",
            "category": "A01:2021 - Broken Access Control",
            "difficulty": "Easy",
            "difficulty_color": "#00ff41",
            "description": "Read arbitrary files from the server using directory traversal.",
            "endpoints": ["/files/read?filename="],
            "link": "/files/read?filename=welcome.txt",
        },
        {
            "name": "XML External Entity (XXE)",
            "category": "A05:2021 - Security Misconfiguration",
            "difficulty": "Hard",
            "difficulty_color": "#ff0040",
            "description": "Exploit XML parsers to read files and perform SSRF.",
            "endpoints": ["/xxe/parse"],
            "link": "/xxe/parse",
        },
    ]
    return templates.TemplateResponse(
        "index.html", {"request": request, "challenges": challenges}
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
    )
