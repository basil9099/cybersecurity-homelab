# BREACH - Broken, Risky, and Exploitable Application for Cybersecurity Hacking

An intentionally vulnerable web application designed as a Capture The Flag (CTF) training platform. Each challenge maps to a real-world vulnerability from the OWASP Top 10 (2021 edition).

## Ethical Disclaimer

**WARNING: This application contains intentional, exploitable security vulnerabilities.**

- **NEVER** deploy this application on a network accessible to the internet.
- **NEVER** run this on a production server or shared hosting environment.
- Use this **ONLY** in isolated lab environments (local machine, private VM, or air-gapped network).
- This tool is provided for **authorized educational and training purposes only**.
- Unauthorized use of the techniques demonstrated here against systems you do not own or have explicit permission to test is **illegal** and **unethical**.

By using this application, you agree that you are solely responsible for ensuring your activities comply with all applicable laws and regulations.

## Challenges

| Challenge | OWASP Category | Difficulty | Endpoints |
|-----------|---------------|------------|-----------|
| SQL Injection (Login Bypass) | A03:2021 - Injection | Easy | `/sqli/login` |
| SQL Injection (UNION Extract) | A03:2021 - Injection | Easy | `/sqli/search` |
| Cross-Site Scripting (Reflected) | A03:2021 - Injection | Easy | `/xss/search` |
| Cross-Site Scripting (Stored) | A03:2021 - Injection | Easy | `/xss/guestbook` |
| Insecure Direct Object Reference | A01:2021 - Broken Access Control | Easy | `/idor/profile/{id}` |
| Broken Authentication (JWT) | A07:2021 - Identification Failures | Medium | `/auth/login`, `/auth/profile` |
| OS Command Injection | A03:2021 - Injection | Medium | `/cmd/ping` |
| Server-Side Request Forgery | A10:2021 - SSRF | Medium | `/ssrf/fetch` |
| Path Traversal | A01:2021 - Broken Access Control | Easy | `/files/read?filename=` |
| XML External Entity (XXE) | A05:2021 - Security Misconfiguration | Hard | `/xxe/parse` |

## Flag Format

All flags follow the format: `FLAG{descriptive_string_here}`

There are 11 flags hidden across the challenges. Track your progress on the scoreboard at `/flags/scoreboard`.

## Setup Instructions

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Installation

```bash
# Navigate to the project directory
cd projects/offensive/vulnerable_web_app

# Create and activate a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

The application starts on `http://127.0.0.1:8080` by default.

### Alternative: Run with uvicorn directly

```bash
uvicorn main:app --host 127.0.0.1 --port 8080 --reload
```

### API Documentation

FastAPI auto-generates interactive API docs:
- Swagger UI: `http://127.0.0.1:8080/docs`
- ReDoc: `http://127.0.0.1:8080/redoc`

## Hint System

Each challenge has 3 progressive hints (vague to specific):

```bash
# Get a hint via API
curl http://127.0.0.1:8080/hints/hint/sqli_login?level=1

# Level 1: General direction
# Level 2: Technique identification
# Level 3: Near-complete walkthrough
```

## Project Structure

```
vulnerable_web_app/
├── main.py                          # FastAPI application entry point
├── requirements.txt                 # Python dependencies
├── README.md                        # This file
├── app/
│   ├── __init__.py
│   ├── config.py                    # Application configuration
│   ├── database.py                  # SQLite setup and seed data
│   ├── models.py                    # Pydantic request/response models
│   ├── templates/                   # Jinja2 HTML templates
│   │   ├── base.html                # Base template with dark theme
│   │   ├── index.html               # Challenge dashboard
│   │   ├── sqli_login.html
│   │   ├── sqli_search.html
│   │   ├── xss_search.html
│   │   ├── xss_guestbook.html
│   │   ├── idor_profile.html
│   │   ├── auth_login.html
│   │   ├── cmd_ping.html
│   │   ├── ssrf_fetch.html
│   │   ├── path_traversal.html
│   │   ├── xxe_parse.html
│   │   └── scoreboard.html
│   ├── vulnerabilities/             # Challenge route modules
│   │   ├── __init__.py
│   │   ├── sqli.py                  # SQL Injection
│   │   ├── xss.py                   # Cross-Site Scripting
│   │   ├── idor.py                  # Insecure Direct Object Reference
│   │   ├── auth_bypass.py           # Broken Authentication / JWT
│   │   ├── command_injection.py     # OS Command Injection
│   │   ├── ssrf.py                  # Server-Side Request Forgery
│   │   ├── path_traversal.py        # Path Traversal
│   │   └── xxe.py                   # XML External Entity
│   ├── flags/
│   │   ├── __init__.py
│   │   └── flag_manager.py          # CTF flag tracking and validation
│   └── hints/
│       ├── __init__.py
│       └── hint_system.py           # Progressive hint system
└── sandbox_files/                   # Files for path traversal challenge
    ├── welcome.txt
    ├── secret.txt
    └── notes.txt
```

## Technology Stack

- **FastAPI** - Modern Python web framework
- **Jinja2** - HTML templating
- **SQLite** - Embedded database
- **python-jose** - JWT token handling
- **lxml** - XML parsing (for XXE)
- **httpx** - Async HTTP client (for SSRF)

## Resetting the Environment

To reset all progress:

```bash
# Reset captured flags
curl -X POST http://127.0.0.1:8080/flags/reset

# Full reset: delete the database (it will be recreated on next startup)
rm breach.db
```
