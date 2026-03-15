# API Security Tester

> A full-stack web application that probes API endpoints for common security vulnerabilities — built to teach both offensive and defensive API security.

---

## What It Tests

| Scanner | What It Looks For | OWASP API Top 10 |
|---|---|---|
| **Rate Limiting** | Missing HTTP 429 throttling, absent `X-RateLimit-*` headers | API4 — Unrestricted Resource Consumption |
| **Auth Bypass** | Empty/null tokens, `alg:none` JWTs, IP-spoof headers, path overrides | API2 — Broken Authentication |
| **SQL Injection** | Error-based, boolean-blind, time-based, UNION payloads in URL params | API8 — Security Misconfiguration |
| **Authorization Flaws** | IDOR/BOLA via ID probing, verb tampering, admin path discovery, role headers | API1 — BOLA, API5 — BFLA |

---

## Architecture

```
api_security_tester/
├── backend/
│   ├── main.py                  # FastAPI app — scan lifecycle, SSE streaming
│   ├── requirements.txt
│   └── scanner/
│       ├── __init__.py
│       ├── base.py              # BaseScanner, Finding, ScanResult models
│       ├── rate_limit.py        # Burst 25 requests, check 429 + headers
│       ├── auth_bypass.py       # 9 bypass techniques per request
│       ├── sql_injection.py     # 13 SQLi payloads, 3 detection methods
│       └── authz_flaws.py       # IDOR, verb tampering, admin paths, role headers
└── frontend/
    ├── index.html
    ├── package.json
    ├── vite.config.js           # Proxies /scan → localhost:8000
    └── src/
        ├── main.jsx
        ├── App.jsx              # Root layout, SSE client, state
        ├── index.css
        └── components/
            ├── ScanForm.jsx     # URL input, header entry, module picker
            ├── ResultsPanel.jsx # Tabbed results, summary bar, raw requests
            └── VulnerabilityCard.jsx  # Finding display with attack/fix detail
```

**Data flow:**

```
Browser → POST /scan → FastAPI creates job + asyncio.Task
                     → GET /scan/{id}/stream (SSE)
                         ← module_start event
                         ← module_done event (with findings)
                         ← done event
```

All four scanners run **concurrently** via `asyncio.gather`.
Results stream to the UI module-by-module as they complete.

---

## Quick Start

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

API docs available at `http://localhost:8000/docs`.

### Frontend

```bash
cd frontend
npm install
npm run dev        # → http://localhost:3000
```

Vite proxies `/scan` requests to `localhost:8000` so no CORS issues during development.

---

## Usage

1. Open `http://localhost:3000`
2. Enter the target API URL — e.g. `http://localhost:8000/health` (the backend itself) or any lab API
3. Optionally add authentication headers (`Authorization: Bearer <token>`)
4. Select which scanner modules to run
5. Click **Start Scan** — results stream in as each module finishes

Each finding shows:
- **Severity** — Critical / High / Medium / Low / Pass
- **What was found** — plain-English description
- **Evidence** — exact URLs, payloads, and response codes used
- **How attackers exploit this** — the attacker's perspective
- **How to fix it** — concrete remediation steps
- **Raw Requests** — every HTTP exchange, expandable for deep inspection

---

## Scanner Details

### Rate Limit Scanner
Sends 25 concurrent GET requests and inspects:
- Whether any response is HTTP 429 (Too Many Requests)
- Whether any `X-RateLimit-*` or `Retry-After` header is present

**Why it matters:** Without rate limiting, login endpoints can be brute-forced, user data can be scraped, and any logic flaw can be replayed at machine speed.

### Auth Bypass Scanner
Sends 9 probe variants against the baseline request:

| Probe | Technique |
|---|---|
| No Authorization header | Stripped creds |
| Empty bearer | `Authorization: Bearer ` |
| Bearer "null" / "undefined" | JS serialisation bugs |
| `alg:none` JWT | CVE-2015-9235 unsigned token |
| `X-Forwarded-For: 127.0.0.1` | IP allowlist bypass |
| `X-Real-IP: 127.0.0.1` | nginx IP header spoof |
| `X-Original-URL: /admin` | Reverse-proxy path override |
| `X-HTTP-Method-Override: GET` | HTTP method confusion |

A bypass is flagged when a probe returns 2xx where the baseline returned 401/403, or when the response body changes significantly.

### SQL Injection Scanner
Injects 13 payloads into every URL query parameter:

| Category | Example |
|---|---|
| Error-based | `'`, `"`, `';--` |
| Boolean-blind | `' OR '1'='1`, `' OR '1'='2` |
| UNION | `' UNION SELECT NULL,NULL--` |
| Stacked queries | `'; SELECT 1--` |
| Time-based | `' AND SLEEP(5)--`, `pg_sleep(5)`, `WAITFOR DELAY` |

Detection methods: DB error strings in response body, ≥4.5s delay for time-based payloads, and significant body-size difference for boolean-blind.

### Authorization Flaw Scanner
Four sub-checks:

1. **IDOR** — if the URL contains `/resource/123`, probes IDs 1, 2, 122, 124, 223
2. **HTTP Verb Tampering** — tries DELETE, PUT, PATCH against the same path
3. **Admin Path Discovery** — 20 common paths: `/admin`, `/actuator/env`, `/graphql`, etc.
4. **Role-Escalation Headers** — 7 headers: `X-Role: admin`, `X-Admin: true`, etc.

---

## Legal Notice

> **Only use this tool against APIs you own or have explicit written permission to test.**
> Unauthorised scanning may violate the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), GDPR, or equivalent laws in your jurisdiction.
> This tool is provided for educational and authorised penetration testing purposes only.

---

## Learning Resources

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [PortSwigger Web Security Academy — API Testing](https://portswigger.net/web-security/api-testing)
- [HackTricks — API Pentesting](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/api-pentesting)
- [JWT Attack Playbook](https://github.com/ticarpi/jwt_tool/wiki)
