"""
SQL Injection Scanner
=====================
Injects common SQLi payloads into URL query parameters and inspects
responses for error messages, status-code changes, and body-size
anomalies that indicate the backend is vulnerable.

Categories tested:
  - Classic error-based (single/double quote)
  - Boolean-based blind (OR 1=1 vs OR 1=2)
  - Time-based blind (SLEEP / pg_sleep / waitfor delay)
  - UNION-based (NULL columns)
  - Stacked queries

The scanner does NOT modify the database — it only reads responses.
Time-based probes use a 5-second sleep threshold so they don't
accidentally match slow networks.
"""

import asyncio
import time
import urllib.parse

import httpx

from .base import BaseScanner, Finding, ScanResult, Severity

# Error strings emitted by common databases — presence in response = confirmed injection point
DB_ERROR_PATTERNS = [
    # MySQL / MariaDB
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "supplied argument is not a valid mysql",
    # PostgreSQL
    "pg_query()",
    "pg_exec()",
    "postgresql error",
    "unterminated quoted string",
    "syntax error at or near",
    # MSSQL
    "unclosed quotation mark",
    "incorrect syntax near",
    "odbc sql server driver",
    "microsoft ole db provider for sql server",
    # Oracle
    "ora-01756",
    "ora-00907",
    "oracle error",
    # SQLite
    "sqlite_master",
    "no such table",
    "sqlite3.operationalerror",
    # Generic
    "syntax error",
    "sql syntax",
    "database error",
    "db error",
    "unrecognized token",
]

PAYLOADS = [
    # ── Classic / Error-based ───────────────────────────────────────────────
    {"payload": "'", "category": "error-based", "note": "Single quote — breaks SQL string context"},
    {"payload": '"', "category": "error-based", "note": "Double quote — breaks SQL string context"},
    {"payload": "';--", "category": "error-based", "note": "Quote + comment — terminates query"},
    {"payload": "' OR '1'='1", "category": "boolean", "note": "Classic OR 1=1 tautology"},
    {"payload": "' OR '1'='2", "category": "boolean", "note": "False condition — response should differ from 1=1"},
    {"payload": '" OR "1"="1', "category": "boolean", "note": "Double-quote variant of OR 1=1"},
    # ── UNION-based ─────────────────────────────────────────────────────────
    {"payload": "' UNION SELECT NULL--", "category": "union", "note": "1-column UNION probe"},
    {"payload": "' UNION SELECT NULL,NULL--", "category": "union", "note": "2-column UNION probe"},
    {"payload": "' UNION SELECT NULL,NULL,NULL--", "category": "union", "note": "3-column UNION probe"},
    # ── Stacked queries ─────────────────────────────────────────────────────
    {"payload": "'; SELECT 1--", "category": "stacked", "note": "Stacked query probe (PostgreSQL / MSSQL)"},
    # ── Time-based blind ────────────────────────────────────────────────────
    {"payload": "' AND SLEEP(5)--", "category": "time-based", "note": "MySQL SLEEP(5) — measures response delay"},
    {"payload": "'; SELECT pg_sleep(5)--", "category": "time-based", "note": "PostgreSQL pg_sleep"},
    {"payload": "'; WAITFOR DELAY '0:0:5'--", "category": "time-based", "note": "MSSQL WAITFOR DELAY"},
]

TIME_SLEEP_THRESHOLD = 4.5   # seconds — flag if response takes this long


def _has_db_error(body: str) -> tuple[bool, str]:
    lower = body.lower()
    for pattern in DB_ERROR_PATTERNS:
        if pattern in lower:
            return True, pattern
    return False, ""


def _inject_params(url: str, payload: str) -> list[str]:
    """Return URLs with each query parameter replaced by the payload."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if not params:
        # No query params — append a generic one to test
        new_query = urllib.parse.urlencode({"id": payload})
        injected = parsed._replace(query=new_query)
        return [urllib.parse.urlunparse(injected)]

    results = []
    for key in params:
        new_params = dict(params)
        new_params[key] = [payload]
        new_query = urllib.parse.urlencode(new_params, doseq=True)
        injected = parsed._replace(query=new_query)
        results.append(urllib.parse.urlunparse(injected))
    return results


class SQLInjectionScanner(BaseScanner):
    NAME = "SQL Injection"

    async def run(self) -> ScanResult:
        result = ScanResult(scanner=self.NAME, target=self.target)
        confirmed_params: set[str] = set()

        async with httpx.AsyncClient(follow_redirects=True) as client:
            # Baseline
            try:
                base_resp = await client.get(self.target, headers=self.headers, timeout=self.timeout)
                baseline_status = base_resp.status_code
                baseline_len = len(base_resp.content)
                baseline_body = base_resp.text
            except httpx.RequestError as exc:
                result.error = f"Baseline request failed: {exc}"
                return result

            result.raw_requests.append({
                "probe": "Baseline",
                "url": self.target,
                "status_code": baseline_status,
                "body_length": baseline_len,
            })

            for probe in PAYLOADS:
                payload = probe["payload"]
                injected_urls = _inject_params(self.target, payload)

                for inj_url in injected_urls:
                    t0 = time.monotonic()
                    try:
                        resp = await client.get(inj_url, headers=self.headers, timeout=self.timeout + 7)
                        elapsed = time.monotonic() - t0
                        status = resp.status_code
                        body = resp.text
                        body_len = len(resp.content)
                    except httpx.RequestError as exc:
                        result.raw_requests.append({"probe": probe["note"], "url": inj_url, "error": str(exc)})
                        continue

                    result.raw_requests.append({
                        "probe": probe["note"],
                        "category": probe["category"],
                        "url": inj_url,
                        "payload": payload,
                        "status_code": status,
                        "body_length": body_len,
                        "elapsed_s": round(elapsed, 2),
                    })

                    has_error, matched_pattern = _has_db_error(body)

                    # ── Error-based confirmation ──────────────────────────
                    if has_error and inj_url not in confirmed_params:
                        confirmed_params.add(inj_url)
                        result.findings.append(Finding(
                            title=f"SQL Injection — Error-Based ({probe['category']})",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Database error message detected in response to payload: {payload!r}. "
                                f"Matched pattern: '{matched_pattern}'."
                            ),
                            evidence=(
                                f"URL: {inj_url}\n"
                                f"Payload: {payload!r}\n"
                                f"Status: {status} | Body length: {body_len} bytes\n"
                                f"DB error pattern matched: '{matched_pattern}'"
                            ),
                            remediation=(
                                "Use parameterised queries or prepared statements. "
                                "Never concatenate user input into SQL strings. "
                                "Suppress verbose database errors in production responses. "
                                "Apply an ORM with proper escaping."
                            ),
                            attack_explanation=(
                                "Error-based SQLi is the easiest to exploit: the database "
                                "error message itself reveals the query structure. Attackers "
                                "can extract table names, column names, and data directly "
                                "from error output."
                            ),
                        ))

                    # ── Time-based blind ─────────────────────────────────
                    if probe["category"] == "time-based" and elapsed >= TIME_SLEEP_THRESHOLD:
                        result.findings.append(Finding(
                            title=f"SQL Injection — Time-Based Blind",
                            severity=Severity.CRITICAL,
                            description=(
                                f"Response took {elapsed:.1f}s after injecting a sleep payload, "
                                "strongly suggesting the database executed the delay function."
                            ),
                            evidence=(
                                f"URL: {inj_url}\n"
                                f"Payload: {payload!r}\n"
                                f"Response time: {elapsed:.2f}s (threshold: {TIME_SLEEP_THRESHOLD}s)"
                            ),
                            remediation=(
                                "Use parameterised queries. "
                                "Restrict database user privileges to prevent function execution. "
                                "Set aggressive query timeouts on the database."
                            ),
                            attack_explanation=(
                                "Time-based blind SQLi exploits the absence of visible output. "
                                "Attackers use conditional delays (IF condition THEN SLEEP) to "
                                "exfiltrate data one bit at a time by measuring response times."
                            ),
                        ))

                    # ── Boolean anomaly ──────────────────────────────────
                    if probe["category"] == "boolean":
                        body_diff = abs(body_len - baseline_len)
                        if body_diff > 200 and status == baseline_status:
                            result.findings.append(Finding(
                                title="Possible Boolean-Based Blind SQL Injection",
                                severity=Severity.HIGH,
                                description=(
                                    f"Body size changed by {body_diff} bytes with a boolean "
                                    f"payload ({payload!r}) while status code stayed the same. "
                                    "This may indicate the query result is affecting the response."
                                ),
                                evidence=(
                                    f"Baseline body: {baseline_len} bytes. "
                                    f"Injected body: {body_len} bytes. "
                                    f"Diff: {body_diff} bytes."
                                ),
                                remediation=(
                                    "Use parameterised queries. "
                                    "Ensure error responses do not leak row counts or data shape."
                                ),
                                attack_explanation=(
                                    "Boolean-blind SQLi injects conditions (OR 1=1 vs OR 1=2) "
                                    "and compares response sizes or content to infer whether "
                                    "the condition was true. Data can be extracted character by character."
                                ),
                            ))

        if not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in result.findings):
            result.findings.append(Finding(
                title="No SQL Injection Detected",
                severity=Severity.PASS,
                description=(
                    "None of the tested payloads triggered database errors, significant body "
                    "size changes, or unusual response delays."
                ),
                evidence=f"Tested {len(PAYLOADS)} payloads across query parameters.",
                remediation="Continue using parameterised queries and input validation.",
                attack_explanation=(
                    "Parameterised queries ensure user input is always treated as data, "
                    "never as executable SQL — the most effective SQLi defence."
                ),
            ))

        return result
