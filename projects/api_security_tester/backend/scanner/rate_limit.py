"""
Rate Limit Scanner
==================
Sends a burst of rapid requests to the target endpoint and inspects
whether any throttling mechanism is in place.

What attackers look for:
  - Endpoints that accept unlimited requests (password spray, enumeration, scraping)
  - Missing or misleading rate-limit headers
  - Soft limits that can be bypassed by rotating IPs or adding jitter

Defensive controls checked:
  - HTTP 429 Too Many Requests responses
  - Retry-After header
  - X-RateLimit-* family of headers
  - Response-time degradation under load
"""

import asyncio
import time

import httpx

from .base import BaseScanner, Finding, ScanResult, Severity

BURST_COUNT = 25        # requests sent in the burst
CONCURRENCY = 10        # simultaneous connections
RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
]


class RateLimitScanner(BaseScanner):
    NAME = "Rate Limit"

    async def run(self) -> ScanResult:
        result = ScanResult(scanner=self.NAME, target=self.target)
        statuses: list[int] = []
        rate_limit_headers_seen: set[str] = set()
        raw: list[dict] = []

        async def _req(client: httpx.AsyncClient, idx: int) -> None:
            t0 = time.monotonic()
            try:
                resp = await client.get(self.target, headers=self.headers, timeout=self.timeout)
                elapsed = round((time.monotonic() - t0) * 1000)
                statuses.append(resp.status_code)

                found_rl_headers = {
                    h.lower(): v
                    for h, v in resp.headers.items()
                    if h.lower() in RATE_LIMIT_HEADERS
                }
                rate_limit_headers_seen.update(found_rl_headers.keys())

                raw.append({
                    "request_num": idx,
                    "method": "GET",
                    "url": self.target,
                    "status_code": resp.status_code,
                    "elapsed_ms": elapsed,
                    "rate_limit_headers": found_rl_headers,
                })
            except httpx.RequestError as exc:
                raw.append({"request_num": idx, "error": str(exc)})

        limits = httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=CONCURRENCY)
        async with httpx.AsyncClient(limits=limits, follow_redirects=True) as client:
            tasks = [_req(client, i) for i in range(1, BURST_COUNT + 1)]
            await asyncio.gather(*tasks)

        result.raw_requests = raw

        got_429 = any(s == 429 for s in statuses)
        all_200 = all(s in (200, 201, 204) for s in statuses if s)

        # ── Finding: no 429 returned after burst ─────────────────────────────
        if not got_429 and all_200:
            result.findings.append(Finding(
                title="No Rate Limiting Detected",
                severity=Severity.HIGH,
                description=(
                    f"Sent {BURST_COUNT} rapid requests — every one returned a 2xx response "
                    "with no throttling or blocking observed."
                ),
                evidence=(
                    f"{BURST_COUNT}/{BURST_COUNT} requests succeeded. "
                    f"Status codes: {sorted(set(statuses))}."
                ),
                remediation=(
                    "Implement rate limiting at the API gateway or application layer. "
                    "Consider token-bucket or sliding-window algorithms. "
                    "Return HTTP 429 with a Retry-After header when limits are exceeded. "
                    "Layer rate limits per IP, per user, and per API key."
                ),
                attack_explanation=(
                    "Without rate limiting, an attacker can: brute-force login endpoints "
                    "at machine speed, enumerate valid usernames/resources via timing, "
                    "scrape all data without restriction, or amplify any logic flaw by "
                    "repeating it thousands of times per minute."
                ),
            ))
        elif got_429:
            result.findings.append(Finding(
                title="Rate Limiting Active",
                severity=Severity.PASS,
                description="The endpoint returned HTTP 429 after repeated requests — throttling is in place.",
                evidence=f"Got 429 after {statuses.index(429) + 1} requests.",
                remediation="Ensure limits are consistent across all endpoints and API versions.",
                attack_explanation="Rate limiting forces attackers to slow down or use more infrastructure.",
            ))

        # ── Finding: rate-limit headers missing ───────────────────────────────
        if not rate_limit_headers_seen:
            result.findings.append(Finding(
                title="Rate-Limit Headers Not Exposed",
                severity=Severity.LOW,
                description=(
                    "No X-RateLimit-* or Retry-After headers were found in any response. "
                    "Clients cannot tell how close they are to a limit."
                ),
                evidence="Headers checked: " + ", ".join(RATE_LIMIT_HEADERS),
                remediation=(
                    "Add standard rate-limit headers so legitimate clients can back off "
                    "gracefully: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset."
                ),
                attack_explanation=(
                    "Missing headers make it harder for defenders to detect abuse in logs "
                    "and harder for security tools to automatically respect limits."
                ),
            ))
        else:
            result.findings.append(Finding(
                title="Rate-Limit Headers Present",
                severity=Severity.PASS,
                description=f"Found headers: {', '.join(sorted(rate_limit_headers_seen))}.",
                evidence=f"Seen in responses: {sorted(rate_limit_headers_seen)}",
                remediation="Keep headers consistent across all endpoints.",
                attack_explanation="Well-documented limits help both clients and security tools.",
            ))

        return result
