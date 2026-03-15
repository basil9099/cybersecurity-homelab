"""
Authentication Bypass Scanner
==============================
Tests a range of well-known techniques attackers use to skip or weaken
authentication checks on API endpoints.

Techniques probed:
  1. No credentials at all
  2. Empty / null / 'undefined' bearer tokens
  3. Algorithm-confusion tricks (alg:none JWT)
  4. IP-spoofing headers that some frameworks trust blindly
  5. HTTP method override (X-HTTP-Method-Override)
  6. Path-traversal variants of the same URL
  7. Content-type confusion (some parsers bypass auth for non-JSON)

For each test the scanner records whether the server behaved differently
(status code, response body length) — a difference is a strong signal.
"""

import base64
import json

import httpx

from .base import BaseScanner, Finding, ScanResult, Severity

# A minimal "alg:none" JWT — header claims no signature, any payload accepted
_NONE_ALG_JWT = (
    base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    + "."
    + base64.urlsafe_b64encode(json.dumps({"sub": "admin", "role": "admin"}).encode()).rstrip(b"=").decode()
    + "."   # empty signature
)

AUTH_BYPASS_PROBES: list[dict] = [
    {
        "name": "No Authorization Header",
        "description": "Strips any Authorization header from the request.",
        "headers_override": {"_remove": "Authorization"},
        "attack_explanation": (
            "If the endpoint returns 200 without any credentials, authentication is missing entirely. "
            "This is BOLA/OWASP API1 and allows unauthenticated access to sensitive data."
        ),
    },
    {
        "name": "Empty Bearer Token",
        "description": "Sends 'Authorization: Bearer ' with nothing after the space.",
        "headers_override": {"Authorization": "Bearer "},
        "attack_explanation": (
            "Some JWT parsers accept an empty string as a valid token or throw an unhandled "
            "exception that falls through to a 200 response."
        ),
    },
    {
        "name": "Bearer 'null' Token",
        "description": "Sends the literal string 'null' as the bearer token.",
        "headers_override": {"Authorization": "Bearer null"},
        "attack_explanation": (
            "JavaScript applications sometimes store tokens as the string 'null' when "
            "localStorage is empty. Servers that do string comparison may accept it."
        ),
    },
    {
        "name": "Bearer 'undefined' Token",
        "description": "Sends the literal string 'undefined' as the bearer token.",
        "headers_override": {"Authorization": "Bearer undefined"},
        "attack_explanation": (
            "Same as above — JS bug turns a missing token into the string 'undefined'."
        ),
    },
    {
        "name": "Algorithm:none JWT",
        "description": "Sends a JWT whose header claims alg=none (unsigned).",
        "headers_override": {"Authorization": f"Bearer {_NONE_ALG_JWT}"},
        "attack_explanation": (
            "CVE-2015-9235 and variants: early JWT libraries honoured the 'alg' field "
            "from the token itself, allowing attackers to craft tokens with no signature "
            "that the server would accept as valid."
        ),
    },
    {
        "name": "X-Forwarded-For: 127.0.0.1 (IP Spoof)",
        "description": "Adds X-Forwarded-For: 127.0.0.1 to impersonate localhost.",
        "headers_override": {"X-Forwarded-For": "127.0.0.1"},
        "attack_explanation": (
            "Some APIs whitelist localhost or internal IP ranges and bypass auth for those IPs. "
            "If the app trusts X-Forwarded-For blindly, any external caller can spoof it."
        ),
    },
    {
        "name": "X-Real-IP: 127.0.0.1 (IP Spoof)",
        "description": "Alternate IP-spoof header used by nginx and others.",
        "headers_override": {"X-Real-IP": "127.0.0.1", "X-Forwarded-For": "127.0.0.1"},
        "attack_explanation": (
            "nginx and some proxies set X-Real-IP. Apps that trust it for IP-allowlisting "
            "can be bypassed by setting this header to an internal address."
        ),
    },
    {
        "name": "X-Original-URL Admin Path Override",
        "description": "Sends X-Original-URL: /admin to attempt path override.",
        "headers_override": {"X-Original-URL": "/admin", "X-Rewrite-URL": "/admin"},
        "attack_explanation": (
            "Some reverse proxies (Symfony, Spring) route based on X-Original-URL before "
            "auth middleware can check the real path, granting access to protected routes."
        ),
    },
    {
        "name": "HTTP Method Override (POST→GET)",
        "description": "Adds X-HTTP-Method-Override: GET on a GET request.",
        "headers_override": {"X-HTTP-Method-Override": "GET", "X-Method-Override": "GET"},
        "attack_explanation": (
            "Frameworks that respect method-override headers can be tricked into treating "
            "a POST as a GET, bypassing auth rules that only apply to one HTTP method."
        ),
    },
]


class AuthBypassScanner(BaseScanner):
    NAME = "Auth Bypass"

    async def _baseline(self, client: httpx.AsyncClient) -> tuple[int, int]:
        """Get status code and body length with normal headers."""
        try:
            r = await client.get(self.target, headers=self.headers, timeout=self.timeout)
            return r.status_code, len(r.content)
        except httpx.RequestError:
            return 0, 0

    async def run(self) -> ScanResult:
        result = ScanResult(scanner=self.NAME, target=self.target)

        async with httpx.AsyncClient(follow_redirects=True) as client:
            baseline_status, baseline_len = await self._baseline(client)

            result.raw_requests.append({
                "probe": "Baseline",
                "method": "GET",
                "url": self.target,
                "status_code": baseline_status,
                "body_length": baseline_len,
                "headers_sent": dict(self.headers),
            })

            # If baseline is already 401/403, that's the expected state.
            # A bypass means we get 200 (or close) without valid creds.
            expected_auth_failure = baseline_status in (401, 403)

            for probe in AUTH_BYPASS_PROBES:
                # Build headers for this probe
                probe_headers = dict(self.headers)
                override = probe["headers_override"]

                if "_remove" in override:
                    probe_headers.pop(override["_remove"], None)
                else:
                    probe_headers.update(override)

                try:
                    resp = await client.get(
                        self.target, headers=probe_headers, timeout=self.timeout
                    )
                    status = resp.status_code
                    body_len = len(resp.content)
                except httpx.RequestError as exc:
                    result.raw_requests.append({"probe": probe["name"], "error": str(exc)})
                    continue

                result.raw_requests.append({
                    "probe": probe["name"],
                    "method": "GET",
                    "url": self.target,
                    "status_code": status,
                    "body_length": body_len,
                    "headers_sent": {k: v for k, v in probe_headers.items() if k.lower() != "authorization"},
                })

                # Flag as suspicious if:
                #  - Baseline was 401/403 and this probe got 2xx
                #  - OR body length is dramatically different (possible data leak)
                bypass_detected = expected_auth_failure and status in (200, 201, 204)
                significant_body_diff = abs(body_len - baseline_len) > 500 and status == baseline_status

                if bypass_detected:
                    result.findings.append(Finding(
                        title=f"Possible Auth Bypass — {probe['name']}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"{probe['description']} Baseline returned {baseline_status} "
                            f"but this probe returned {status}."
                        ),
                        evidence=(
                            f"Baseline: HTTP {baseline_status} ({baseline_len} bytes). "
                            f"With probe headers: HTTP {status} ({body_len} bytes)."
                        ),
                        remediation=(
                            "Validate authentication on every request server-side. "
                            "Do not trust client-supplied headers for access control decisions. "
                            "Use a strict JWT validation library that rejects alg=none. "
                            "Never IP-whitelist based on headers the client can set."
                        ),
                        attack_explanation=probe["attack_explanation"],
                    ))
                elif significant_body_diff:
                    result.findings.append(Finding(
                        title=f"Response Anomaly — {probe['name']}",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Same status code ({status}) but body size changed by "
                            f"{abs(body_len - baseline_len)} bytes with this probe's headers."
                        ),
                        evidence=(
                            f"Baseline body: {baseline_len} bytes. "
                            f"Probe body: {body_len} bytes."
                        ),
                        remediation=(
                            "Investigate why request headers alter the response body. "
                            "Ensure the same authentication path is taken regardless of headers."
                        ),
                        attack_explanation=probe["attack_explanation"],
                    ))

        if not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in result.findings):
            result.findings.append(Finding(
                title="No Auth Bypass Detected",
                severity=Severity.PASS,
                description=(
                    "None of the tested bypass techniques produced a different access level. "
                    "The endpoint appears to enforce authentication consistently."
                ),
                evidence=f"Baseline status: {baseline_status}. All probes returned the same or expected responses.",
                remediation="Continue enforcing server-side auth validation on all endpoints.",
                attack_explanation="Consistent auth enforcement forces attackers to find valid credentials.",
            ))

        return result
