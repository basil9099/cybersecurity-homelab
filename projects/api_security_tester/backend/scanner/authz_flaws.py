"""
Authorization Flaw Scanner (BOLA / IDOR / Privilege Escalation)
================================================================
Tests for Broken Object-Level Authorization (OWASP API1) and
Broken Function-Level Authorization (OWASP API5).

Techniques:
  1. IDOR probe — if the URL contains a numeric ID, try adjacent IDs
  2. HTTP verb tampering — try DELETE/PUT/PATCH on endpoints that only expect GET
  3. Admin path discovery — append common admin suffixes to the base URL
  4. Parameter pollution — duplicate query parameters with elevated values
  5. Role-escalation headers — add headers that some frameworks trust for roles

Why it matters:
  OWASP API Security Top 10 lists BOLA as the #1 API risk. APIs that
  expose object references without checking ownership let any authenticated
  (or unauthenticated) user access or modify another user's data.
"""

import re
import urllib.parse

import httpx

from .base import BaseScanner, Finding, ScanResult, Severity

ADMIN_PATHS = [
    "/admin",
    "/admin/",
    "/api/admin",
    "/api/v1/admin",
    "/management",
    "/internal",
    "/debug",
    "/config",
    "/health/details",
    "/actuator",
    "/actuator/env",
    "/actuator/beans",
    "/.env",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/openapi.json",
    "/api-docs",
    "/graphql",
]

ELEVATED_ROLE_HEADERS = [
    {"X-Role": "admin"},
    {"X-User-Role": "admin"},
    {"X-Admin": "true"},
    {"X-Privileged": "1"},
    {"X-Override-Role": "superuser"},
    {"X-Internal": "true"},
    {"X-Service-Account": "true"},
]

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


def _extract_numeric_ids(url: str) -> list[tuple[str, int]]:
    """Return (param_name_or_path_pos, value) for each numeric segment."""
    results = []
    # Path segments: /users/123/posts/456
    path = urllib.parse.urlparse(url).path
    for match in re.finditer(r"/(\d+)", path):
        results.append(("path:" + match.group(0), int(match.group(1))))
    # Query params: ?user_id=5
    params = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    for k, v in params.items():
        if v and v[0].isdigit():
            results.append((f"query:{k}", int(v[0])))
    return results


def _replace_id_in_url(url: str, original_id: int, new_id: int) -> str:
    parsed = urllib.parse.urlparse(url)
    # Replace in path
    new_path = re.sub(rf"(/)({re.escape(str(original_id))})(/?)", rf"\g<1>{new_id}\3", parsed.path)
    # Replace in query
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    new_params = {}
    for k, v in params.items():
        new_params[k] = [str(new_id) if x == str(original_id) else x for x in v]
    new_query = urllib.parse.urlencode(new_params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(path=new_path, query=new_query))


class AuthzFlawScanner(BaseScanner):
    NAME = "Authorization Flaws"

    async def run(self) -> ScanResult:
        result = ScanResult(scanner=self.NAME, target=self.target)
        base = urllib.parse.urlparse(self.target)
        origin = f"{base.scheme}://{base.netloc}"

        async with httpx.AsyncClient(follow_redirects=False) as client:

            # ── Baseline ─────────────────────────────────────────────────────
            try:
                base_resp = await client.get(self.target, headers=self.headers, timeout=self.timeout)
                baseline_status = base_resp.status_code
                baseline_len = len(base_resp.content)
            except httpx.RequestError as exc:
                result.error = f"Baseline request failed: {exc}"
                return result

            result.raw_requests.append({
                "probe": "Baseline",
                "method": "GET",
                "url": self.target,
                "status_code": baseline_status,
                "body_length": baseline_len,
            })

            # ── 1. IDOR — numeric ID probing ─────────────────────────────────
            numeric_ids = _extract_numeric_ids(self.target)
            for loc, original_id in numeric_ids:
                # Try the IDs immediately around the original
                candidate_ids = {1, 2, original_id - 1, original_id + 1, original_id + 100}
                candidate_ids.discard(original_id)
                candidate_ids.discard(0)

                for cid in sorted(candidate_ids):
                    candidate_url = _replace_id_in_url(self.target, original_id, cid)
                    try:
                        resp = await client.get(candidate_url, headers=self.headers, timeout=self.timeout)
                        status = resp.status_code
                        body_len = len(resp.content)
                    except httpx.RequestError:
                        continue

                    result.raw_requests.append({
                        "probe": f"IDOR probe (id={cid})",
                        "method": "GET",
                        "url": candidate_url,
                        "status_code": status,
                        "body_length": body_len,
                        "original_id": original_id,
                    })

                    if status in (200, 201) and body_len > 50:
                        result.findings.append(Finding(
                            title=f"Possible IDOR — Object ID {cid} Accessible",
                            severity=Severity.HIGH,
                            description=(
                                f"Replaced ID {original_id} with {cid} in the URL and received "
                                f"a {status} response with {body_len} bytes — possible access "
                                "to another user's resource."
                            ),
                            evidence=(
                                f"Original URL: {self.target}\n"
                                f"Probed URL: {candidate_url}\n"
                                f"Status: {status} | Body: {body_len} bytes"
                            ),
                            remediation=(
                                "Enforce object-level authorization on every data-retrieval operation. "
                                "Verify the requesting user owns or has permission to access the "
                                "requested object — never rely solely on the ID being 'unguessable'. "
                                "Consider using non-sequential UUIDs to reduce IDOR discoverability."
                            ),
                            attack_explanation=(
                                "BOLA/IDOR (Broken Object-Level Authorization) is OWASP API #1. "
                                "Attackers increment or decrement numeric IDs to access other users' "
                                "records. A single vulnerable endpoint can expose an entire database."
                            ),
                        ))

            # ── 2. HTTP Verb Tampering ────────────────────────────────────────
            for method in ["DELETE", "PUT", "PATCH"]:
                try:
                    resp = await client.request(
                        method, self.target, headers=self.headers, timeout=self.timeout
                    )
                    status = resp.status_code
                except httpx.RequestError:
                    continue

                result.raw_requests.append({
                    "probe": f"Verb tampering: {method}",
                    "method": method,
                    "url": self.target,
                    "status_code": status,
                })

                if status in (200, 201, 204):
                    result.findings.append(Finding(
                        title=f"Unexpected {method} Method Accepted",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The endpoint accepted {method} and returned {status}. "
                            "If only GET is intended, this may allow unintended modifications."
                        ),
                        evidence=f"Method: {method} → Status: {status}",
                        remediation=(
                            "Explicitly restrict HTTP methods at the route level. "
                            "Return 405 Method Not Allowed for any method not in use. "
                            "Ensure authorization checks apply to every allowed method separately."
                        ),
                        attack_explanation=(
                            "HTTP verb tampering exploits endpoints that only check auth on "
                            "the primary method. An API protecting GET may forget to protect "
                            "DELETE on the same path, letting attackers delete resources."
                        ),
                    ))

            # ── 3. Admin / Sensitive Path Discovery ──────────────────────────
            accessible_paths = []
            for path in ADMIN_PATHS:
                url = origin + path
                try:
                    resp = await client.get(url, headers=self.headers, timeout=self.timeout)
                    status = resp.status_code
                    body_len = len(resp.content)
                except httpx.RequestError:
                    continue

                result.raw_requests.append({
                    "probe": f"Admin path: {path}",
                    "method": "GET",
                    "url": url,
                    "status_code": status,
                    "body_length": body_len,
                })

                if status not in (404, 405, 410) and body_len > 20:
                    accessible_paths.append((path, status, body_len))

            if accessible_paths:
                paths_str = ", ".join(f"{p} ({s})" for p, s, _ in accessible_paths)
                result.findings.append(Finding(
                    title="Sensitive / Admin Paths Accessible",
                    severity=Severity.HIGH,
                    description=f"Found {len(accessible_paths)} potentially sensitive path(s) returning non-404.",
                    evidence=f"Accessible paths: {paths_str}",
                    remediation=(
                        "Restrict admin and internal endpoints to specific roles or IP ranges. "
                        "Disable debug/actuator endpoints in production. "
                        "Return 404 (not 403) for paths that should not be discoverable."
                    ),
                    attack_explanation=(
                        "Exposed admin panels, Swagger UIs, and actuator endpoints are frequent "
                        "attack targets. They often reveal internal API structure, allow unauthenticated "
                        "operations, or expose environment variables and credentials."
                    ),
                ))

            # ── 4. Role-Escalation Headers ────────────────────────────────────
            for extra_headers in ELEVATED_ROLE_HEADERS:
                probe_headers = {**self.headers, **extra_headers}
                try:
                    resp = await client.get(self.target, headers=probe_headers, timeout=self.timeout)
                    status = resp.status_code
                    body_len = len(resp.content)
                except httpx.RequestError:
                    continue

                result.raw_requests.append({
                    "probe": f"Role header: {extra_headers}",
                    "method": "GET",
                    "url": self.target,
                    "status_code": status,
                    "body_length": body_len,
                })

                body_diff = abs(body_len - baseline_len)
                if (status == 200 and baseline_status in (401, 403)) or body_diff > 500:
                    result.findings.append(Finding(
                        title=f"Role-Escalation Header Accepted: {list(extra_headers.keys())[0]}",
                        severity=Severity.CRITICAL,
                        description=(
                            f"Adding header {extra_headers} changed the response from "
                            f"{baseline_status} to {status} (body diff: {body_diff} bytes)."
                        ),
                        evidence=(
                            f"Header sent: {extra_headers}\n"
                            f"Baseline: {baseline_status} ({baseline_len} bytes) → "
                            f"With header: {status} ({body_len} bytes)"
                        ),
                        remediation=(
                            "Never use client-supplied headers to determine user roles or privileges. "
                            "Role/permission data must come from server-side session state or a "
                            "cryptographically verified token (e.g., JWT signed by the server)."
                        ),
                        attack_explanation=(
                            "Some frameworks have middleware that reads role from headers for "
                            "service-to-service communication. If not restricted to internal "
                            "networks, any client can impersonate an admin by adding a header."
                        ),
                    ))

        if not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in result.findings):
            result.findings.append(Finding(
                title="No Authorization Flaws Detected",
                severity=Severity.PASS,
                description=(
                    "IDOR probes, verb tampering, admin path discovery, and role-header tests "
                    "did not reveal any obvious authorization weaknesses."
                ),
                evidence=f"Tested {len(ADMIN_PATHS)} admin paths, {len(ELEVATED_ROLE_HEADERS)} role headers, IDOR probes, and 3 verb variants.",
                remediation="Continue enforcing object-level authorization and restricting sensitive paths.",
                attack_explanation="Consistent authorization checks prevent lateral movement across user accounts.",
            ))

        return result
