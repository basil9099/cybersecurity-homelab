"""Generate ~50 realistic mock CVE records spread over the last 30 days."""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Vulnerability templates: (vuln_type, cwe_id, description_template, products)
# ---------------------------------------------------------------------------
_VULN_TYPES = [
    (
        "RCE",
        "CWE-94",
        "Remote code execution in {product} allows unauthenticated attackers to execute arbitrary commands via crafted {vector}.",
        ["apache:http_server:2.4.51", "apache:struts:2.5.30", "gitlab:gitlab_ce:16.8.1",
         "jenkins:jenkins:2.426", "atlassian:confluence:8.7.1", "vmware:vcenter_server:8.0"],
    ),
    (
        "SQL Injection",
        "CWE-89",
        "SQL injection vulnerability in {product} enables attackers to retrieve sensitive data via the {vector} parameter.",
        ["wordpress:plugin:contact_form_7:5.8", "drupal:core:10.2.1", "moodle:moodle:4.3.2",
         "sap:netweaver:7.50", "oracle:e_business_suite:12.2"],
    ),
    (
        "XSS",
        "CWE-79",
        "Reflected cross-site scripting in {product} permits injection of malicious scripts through {vector} inputs.",
        ["microsoft:outlook_web_app:2019", "roundcube:webmail:1.6.5", "zimbra:collaboration:10.0.1",
         "grafana:grafana:10.2.3", "nextcloud:server:28.0.1"],
    ),
    (
        "Path Traversal",
        "CWE-22",
        "Directory traversal in {product} allows reading arbitrary files on the server via {vector} manipulation.",
        ["apache:tomcat:10.1.17", "nginx:nginx:1.25.4", "paloalto:pan_os:11.1.3",
         "fortinet:fortigate:7.4.2", "citrix:netscaler:14.1"],
    ),
    (
        "Auth Bypass",
        "CWE-287",
        "Authentication bypass in {product} permits unauthenticated access to administrative functions through {vector}.",
        ["cisco:ios_xe:17.12", "juniper:junos:23.4", "fortinet:fortimanager:7.4.1",
         "ivanti:connect_secure:22.7", "sonicwall:sma:10.2.1"],
    ),
    (
        "Deserialization",
        "CWE-502",
        "Insecure deserialization in {product} leads to remote code execution when processing untrusted {vector} data.",
        ["apache:activemq:5.18.3", "apache:ofbiz:18.12.10", "oracle:weblogic:14.1.1",
         "red_hat:jboss_eap:7.4", "ibm:websphere:9.0.5"],
    ),
    (
        "SSRF",
        "CWE-918",
        "Server-side request forgery in {product} enables attackers to access internal services via crafted {vector} requests.",
        ["hashicorp:vault:1.15.4", "elastic:kibana:8.12.0", "grafana:grafana:10.3.1",
         "gitlab:gitlab_ee:16.9.0", "microsoft:exchange_server:2019"],
    ),
    (
        "Buffer Overflow",
        "CWE-120",
        "Stack-based buffer overflow in {product} allows remote attackers to execute code via a specially crafted {vector} packet.",
        ["openssl:openssl:3.2.0", "curl:curl:8.5.0", "linux:kernel:6.7.2",
         "qualcomm:snapdragon:sm8550", "apple:macos:14.2"],
    ),
]

_VECTORS = [
    "HTTP request", "API endpoint", "file upload", "query string",
    "SOAP message", "JSON payload", "URI path", "POST body",
    "multipart form", "WebSocket frame", "LDAP filter", "XML entity",
]

_CVSS_VECTORS = {
    "CRITICAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "HIGH":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "MEDIUM":   "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L",
    "LOW":      "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
}


def generate_mock_cves(count: int = 50, seed: int = 42) -> list[dict]:
    """Return *count* CVE dicts ready for DB insertion into the cves table."""
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)

    # Decide severity distribution
    severity_pool: list[str] = (
        ["CRITICAL"] * 5 + ["HIGH"] * 15 + ["MEDIUM"] * 20 + ["LOW"] * 10
    )
    rng.shuffle(severity_pool)
    severity_pool = severity_pool[:count]

    records: list[dict] = []
    used_ids: set[str] = set()

    for i in range(count):
        # Unique CVE ID
        while True:
            cve_num = rng.randint(10001, 59999)
            cve_id = f"CVE-2026-{cve_num:05d}"
            if cve_id not in used_ids:
                used_ids.add(cve_id)
                break

        severity = severity_pool[i]

        # CVSS score in range for severity
        if severity == "CRITICAL":
            cvss = round(rng.uniform(9.0, 10.0), 1)
        elif severity == "HIGH":
            cvss = round(rng.uniform(7.0, 8.9), 1)
        elif severity == "MEDIUM":
            cvss = round(rng.uniform(4.0, 6.9), 1)
        else:
            cvss = round(rng.uniform(0.1, 3.9), 1)

        # EPSS correlated with CVSS (higher CVSS -> higher EPSS tendency)
        epss_base = cvss / 10.0
        epss = round(min(1.0, max(0.0, epss_base + rng.gauss(0, 0.12))), 4)
        epss_percentile = round(min(0.99, max(0.01, epss + rng.uniform(-0.05, 0.1))), 4)

        # Pick a vuln type
        vtype = rng.choice(_VULN_TYPES)
        vuln_name, cwe, desc_tpl, products = vtype
        product = rng.choice(products)
        vector = rng.choice(_VECTORS)
        description = desc_tpl.format(product=product.replace(":", " ").replace("_", " "), vector=vector)

        # Published date within last 30 days
        days_ago = rng.uniform(0, 30)
        published = now - timedelta(days=days_ago)
        modified = published + timedelta(hours=rng.uniform(1, 48))

        records.append({
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss,
            "cvss_vector": _CVSS_VECTORS[severity],
            "cvss_severity": severity,
            "epss_score": epss,
            "epss_percentile": epss_percentile,
            "cwe_ids": [cwe],
            "affected_products": [product],
            "published_date": published.isoformat(),
            "modified_date": modified.isoformat(),
            "has_exploit": 0,  # will be updated by mock_exploits cross-ref
            "references_": [
                f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            ],
            "fetched_at": now.isoformat(),
        })

    # Sort by published date descending (newest first)
    records.sort(key=lambda r: r["published_date"], reverse=True)
    return records


def get_mock_cve_ids(count: int = 50, seed: int = 42) -> list[str]:
    """Return just the CVE ID strings from the mock data."""
    return [r["cve_id"] for r in generate_mock_cves(count, seed)]
