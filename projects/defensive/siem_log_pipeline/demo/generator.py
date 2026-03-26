"""
demo.generator — Synthetic security event generator.

Produces realistic-looking events for all log sources supported by
SENTINEL so the pipeline can be demonstrated without external infrastructure.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any


class DemoGenerator:
    """Generate synthetic security events for demo / testing purposes."""

    SOURCE_TYPES: list[str] = [
        "honeypot",
        "network_baseline",
        "attack_correlator",
        "cloud_scanner",
    ]

    # ── Honeypot ────────────────────────────────────────────────────────

    _HONEYPOT_PROTOCOLS = ["SSH", "HTTP", "FTP", "TELNET", "SMB", "RDP"]
    _HONEYPOT_EVENT_TYPES = [
        "connection",
        "login_attempt",
        "brute_force",
        "scan",
        "exploit_attempt",
        "credential_stuffing",
    ]
    _SRC_IPS = [
        "203.0.113.42",
        "198.51.100.7",
        "192.0.2.99",
        "10.13.37.5",
        "172.16.44.8",
        "45.33.32.156",
        "91.189.92.10",
        "185.220.101.1",
        "104.248.50.87",
        "162.243.140.4",
    ]

    def _gen_honeypot(self, ts: str) -> dict[str, Any]:
        return {
            "protocol": random.choice(self._HONEYPOT_PROTOCOLS),
            "src_ip": random.choice(self._SRC_IPS),
            "event_type": random.choice(self._HONEYPOT_EVENT_TYPES),
            "timestamp": ts,
            "dst_port": random.choice([22, 80, 21, 23, 445, 3389, 8080, 443]),
            "payload_size": random.randint(0, 4096),
        }

    # ── Network baseline ────────────────────────────────────────────────

    _NET_ALERT_TYPES = [
        "port_scan_detected",
        "c2_beaconing",
        "data_exfiltration",
        "dns_tunneling",
        "arp_spoofing",
        "lateral_movement",
        "unusual_traffic_volume",
    ]
    _NET_SEVERITIES = ["low", "medium", "high", "critical"]
    _NET_DETAILS = [
        "Multiple SYN packets to sequential ports from 10.0.0.15",
        "Periodic HTTPS callbacks to known C2 domain every 60s",
        "Large outbound transfer to external IP 203.0.113.77 (2.3 GB)",
        "TXT record queries with encoded payloads to susp-domain.xyz",
        "Gratuitous ARP replies detected from 10.0.0.200",
        "SMB lateral movement from workstation to domain controller",
        "Outbound traffic 450% above 7-day baseline",
    ]

    def _gen_network_baseline(self, ts: str) -> dict[str, Any]:
        idx = random.randrange(len(self._NET_ALERT_TYPES))
        return {
            "alert_type": self._NET_ALERT_TYPES[idx],
            "severity": random.choice(self._NET_SEVERITIES),
            "details": self._NET_DETAILS[idx % len(self._NET_DETAILS)],
            "timestamp": ts,
            "src_ip": random.choice(self._SRC_IPS),
            "dst_ip": f"10.0.0.{random.randint(1, 254)}",
        }

    # ── Attack correlator ───────────────────────────────────────────────

    _TACTICS = [
        "initial_access",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "credential_access",
        "discovery",
        "lateral_movement",
        "collection",
        "exfiltration",
        "impact",
    ]
    _TECHNIQUES: dict[str, list[str]] = {
        "initial_access": ["T1566.001-phishing_attachment", "T1190-exploit_public_app"],
        "execution": ["T1059.001-powershell", "T1059.003-cmd_shell"],
        "persistence": ["T1053.005-scheduled_task", "T1547.001-registry_run_key"],
        "privilege_escalation": ["T1068-exploitation_for_privesc", "T1548.002-uac_bypass"],
        "defense_evasion": ["T1070.004-file_deletion", "T1027-obfuscated_files"],
        "credential_access": ["T1003.001-lsass_dump", "T1110.001-password_spraying"],
        "discovery": ["T1087.001-local_account_enum", "T1082-system_info_discovery"],
        "lateral_movement": ["T1021.001-rdp", "T1021.002-smb_admin_shares"],
        "collection": ["T1005-local_data_collection", "T1114.001-email_collection"],
        "exfiltration": ["T1041-exfil_over_c2", "T1048.003-exfil_over_dns"],
        "impact": ["T1486-data_encrypted_for_impact", "T1489-service_stop"],
    }

    def _gen_attack_correlator(self, ts: str) -> dict[str, Any]:
        tactic = random.choice(self._TACTICS)
        technique = random.choice(self._TECHNIQUES.get(tactic, ["T0000-unknown"]))
        return {
            "chain_id": f"CHAIN-{random.randint(1000, 9999)}",
            "tactic": tactic,
            "technique": technique,
            "confidence": round(random.uniform(0.15, 0.99), 2),
            "timestamp": ts,
            "affected_host": f"10.0.0.{random.randint(1, 254)}",
        }

    # ── Cloud scanner ───────────────────────────────────────────────────

    _CLOUD_CHECKS: list[dict[str, str]] = [
        {"check_id": "S3-001", "resource": "s3://company-backups", "desc": "S3 bucket publicly accessible"},
        {"check_id": "SG-002", "resource": "sg-0a1b2c3d4e", "desc": "Security group allows 0.0.0.0/0 on port 22"},
        {"check_id": "IAM-003", "resource": "arn:aws:iam::123456:user/admin", "desc": "Root account MFA not enabled"},
        {"check_id": "EBS-004", "resource": "vol-0abc123def", "desc": "EBS volume not encrypted"},
        {"check_id": "RDS-005", "resource": "db-production", "desc": "RDS instance publicly accessible"},
        {"check_id": "CW-006", "resource": "trail-main", "desc": "CloudTrail logging disabled in us-west-2"},
        {"check_id": "LB-007", "resource": "alb-frontend", "desc": "Load balancer missing access logs"},
        {"check_id": "KMS-008", "resource": "key-abc123", "desc": "KMS key rotation not enabled"},
    ]
    _CLOUD_STATUSES = ["fail", "warn", "pass"]
    _CLOUD_PROVIDERS = ["aws", "gcp", "azure"]

    def _gen_cloud_scanner(self, ts: str) -> dict[str, Any]:
        check = random.choice(self._CLOUD_CHECKS)
        return {
            "check_id": check["check_id"],
            "resource": check["resource"],
            "status": random.choice(self._CLOUD_STATUSES),
            "provider": random.choice(self._CLOUD_PROVIDERS),
            "timestamp": ts,
            "description": check["desc"],
        }

    # ── Public API ──────────────────────────────────────────────────────

    _GENERATORS: dict[str, str] = {
        "honeypot": "_gen_honeypot",
        "network_baseline": "_gen_network_baseline",
        "attack_correlator": "_gen_attack_correlator",
        "cloud_scanner": "_gen_cloud_scanner",
    }

    def generate_all(
        self,
        count_per_source: int = 50,
    ) -> list[tuple[str, dict[str, Any]]]:
        """Generate synthetic events for every source type.

        Parameters
        ----------
        count_per_source:
            Number of events to generate per source.

        Returns
        -------
        List of ``(source_type, raw_data)`` tuples.
        """
        events: list[tuple[str, dict[str, Any]]] = []
        now = datetime.now(timezone.utc)

        for source_type in self.SOURCE_TYPES:
            gen_method = getattr(self, self._GENERATORS[source_type])
            for i in range(count_per_source):
                # Spread events over the last 24 hours.
                offset = timedelta(seconds=random.randint(0, 86400))
                ts = (now - offset).isoformat()
                events.append((source_type, gen_method(ts)))

        # Shuffle so events from different sources are interleaved.
        random.shuffle(events)
        return events
