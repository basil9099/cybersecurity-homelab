#!/usr/bin/env python3
"""
mappings/mitre_attack.py
========================
MITRE ATT&CK technique and tactic mappings for homelab alert types.

Maps anomaly types from each source tool to ATT&CK technique IDs and their
parent tactics (kill chain stages). This enables the state machine to track
entity progression through the kill chain.

ATT&CK Tactics (ordered by kill chain):
  1. reconnaissance
  2. resource_development
  3. initial_access
  4. execution
  5. persistence
  6. privilege_escalation
  7. defense_evasion
  8. credential_access
  9. discovery
  10. lateral_movement
  11. collection
  12. command_and_control
  13. exfiltration
  14. impact
"""

from __future__ import annotations

from dataclasses import dataclass


# Kill chain stage ordering (lower = earlier in chain)
TACTIC_ORDER: dict[str, int] = {
    "reconnaissance": 1,
    "resource_development": 2,
    "initial_access": 3,
    "execution": 4,
    "persistence": 5,
    "privilege_escalation": 6,
    "defense_evasion": 7,
    "credential_access": 8,
    "discovery": 9,
    "lateral_movement": 10,
    "collection": 11,
    "command_and_control": 12,
    "exfiltration": 13,
    "impact": 14,
}


@dataclass(frozen=True)
class TechniqueMapping:
    """Maps an alert type to ATT&CK technique(s) and tactic."""
    technique_ids: tuple[str, ...]
    tactic: str
    description: str


# ── Alert type → ATT&CK mapping table ────────────────────────────────────────
# Keys are (source, anomaly_type) tuples for precise matching.

ALERT_MAPPINGS: dict[tuple[str, str], TechniqueMapping] = {
    # Network Baseline Monitor alerts
    ("network_baseline", "port_scan"): TechniqueMapping(
        technique_ids=("T1046",),
        tactic="discovery",
        description="Network Service Discovery via port scanning",
    ),
    ("network_baseline", "exfiltration"): TechniqueMapping(
        technique_ids=("T1041", "T1048"),
        tactic="exfiltration",
        description="Exfiltration Over C2 Channel / Alternative Protocol",
    ),
    ("network_baseline", "c2_beaconing"): TechniqueMapping(
        technique_ids=("T1071", "T1573"),
        tactic="command_and_control",
        description="Application Layer Protocol / Encrypted Channel beaconing",
    ),
    ("network_baseline", "lateral_movement"): TechniqueMapping(
        technique_ids=("T1021", "T1570"),
        tactic="lateral_movement",
        description="Remote Services / Lateral Tool Transfer",
    ),
    ("network_baseline", "statistical_anomaly"): TechniqueMapping(
        technique_ids=("T1071",),
        tactic="command_and_control",
        description="Unusual network traffic volume (possible C2 or exfil)",
    ),
    ("network_baseline", "coordinated_incident"): TechniqueMapping(
        technique_ids=("T1071", "T1046", "T1041"),
        tactic="impact",
        description="Multiple simultaneous anomaly types — active intrusion",
    ),

    # Splunk SIEM alerts
    ("splunk_siem", "brute_force"): TechniqueMapping(
        technique_ids=("T1110",),
        tactic="credential_access",
        description="Brute Force password attack",
    ),
    ("splunk_siem", "failed_login_spike"): TechniqueMapping(
        technique_ids=("T1110.001",),
        tactic="credential_access",
        description="Password Guessing — spike in failed authentications",
    ),
    ("splunk_siem", "new_service_created"): TechniqueMapping(
        technique_ids=("T1543.003",),
        tactic="persistence",
        description="Windows Service creation for persistence",
    ),
    ("splunk_siem", "scheduled_task_created"): TechniqueMapping(
        technique_ids=("T1053.005",),
        tactic="persistence",
        description="Scheduled Task creation for persistence",
    ),
    ("splunk_siem", "powershell_execution"): TechniqueMapping(
        technique_ids=("T1059.001",),
        tactic="execution",
        description="PowerShell command/script execution",
    ),
    ("splunk_siem", "suspicious_process"): TechniqueMapping(
        technique_ids=("T1059",),
        tactic="execution",
        description="Suspicious process execution",
    ),
    ("splunk_siem", "registry_modification"): TechniqueMapping(
        technique_ids=("T1547.001",),
        tactic="persistence",
        description="Registry Run Keys modification for persistence",
    ),
    ("splunk_siem", "privilege_escalation"): TechniqueMapping(
        technique_ids=("T1068",),
        tactic="privilege_escalation",
        description="Exploitation for Privilege Escalation",
    ),
    ("splunk_siem", "log_cleared"): TechniqueMapping(
        technique_ids=("T1070.001",),
        tactic="defense_evasion",
        description="Clear Windows Event Logs",
    ),

    # Cloud scanner findings
    ("cloud_scanner", "public_s3_bucket"): TechniqueMapping(
        technique_ids=("T1530",),
        tactic="collection",
        description="Data from Cloud Storage Object — public bucket",
    ),
    ("cloud_scanner", "overly_permissive_iam"): TechniqueMapping(
        technique_ids=("T1078.004",),
        tactic="initial_access",
        description="Valid Accounts: Cloud Accounts with excessive permissions",
    ),
    ("cloud_scanner", "security_group_open"): TechniqueMapping(
        technique_ids=("T1190",),
        tactic="initial_access",
        description="Exploit Public-Facing Application via open security groups",
    ),
    ("cloud_scanner", "logging_disabled"): TechniqueMapping(
        technique_ids=("T1562.008",),
        tactic="defense_evasion",
        description="Disable Cloud Logs",
    ),

    # Vulnerability scanner findings
    ("vuln_scanner", "critical_cve"): TechniqueMapping(
        technique_ids=("T1190",),
        tactic="initial_access",
        description="Exploit Public-Facing Application via critical CVE",
    ),
    ("vuln_scanner", "high_cve"): TechniqueMapping(
        technique_ids=("T1190",),
        tactic="initial_access",
        description="Exploitable high-severity vulnerability",
    ),
}

# Fallback mapping for unknown alert types
DEFAULT_MAPPING = TechniqueMapping(
    technique_ids=("T1071",),
    tactic="discovery",
    description="Unknown alert type — mapped to discovery by default",
)


def map_alert(source: str, anomaly_type: str) -> TechniqueMapping:
    """Look up ATT&CK mapping for a given source and anomaly type."""
    return ALERT_MAPPINGS.get((source, anomaly_type), DEFAULT_MAPPING)


def tactic_stage(tactic: str) -> int:
    """Return the kill chain stage number for a tactic (1-14)."""
    return TACTIC_ORDER.get(tactic, 0)


def is_progression(earlier_tactic: str, later_tactic: str) -> bool:
    """Return True if later_tactic comes after earlier_tactic in the kill chain."""
    return tactic_stage(later_tactic) > tactic_stage(earlier_tactic)
