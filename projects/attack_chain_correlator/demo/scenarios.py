#!/usr/bin/env python3
"""
demo/scenarios.py
=================
Synthetic multi-stage attack scenarios for testing the correlator.

Each scenario generates a realistic sequence of NormalizedAlerts that
simulate a full attack chain progressing through ATT&CK tactics. These
can be fed into the ChainManager to verify detection and scoring.

Scenarios:
  1. APT-style intrusion: recon → initial access → execution → persistence →
     lateral movement → C2 → exfiltration
  2. Insider threat: credential access → discovery → collection → exfiltration
  3. Cloud breach: initial access → privilege escalation → defense evasion →
     collection → exfiltration
  4. Noisy red team: rapid multi-vector attack hitting many stages fast
  5. False positive mix: benign alerts that should NOT form a chain
"""

from __future__ import annotations

import time

from correlation.chains import ChainManager
from ingestion.schema import AlertSource, NormalizedAlert, Severity
from mappings.mitre_attack import map_alert


def _alert(
    ts_offset: float,
    source: str,
    anomaly_type: str,
    src_entity: str,
    severity: Severity = Severity.MEDIUM,
    score: float = 5.0,
    dst_entity: str = "",
    detail: dict | None = None,
) -> NormalizedAlert:
    """Helper to create a NormalizedAlert with ATT&CK mapping."""
    mapping = map_alert(source, anomaly_type)
    source_enum = AlertSource(source)
    return NormalizedAlert(
        timestamp=time.time() + ts_offset,
        source=source_enum,
        anomaly_type=anomaly_type,
        severity=severity,
        score=score,
        src_entity=src_entity,
        dst_entity=dst_entity,
        technique_ids=list(mapping.technique_ids),
        tactic=mapping.tactic,
        raw_detail=detail or {"scenario": "demo"},
    )


def scenario_apt_intrusion() -> list[NormalizedAlert]:
    """
    Scenario 1: APT-style multi-stage intrusion.

    Attacker at 10.0.0.50 performs reconnaissance, exploits a vulnerability,
    establishes persistence, moves laterally, sets up C2, and exfiltrates data.
    """
    attacker = "10.0.0.50"
    return [
        # Stage 1: Discovery — port scan
        _alert(0, "network_baseline", "port_scan", attacker,
               Severity.MEDIUM, 6.5, "10.0.0.0/24",
               {"unique_ports_contacted": 45, "ports_sample": [22, 80, 443, 445, 3389]}),

        # Stage 2: Initial access — critical CVE exploited
        _alert(120, "vuln_scanner", "critical_cve", attacker,
               Severity.HIGH, 9.0, "10.0.0.10",
               {"cve_id": "CVE-2024-1234", "service": "Apache/2.4.49"}),

        # Stage 3: Execution — PowerShell on target
        _alert(180, "splunk_siem", "powershell_execution", attacker,
               Severity.HIGH, 7.5, "10.0.0.10",
               {"command": "IEX (New-Object Net.WebClient).DownloadString(...)"}),

        # Stage 4: Persistence — scheduled task created
        _alert(300, "splunk_siem", "scheduled_task_created", attacker,
               Severity.MEDIUM, 6.0, "10.0.0.10",
               {"task_name": "WindowsUpdate", "action": "powershell.exe -enc ..."}),

        # Stage 5: Lateral movement — new internal pairs
        _alert(600, "network_baseline", "lateral_movement", attacker,
               Severity.HIGH, 7.0, "10.0.0.20",
               {"new_internal_pairs": ["10.0.0.50:10.0.0.20", "10.0.0.50:10.0.0.30"]}),

        # Stage 6: C2 — beaconing detected
        _alert(900, "network_baseline", "c2_beaconing", attacker,
               Severity.HIGH, 8.0, "203.0.113.50",
               {"mean_interval_s": 60.0, "interval_cv": 0.05}),

        # Stage 7: Exfiltration — large outbound transfer
        _alert(1200, "network_baseline", "exfiltration", attacker,
               Severity.HIGH, 8.5, "203.0.113.50",
               {"external_bytes_out": 52428800, "ratio_vs_baseline": 12.5}),
    ]


def scenario_insider_threat() -> list[NormalizedAlert]:
    """
    Scenario 2: Insider threat.

    A compromised user account performs credential stuffing, discovers
    sensitive resources, collects data, and exfiltrates it.
    """
    insider = "10.0.0.100"
    return [
        # Credential access — brute force attempts
        _alert(0, "splunk_siem", "brute_force", insider,
               Severity.MEDIUM, 5.5, "10.0.0.5",
               {"failed_attempts": 150, "target_accounts": 12}),

        # Discovery — port scan of internal network
        _alert(300, "network_baseline", "port_scan", insider,
               Severity.MEDIUM, 5.0, "10.0.0.0/24",
               {"unique_ports_contacted": 25}),

        # Defense evasion — logs cleared
        _alert(600, "splunk_siem", "log_cleared", insider,
               Severity.HIGH, 8.0, "10.0.0.100",
               {"log_type": "Security", "event_id": 1102}),

        # Exfiltration
        _alert(1800, "network_baseline", "exfiltration", insider,
               Severity.HIGH, 7.5, "198.51.100.25",
               {"external_bytes_out": 104857600}),
    ]


def scenario_cloud_breach() -> list[NormalizedAlert]:
    """
    Scenario 3: Cloud infrastructure breach.

    Attacker exploits misconfigured IAM, escalates privileges, disables
    logging, accesses S3 data, and exfiltrates.
    """
    cloud_entity = "arn:aws:iam::123456789012:user/compromised"
    return [
        # Initial access — overly permissive IAM
        _alert(0, "cloud_scanner", "overly_permissive_iam", cloud_entity,
               Severity.HIGH, 7.0, "us-east-1",
               {"policy": "AdministratorAccess", "resource": "iam-user-compromised"}),

        # Privilege escalation
        _alert(120, "splunk_siem", "privilege_escalation", cloud_entity,
               Severity.HIGH, 8.0, "us-east-1",
               {"action": "iam:AttachRolePolicy", "policy": "AdministratorAccess"}),

        # Defense evasion — logging disabled
        _alert(300, "cloud_scanner", "logging_disabled", cloud_entity,
               Severity.HIGH, 8.5, "us-east-1",
               {"service": "CloudTrail", "trail": "management-events"}),

        # Collection — public S3 bucket accessed
        _alert(600, "cloud_scanner", "public_s3_bucket", cloud_entity,
               Severity.HIGH, 7.5, "us-east-1",
               {"bucket": "company-sensitive-data", "public_access": True}),

        # Exfiltration
        _alert(900, "network_baseline", "exfiltration", cloud_entity,
               Severity.HIGH, 9.0, "203.0.113.100",
               {"external_bytes_out": 209715200}),
    ]


def scenario_noisy_redteam() -> list[NormalizedAlert]:
    """
    Scenario 4: Noisy red team exercise.

    Rapid, aggressive attack hitting many stages in quick succession.
    Should produce a high-velocity, high-confidence chain.
    """
    redteam = "10.0.0.200"
    return [
        _alert(0, "network_baseline", "port_scan", redteam,
               Severity.HIGH, 8.0, "10.0.0.0/24"),
        _alert(30, "vuln_scanner", "critical_cve", redteam,
               Severity.CRITICAL, 9.5, "10.0.0.10"),
        _alert(60, "splunk_siem", "powershell_execution", redteam,
               Severity.HIGH, 8.0, "10.0.0.10"),
        _alert(90, "splunk_siem", "new_service_created", redteam,
               Severity.HIGH, 7.0, "10.0.0.10"),
        _alert(120, "splunk_siem", "privilege_escalation", redteam,
               Severity.HIGH, 8.5, "10.0.0.10"),
        _alert(150, "network_baseline", "lateral_movement", redteam,
               Severity.HIGH, 8.0, "10.0.0.20"),
        _alert(180, "network_baseline", "c2_beaconing", redteam,
               Severity.HIGH, 9.0, "203.0.113.99"),
        _alert(210, "network_baseline", "exfiltration", redteam,
               Severity.HIGH, 9.5, "203.0.113.99"),
    ]


def scenario_false_positives() -> list[NormalizedAlert]:
    """
    Scenario 5: Benign alerts that should NOT form attack chains.

    Scattered low-severity alerts from different entities that don't
    show kill chain progression.
    """
    return [
        _alert(0, "network_baseline", "statistical_anomaly", "10.0.0.5",
               Severity.LOW, 2.0),
        _alert(300, "network_baseline", "statistical_anomaly", "10.0.0.6",
               Severity.LOW, 1.5),
        _alert(600, "cloud_scanner", "security_group_open", "sg-12345",
               Severity.MEDIUM, 4.0, "us-west-2"),
        _alert(900, "splunk_siem", "failed_login_spike", "10.0.0.7",
               Severity.LOW, 3.0, "10.0.0.5"),
    ]


ALL_SCENARIOS = {
    "apt_intrusion": scenario_apt_intrusion,
    "insider_threat": scenario_insider_threat,
    "cloud_breach": scenario_cloud_breach,
    "noisy_redteam": scenario_noisy_redteam,
    "false_positives": scenario_false_positives,
}


def run_demo(scenario_name: str | None = None) -> None:
    """
    Run demo scenarios and print results.

    Args:
        scenario_name: Specific scenario to run, or None for all.
    """
    manager = ChainManager(
        chain_window_seconds=7200,
        min_chain_stages=3,
    )

    scenarios = (
        {scenario_name: ALL_SCENARIOS[scenario_name]}
        if scenario_name and scenario_name in ALL_SCENARIOS
        else ALL_SCENARIOS
    )

    print("=" * 70)
    print("ATTACK CHAIN CORRELATOR — DEMO")
    print("=" * 70)

    for name, scenario_fn in scenarios.items():
        alerts = scenario_fn()
        print(f"\n{'─' * 70}")
        print(f"Scenario: {name.upper().replace('_', ' ')}")
        print(f"Alerts: {len(alerts)}")
        print(f"{'─' * 70}")

        chains = manager.process_batch(alerts)

        if not chains:
            print("  No attack chains detected (expected for benign scenarios)")
            continue

        for chain in chains:
            print(f"\n  Chain ID: {chain.chain_id}")
            print(f"  Entity:   {chain.entity_id}")
            print(f"  Status:   {chain.status.upper()}")
            if chain.score:
                print(f"  Score:    {chain.score.composite:.1f}/10 "
                      f"(posterior: {chain.score.posterior:.1%})")
                print(f"  Level:    {chain.score.escalation_level.upper()}")
            if chain.state:
                tactics = [obs.tactic for obs in chain.state.tactics_in_order]
                print(f"  Stages:   {' → '.join(tactics)}")
            print(f"  Summary:  {chain.summary}")

    # Overall stats
    stats = manager.get_stats()
    print(f"\n{'=' * 70}")
    print("OVERALL STATS")
    print(f"  Total alerts processed: {stats['total_alerts_processed']}")
    print(f"  Tracked entities:       {stats['tracked_entities']}")
    print(f"  Active chains:          {stats['active_chains']}")
    print(f"  Escalated chains:       {stats['escalated_chains']}")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    import sys
    scenario = sys.argv[1] if len(sys.argv) > 1 else None
    run_demo(scenario)
