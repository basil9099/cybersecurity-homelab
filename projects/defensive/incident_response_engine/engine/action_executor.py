"""Action executor that performs individual incident response actions.

In demo mode, all actions are simulated with realistic output.
In live mode, actions would integrate with real security tools and APIs.
"""

from __future__ import annotations

import random
import time
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel

from models.response import StepResult, ExecutionStatus

console = Console()

# Simulated delays (seconds) to make demo output feel realistic
_SIM_DELAY_RANGE: tuple[float, float] = (0.3, 1.2)


class ActionExecutor:
    """Executes individual incident response actions.

    Supports both demo (simulated) and live execution modes.
    Each action type has a dedicated handler that produces structured
    output and collects evidence artifacts.

    Attributes:
        demo_mode: When True, all actions are simulated.
    """

    def __init__(self, demo_mode: bool = True) -> None:
        self.demo_mode = demo_mode
        self._action_handlers: dict[str, Any] = {
            "log_event": self._action_log_event,
            "block_ip": self._action_block_ip,
            "isolate_host": self._action_isolate_host,
            "collect_evidence": self._action_collect_evidence,
            "notify": self._action_notify,
            "escalate": self._action_escalate,
            "run_script": self._action_run_script,
            "disable_account": self._action_disable_account,
            "capture_traffic": self._action_capture_traffic,
            "scan_network": self._action_scan_network,
            "review_sessions": self._action_review_sessions,
            "audit_logs": self._action_audit_logs,
            "preserve_logs": self._action_preserve_logs,
        }

    def execute(self, action: str, parameters: dict[str, Any], timeout: int = 300) -> StepResult:
        """Execute a single action with the given parameters.

        Args:
            action: The action type to execute.
            parameters: Action-specific parameters.
            timeout: Maximum execution time in seconds.

        Returns:
            A StepResult containing the outcome of the action.
        """
        result = StepResult(
            step_name=parameters.get("step_name", action),
            action=action,
            started_at=datetime.utcnow(),
            nist_phase=parameters.get("nist_phase", "containment"),
        )

        handler = self._action_handlers.get(action)
        if handler is None:
            result.status = ExecutionStatus.FAILED
            result.error = f"Unknown action type: {action}"
            result.completed_at = datetime.utcnow()
            return result

        try:
            output, evidence = handler(parameters)
            result.status = ExecutionStatus.SUCCESS
            result.output = output
            result.evidence = evidence
        except Exception as exc:
            result.status = ExecutionStatus.FAILED
            result.error = str(exc)

        result.completed_at = datetime.utcnow()
        return result

    def execute_rollback(self, rollback_action: str, parameters: dict[str, Any]) -> StepResult:
        """Execute a rollback action for a failed step.

        Args:
            rollback_action: The rollback action type.
            parameters: Rollback-specific parameters.

        Returns:
            A StepResult for the rollback execution.
        """
        console.print(f"  [yellow]Rolling back:[/yellow] {rollback_action}")
        return self.execute(rollback_action, parameters)

    def _sim_delay(self) -> None:
        """Introduce a small delay for realistic demo output."""
        if self.demo_mode:
            time.sleep(random.uniform(*_SIM_DELAY_RANGE))

    # ── Action Handlers ──────────────────────────────────────────────

    def _action_log_event(self, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Log a security event to the incident log."""
        self._sim_delay()
        message = params.get("message", "Security event logged")
        severity = params.get("severity", "info")
        log_entry = f"[{datetime.utcnow().isoformat()}] [{severity.upper()}] {message}"

        if self.demo_mode:
            console.print(f"    [dim]{log_entry}[/dim]")

        return log_entry, {"log_entry": log_entry}

    def _action_block_ip(self, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Block an IP address at the firewall level."""
        self._sim_delay()
        ip = params.get("ip", params.get("source_ip", "unknown"))
        duration = params.get("duration", "24h")
        firewall = params.get("firewall", "iptables")

        if self.demo_mode:
            output = (
                f"[SIMULATED] Firewall rule added on {firewall}:\n"
                f"  Action: DROP\n"
                f"  Source: {ip}\n"
                f"  Duration: {duration}\n"
                f"  Rule ID: FW-{random.randint(10000, 99999)}\n"
                f"  Status: ACTIVE"
            )
            console.print(f"    [red]Blocked IP {ip}[/red] via {firewall} for {duration}")
        else:
            output = f"Blocked IP {ip} via {firewall} for {duration}"

        return output, {"blocked_ip": ip, "duration": duration, "firewall": firewall}

    def _action_isolate_host(self, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Isolate a host from the network."""
        self._sim_delay()
        host = params.get("host", params.get("hostname", "unknown"))
        method = params.get("method", "vlan_isolation")

        if self.demo_mode:
            vlan_id = random.randint(900, 999)
            output = (
                f"[SIMULATED] Host isolation executed:\n"
                f"  Host: {host}\n"
                f"  Method: {method}\n"
                f"  Quarantine VLAN: {vlan_id}\n"
                f"  Original VLAN preserved for rollback\n"
                f"  Network connections terminated: {random.randint(5, 30)}\n"
                f"  Status: ISOLATED"
            )
            console.print(f"    [red]Isolated host {host}[/red] -> Quarantine VLAN {vlan_id}")
        else:
            output = f"Isolated host {host} using {method}"

        return output, {"isolated_host": host, "method": method}

    def _action_collect_evidence(self, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Collect forensic evidence from specified sources."""
        self._sim_delay()
        evidence_type = params.get("type", "logs")
        source = params.get("source", "system")
        dest = params.get("destination", "/evidence/staging")

        if self.demo_mode:
            file_count = random.randint(3, 25)
            size_mb = round(random.uniform(1.5, 150.0), 1)
            hash_val = f"sha256:{random.randbytes(16).hex()}"
            output = (
                f"[SIMULATED] Evidence collection completed:\n"
                f"  Type: {evidence_type}\n"
                f"  Source: {source}\n"
                f"  Files collected: {file_count}\n"
                f"  Total size: {size_mb} MB\n"
                f"  Integrity hash: {hash_val}\n"
                f"  Stored at: {dest}\n"
                f"  Chain of custody: INITIATED"
            )
            console.print(
                f"    [cyan]Collected {file_count} {evidence_type} artifacts[/cyan] "
                f"({size_mb} MB) -> {dest}"
            )
        else:
            output = f"Collected {evidence_type} from {source}"
            hash_val = "n/a"

        return output, {
            "evidence_type": evidence_type,
            "source": source,
            "destination": dest,
            "integrity_hash": hash_val,
        }

    def _action_notify(self, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Send notifications to specified channels/teams."""
        self._sim_delay()
        channel = params.get("channel", "soc")
        message = params.get("message", "Incident notification")
        method = params.get("method", "email")
        recipients = params.get("recipients", [channel])

        if self.demo_mode:
            msg_id = f"MSG-{random.randint(100000, 999999)}"
            output = (
                f"[SIMULATED] Notification sent:\n"
                f"  Method: {method}\n"
                f"  Recipients: {', '.join(recipients) if isinstance(recipients, list) else recipients}\n"
                f"  Message: {message}\n"
                f"  Message ID: {msg_id}\n"
                f"  Delivery status: SENT"
            )
            console.print(
                f"    [green]Notified {channel}[/green] via {method}: {message[:60]}"
            )
        else:
            output = f"Notification sent to {channel} via {method}"
            msg_id = "n/a"

        return output, {"channel": channel, "method": method, "message_id": msg_id}

    def _action_escalate(self, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Escalate the incident to higher-tier responders."""
        self._sim_delay()
        level = params.get("level", "tier2")
        reason = params.get("reason", "Automated escalation threshold reached")
        contacts = params.get("contacts", ["incident-commander@org.local"])

        if self.demo_mode:
            ticket_id = f"ESC-{random.randint(1000, 9999)}"
            output = (
                f"[SIMULATED] Incident escalated:\n"
                f"  Level: {level}\n"
                f"  Reason: {reason}\n"
                f"  Contacts: {', '.join(contacts) if isinstance(contacts, list) else contacts}\n"
                f"  Escalation ticket: {ticket_id}\n"
                f"  SLA clock: STARTED"
            )
            console.print(
                f"    [bold yellow]Escalated to {level}[/bold yellow] - {reason}"
            )
        else:
            output = f"Escalated to {level}: {reason}"
            ticket_id = "n/a"

        return output, {"level": level, "reason": reason, "ticket_id": ticket_id}

    def _action_run_script(self, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Execute a response script on a target system."""
        self._sim_delay()
        script = params.get("script", "collect_artifacts.sh")
        target = params.get("target", "localhost")
        args = params.get("args", "")

        if self.demo_mode:
            exit_code = 0
            output = (
                f"[SIMULATED] Script execution:\n"
                f"  Script: {script}\n"
                f"  Target: {target}\n"
                f"  Arguments: {args or '(none)'}\n"
                f"  Exit code: {exit_code}\n"
                f"  Runtime: {round(random.uniform(0.5, 5.0), 2)}s\n"
                f"  Output: Script completed successfully"
            )
            console.print(f"    [blue]Executed {script}[/blue] on {target} (exit: {exit_code})")
        else:
            output = f"Executed {script} on {target}"
            exit_code = -1

        return output, {"script": script, "target": target, "exit_code": exit_code}

    def _action_disable_account(self, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Disable a user account in the directory service."""
        self._sim_delay()
        account = params.get("account", params.get("username", "unknown"))
        directory = params.get("directory", "active_directory")

        if self.demo_mode:
            output = (
                f"[SIMULATED] Account disabled:\n"
                f"  Account: {account}\n"
                f"  Directory: {directory}\n"
                f"  Active sessions terminated: {random.randint(0, 5)}\n"
                f"  Tokens revoked: {random.randint(1, 10)}\n"
                f"  Status: DISABLED"
            )
            console.print(f"    [red]Disabled account {account}[/red] in {directory}")
        else:
            output = f"Disabled account {account} in {directory}"

        return output, {"account": account, "directory": directory}

    def _action_capture_traffic(self, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Capture network traffic for analysis."""
        self._sim_delay()
        interface = params.get("interface", "eth0")
        duration = params.get("duration", "300s")
        bpf_filter = params.get("filter", "")

        if self.demo_mode:
            packets = random.randint(1000, 50000)
            pcap_size = round(random.uniform(5.0, 200.0), 1)
            pcap_path = f"/evidence/captures/capture_{random.randint(1000,9999)}.pcap"
            output = (
                f"[SIMULATED] Traffic capture completed:\n"
                f"  Interface: {interface}\n"
                f"  Duration: {duration}\n"
                f"  BPF filter: {bpf_filter or '(none)'}\n"
                f"  Packets captured: {packets}\n"
                f"  PCAP size: {pcap_size} MB\n"
                f"  Stored at: {pcap_path}"
            )
            console.print(
                f"    [cyan]Captured {packets} packets[/cyan] on {interface} ({pcap_size} MB)"
            )
        else:
            output = f"Captured traffic on {interface}"
            pcap_path = "n/a"

        return output, {"interface": interface, "pcap_path": pcap_path}

    def _action_scan_network(self, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Scan network for indicators of compromise."""
        self._sim_delay()
        target_range = params.get("range", params.get("target", "10.0.0.0/24"))
        scan_type = params.get("scan_type", "ioc_sweep")

        if self.demo_mode:
            hosts_scanned = random.randint(20, 254)
            iocs_found = random.randint(0, 3)
            output = (
                f"[SIMULATED] Network scan completed:\n"
                f"  Range: {target_range}\n"
                f"  Scan type: {scan_type}\n"
                f"  Hosts scanned: {hosts_scanned}\n"
                f"  IOCs found: {iocs_found}\n"
                f"  Clean hosts: {hosts_scanned - iocs_found}"
            )
            console.print(
                f"    [magenta]Scanned {hosts_scanned} hosts[/magenta] in {target_range} "
                f"- {iocs_found} IOCs found"
            )
        else:
            output = f"Scanned {target_range}"
            iocs_found = 0

        return output, {"target_range": target_range, "iocs_found": iocs_found}

    def _action_review_sessions(self, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Review active sessions for a user or host."""
        self._sim_delay()
        target = params.get("target", params.get("account", "unknown"))

        if self.demo_mode:
            active = random.randint(0, 8)
            suspicious = random.randint(0, min(2, active))
            output = (
                f"[SIMULATED] Session review completed:\n"
                f"  Target: {target}\n"
                f"  Active sessions: {active}\n"
                f"  Suspicious sessions: {suspicious}\n"
                f"  Geo-anomalies detected: {random.randint(0, suspicious)}"
            )
            console.print(
                f"    [yellow]Reviewed sessions for {target}[/yellow] "
                f"- {active} active, {suspicious} suspicious"
            )
        else:
            output = f"Reviewed sessions for {target}"
            suspicious = 0

        return output, {"target": target, "suspicious_sessions": suspicious}

    def _action_audit_logs(self, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Audit system and application logs for the incident timeframe."""
        self._sim_delay()
        log_source = params.get("source", "all")
        timeframe = params.get("timeframe", "24h")

        if self.demo_mode:
            entries = random.randint(500, 10000)
            anomalies = random.randint(1, 15)
            output = (
                f"[SIMULATED] Log audit completed:\n"
                f"  Source: {log_source}\n"
                f"  Timeframe: {timeframe}\n"
                f"  Entries analyzed: {entries}\n"
                f"  Anomalies flagged: {anomalies}\n"
                f"  Report generated: /evidence/audit_{random.randint(1000,9999)}.json"
            )
            console.print(
                f"    [cyan]Audited {entries} log entries[/cyan] from {log_source} "
                f"({timeframe}) - {anomalies} anomalies"
            )
        else:
            output = f"Audited logs from {log_source}"
            anomalies = 0

        return output, {"log_source": log_source, "anomalies": anomalies}

    def _action_preserve_logs(self, params: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Preserve logs to tamper-proof storage for forensic analysis."""
        self._sim_delay()
        sources = params.get("sources", ["syslog", "auth.log", "firewall"])
        destination = params.get("destination", "/evidence/preserved_logs")

        if self.demo_mode:
            total_size = round(random.uniform(50.0, 500.0), 1)
            hash_val = f"sha256:{random.randbytes(16).hex()}"
            output = (
                f"[SIMULATED] Log preservation completed:\n"
                f"  Sources: {', '.join(sources) if isinstance(sources, list) else sources}\n"
                f"  Destination: {destination}\n"
                f"  Total size: {total_size} MB\n"
                f"  Integrity hash: {hash_val}\n"
                f"  Write-protected: YES"
            )
            console.print(
                f"    [cyan]Preserved logs[/cyan] ({total_size} MB) -> {destination}"
            )
        else:
            output = f"Preserved logs to {destination}"
            hash_val = "n/a"

        return output, {"destination": destination, "integrity_hash": hash_val}
