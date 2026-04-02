"""Tests for the incident response action executor."""

import pytest

from engine.action_executor import ActionExecutor
from models.response import ExecutionStatus


@pytest.fixture
def executor():
    """Create an executor in demo mode with delays disabled."""
    ex = ActionExecutor(demo_mode=True)
    # Monkey-patch out sleep for fast tests
    ex._sim_delay = lambda: None
    return ex


class TestExecuteAction:
    def test_known_action_succeeds(self, executor):
        result = executor.execute("log_event", {"message": "test"})
        assert result.status == ExecutionStatus.SUCCESS
        assert result.output is not None
        assert result.completed_at is not None

    def test_unknown_action_fails(self, executor):
        result = executor.execute("nonexistent_action", {})
        assert result.status == ExecutionStatus.FAILED
        assert "Unknown action type" in result.error

    def test_step_name_from_params(self, executor):
        result = executor.execute("log_event", {"step_name": "Custom Name"})
        assert result.step_name == "Custom Name"

    def test_nist_phase_from_params(self, executor):
        result = executor.execute("log_event", {"nist_phase": "identification"})
        assert result.nist_phase == "identification"


class TestBlockIP:
    def test_block_ip_returns_evidence(self, executor):
        result = executor.execute("block_ip", {
            "ip": "203.0.113.42",
            "duration": "48h",
            "firewall": "pfsense",
        })
        assert result.status == ExecutionStatus.SUCCESS
        assert result.evidence["blocked_ip"] == "203.0.113.42"
        assert result.evidence["duration"] == "48h"

    def test_block_ip_fallback_to_source_ip(self, executor):
        result = executor.execute("block_ip", {"source_ip": "10.0.0.1"})
        assert result.evidence["blocked_ip"] == "10.0.0.1"


class TestIsolateHost:
    def test_isolate_host_evidence(self, executor):
        result = executor.execute("isolate_host", {"host": "WS-FIN-012"})
        assert result.status == ExecutionStatus.SUCCESS
        assert result.evidence["isolated_host"] == "WS-FIN-012"


class TestCollectEvidence:
    def test_collect_evidence_returns_hash(self, executor):
        result = executor.execute("collect_evidence", {
            "type": "disk_image",
            "source": "WS-FIN-012",
        })
        assert result.status == ExecutionStatus.SUCCESS
        assert "sha256:" in result.evidence["integrity_hash"]
        assert result.evidence["evidence_type"] == "disk_image"


class TestNotify:
    def test_notify_returns_message_id(self, executor):
        result = executor.execute("notify", {
            "channel": "soc",
            "message": "Incident detected",
            "method": "slack",
        })
        assert result.status == ExecutionStatus.SUCCESS
        assert result.evidence["channel"] == "soc"
        assert result.evidence["method"] == "slack"


class TestEscalate:
    def test_escalate_returns_ticket(self, executor):
        result = executor.execute("escalate", {
            "level": "tier3",
            "reason": "Critical severity",
        })
        assert result.status == ExecutionStatus.SUCCESS
        assert result.evidence["level"] == "tier3"
        assert "ESC-" in result.evidence["ticket_id"]


class TestDisableAccount:
    def test_disable_account(self, executor):
        result = executor.execute("disable_account", {"account": "jdoe"})
        assert result.status == ExecutionStatus.SUCCESS
        assert result.evidence["account"] == "jdoe"


class TestCaptureTraffic:
    def test_capture_traffic(self, executor):
        result = executor.execute("capture_traffic", {
            "interface": "eth0",
            "duration": "60s",
        })
        assert result.status == ExecutionStatus.SUCCESS
        assert result.evidence["interface"] == "eth0"


class TestScanNetwork:
    def test_scan_network(self, executor):
        result = executor.execute("scan_network", {
            "range": "10.0.0.0/24",
            "scan_type": "ioc_sweep",
        })
        assert result.status == ExecutionStatus.SUCCESS
        assert result.evidence["target_range"] == "10.0.0.0/24"


class TestAuditLogs:
    def test_audit_logs(self, executor):
        result = executor.execute("audit_logs", {
            "source": "auth.log",
            "timeframe": "6h",
        })
        assert result.status == ExecutionStatus.SUCCESS
        assert result.evidence["log_source"] == "auth.log"


class TestPreserveLogs:
    def test_preserve_logs(self, executor):
        result = executor.execute("preserve_logs", {
            "sources": ["syslog", "auth.log"],
        })
        assert result.status == ExecutionStatus.SUCCESS
        assert "sha256:" in result.evidence["integrity_hash"]


class TestAllActions:
    """Verify every registered action can execute without error."""

    def test_all_registered_actions_succeed(self, executor):
        for action_name in executor._action_handlers:
            result = executor.execute(action_name, {})
            assert result.status == ExecutionStatus.SUCCESS, (
                f"Action '{action_name}' failed: {result.error}"
            )


class TestRollback:
    def test_rollback_calls_execute(self, executor):
        result = executor.execute_rollback("log_event", {"message": "rollback"})
        assert result.status == ExecutionStatus.SUCCESS
