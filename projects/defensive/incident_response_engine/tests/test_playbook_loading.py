"""Tests for playbook YAML loading and data models."""

import tempfile
from pathlib import Path

import pytest
import yaml

from models.playbook import Playbook, TriggerCondition, PlaybookStep, EscalationPolicy
from models.alert import Alert, AlertSeverity, AlertType
from models.response import ExecutionStatus, StepResult, ResponseResult


# ── Playbook Loading ─────────────────────────────────────────────────────────

SAMPLE_PLAYBOOK_YAML = {
    "playbook": {
        "name": "Test Brute Force Response",
        "description": "Handle brute force attacks",
        "nist_phase": "containment",
        "version": "2.0",
        "author": "Test",
        "tags": ["brute_force", "automated"],
        "trigger_conditions": {
            "alert_types": ["brute_force"],
            "min_severity": "medium",
            "required_tags": [],
            "any_tags": ["ssh", "rdp"],
        },
        "steps": [
            {
                "name": "Log incident",
                "action": "log_event",
                "parameters": {"message": "Brute force detected"},
                "nist_phase": "identification",
            },
            {
                "name": "Block attacker",
                "action": "block_ip",
                "parameters": {"duration": "48h"},
                "timeout": 60,
                "rollback_action": "log_event",
                "rollback_parameters": {"message": "Rollback: unblock IP"},
                "continue_on_failure": False,
                "nist_phase": "containment",
            },
        ],
        "escalation_policy": {
            "notify_on_failure": True,
            "escalation_contacts": ["soc@example.com"],
            "escalation_threshold": 2,
            "auto_escalate_severity": ["critical"],
        },
    }
}


class TestPlaybookFromYaml:
    def test_load_valid_playbook(self, tmp_path):
        path = tmp_path / "test_playbook.yaml"
        path.write_text(yaml.dump(SAMPLE_PLAYBOOK_YAML))

        pb = Playbook.from_yaml(path)
        assert pb.name == "Test Brute Force Response"
        assert pb.version == "2.0"
        assert pb.author == "Test"
        assert len(pb.steps) == 2
        assert pb.nist_phase == "containment"

    def test_trigger_conditions_loaded(self, tmp_path):
        path = tmp_path / "test_playbook.yaml"
        path.write_text(yaml.dump(SAMPLE_PLAYBOOK_YAML))

        pb = Playbook.from_yaml(path)
        assert pb.trigger_conditions.alert_types == ["brute_force"]
        assert pb.trigger_conditions.min_severity == "medium"
        assert "ssh" in pb.trigger_conditions.any_tags

    def test_steps_loaded_with_rollback(self, tmp_path):
        path = tmp_path / "test_playbook.yaml"
        path.write_text(yaml.dump(SAMPLE_PLAYBOOK_YAML))

        pb = Playbook.from_yaml(path)
        block_step = pb.steps[1]
        assert block_step.action == "block_ip"
        assert block_step.timeout == 60
        assert block_step.rollback_action == "log_event"
        assert block_step.continue_on_failure is False

    def test_escalation_policy_loaded(self, tmp_path):
        path = tmp_path / "test_playbook.yaml"
        path.write_text(yaml.dump(SAMPLE_PLAYBOOK_YAML))

        pb = Playbook.from_yaml(path)
        assert pb.escalation_policy.notify_on_failure is True
        assert pb.escalation_policy.escalation_threshold == 2
        assert "soc@example.com" in pb.escalation_policy.escalation_contacts

    def test_to_dict_serialization(self, tmp_path):
        path = tmp_path / "test_playbook.yaml"
        path.write_text(yaml.dump(SAMPLE_PLAYBOOK_YAML))

        pb = Playbook.from_yaml(path)
        d = pb.to_dict()
        assert d["name"] == "Test Brute Force Response"
        assert d["steps_count"] == 2
        assert d["steps"][0]["action"] == "log_event"

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            Playbook.from_yaml(Path("/nonexistent/playbook.yaml"))

    def test_defaults_applied(self, tmp_path):
        minimal = {"playbook": {
            "name": "Minimal",
            "steps": [{"name": "Step 1", "action": "log_event"}],
        }}
        path = tmp_path / "minimal.yaml"
        path.write_text(yaml.dump(minimal))

        pb = Playbook.from_yaml(path)
        assert pb.version == "1.0"
        assert pb.author == "AEGIS"
        assert pb.trigger_conditions.min_severity == "low"
        assert pb.escalation_policy.escalation_threshold == 2


class TestLoadRealPlaybooks:
    """Verify the actual YAML playbooks in the repo can be loaded."""

    PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent / "playbooks"

    @pytest.mark.parametrize("filename", [
        "brute_force.yaml",
        "malware_detected.yaml",
        "data_exfiltration.yaml",
        "unauthorized_access.yaml",
    ])
    def test_real_playbook_loads(self, filename):
        path = self.PLAYBOOKS_DIR / filename
        if not path.exists():
            pytest.skip(f"{filename} not found")
        pb = Playbook.from_yaml(path)
        assert pb.name
        assert len(pb.steps) > 0
        assert pb.trigger_conditions.alert_types


# ── Alert Model ──────────────────────────────────────────────────────────────

class TestAlertModel:
    def test_alert_creation(self):
        alert = Alert(
            alert_type=AlertType.BRUTE_FORCE,
            severity=AlertSeverity.HIGH,
            source_ip="1.2.3.4",
            dest_ip="10.0.0.1",
            description="SSH brute force",
            tags=["ssh"],
        )
        assert alert.id.startswith("ALERT-")
        assert alert.alert_type == AlertType.BRUTE_FORCE

    def test_alert_to_dict_roundtrip(self):
        alert = Alert(
            alert_type=AlertType.MALWARE_DETECTED,
            severity=AlertSeverity.CRITICAL,
            source_ip="10.0.1.50",
            dest_ip="evil.example.com",
            description="Emotet C2",
            tags=["malware", "c2"],
        )
        d = alert.to_dict()
        restored = Alert.from_dict(d)
        assert restored.alert_type == alert.alert_type
        assert restored.severity == alert.severity
        assert restored.tags == alert.tags

    def test_severity_str(self):
        assert str(AlertSeverity.CRITICAL) == "critical"

    def test_alert_type_str(self):
        assert str(AlertType.BRUTE_FORCE) == "brute_force"


# ── Response Model ───────────────────────────────────────────────────────────

class TestResponseModel:
    def test_step_result_defaults(self):
        result = StepResult(step_name="test", action="log_event")
        assert result.status == ExecutionStatus.PENDING
        assert not result.error

    def test_response_result_counts(self):
        from datetime import datetime
        resp = ResponseResult(playbook_name="test", alert_id="A-1")
        resp.steps_executed.append(StepResult(
            step_name="s1", action="log_event",
            status=ExecutionStatus.SUCCESS,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        ))
        resp.steps_executed.append(StepResult(
            step_name="s2", action="block_ip",
            status=ExecutionStatus.FAILED,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
            error="timeout",
        ))
        assert resp.success_count == 1
        assert resp.failure_count == 1
