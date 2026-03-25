"""Playbook data model loaded from YAML definitions."""

from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TriggerCondition:
    """Defines when a playbook should be activated.

    Attributes:
        alert_types: List of alert types that trigger this playbook.
        min_severity: Minimum severity level required to trigger.
        required_tags: Tags that must be present on the alert.
        any_tags: Tags where at least one must be present (optional).
    """

    alert_types: list[str] = field(default_factory=list)
    min_severity: str = "low"
    required_tags: list[str] = field(default_factory=list)
    any_tags: list[str] = field(default_factory=list)


@dataclass
class PlaybookStep:
    """A single step in a playbook's response workflow.

    Attributes:
        name: Human-readable step name.
        action: Action type to execute (e.g., block_ip, isolate_host).
        parameters: Parameters passed to the action executor.
        timeout: Maximum execution time in seconds.
        rollback_action: Action to execute if this step fails.
        continue_on_failure: Whether to proceed if this step fails.
        nist_phase: NIST 800-61 phase this step maps to.
    """

    name: str
    action: str
    parameters: dict[str, Any] = field(default_factory=dict)
    timeout: int = 300
    rollback_action: str | None = None
    rollback_parameters: dict[str, Any] = field(default_factory=dict)
    continue_on_failure: bool = False
    nist_phase: str = "containment"


@dataclass
class EscalationPolicy:
    """Defines escalation rules when automated response is insufficient.

    Attributes:
        notify_on_failure: Whether to send notifications on step failure.
        escalation_contacts: Contacts to notify during escalation.
        escalation_threshold: Number of failed steps before escalating.
        auto_escalate_severity: Severity levels that always escalate.
    """

    notify_on_failure: bool = True
    escalation_contacts: list[str] = field(default_factory=list)
    escalation_threshold: int = 2
    auto_escalate_severity: list[str] = field(default_factory=lambda: ["critical"])


@dataclass
class Playbook:
    """An incident response playbook loaded from a YAML definition.

    Attributes:
        name: Playbook display name.
        description: Detailed description of the playbook's purpose.
        nist_phase: Primary NIST 800-61 phase this playbook addresses.
        trigger_conditions: Conditions that activate this playbook.
        steps: Ordered list of response steps.
        escalation_policy: Rules for escalation handling.
        version: Playbook version string.
        author: Playbook author.
        tags: Classification tags for the playbook.
    """

    name: str
    description: str
    nist_phase: str
    trigger_conditions: TriggerCondition
    steps: list[PlaybookStep]
    escalation_policy: EscalationPolicy
    version: str = "1.0"
    author: str = "AEGIS"
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: Path) -> Playbook:
        """Load a playbook from a YAML file.

        Args:
            path: Path to the YAML playbook file.

        Returns:
            A fully initialized Playbook instance.

        Raises:
            FileNotFoundError: If the YAML file does not exist.
            yaml.YAMLError: If the YAML is malformed.
            KeyError: If required fields are missing.
        """
        with open(path, "r") as f:
            data = yaml.safe_load(f)

        playbook_data = data.get("playbook", data)

        trigger_data = playbook_data.get("trigger_conditions", {})
        trigger = TriggerCondition(
            alert_types=trigger_data.get("alert_types", []),
            min_severity=trigger_data.get("min_severity", "low"),
            required_tags=trigger_data.get("required_tags", []),
            any_tags=trigger_data.get("any_tags", []),
        )

        steps = []
        for step_data in playbook_data.get("steps", []):
            steps.append(
                PlaybookStep(
                    name=step_data["name"],
                    action=step_data["action"],
                    parameters=step_data.get("parameters", {}),
                    timeout=step_data.get("timeout", 300),
                    rollback_action=step_data.get("rollback_action"),
                    rollback_parameters=step_data.get("rollback_parameters", {}),
                    continue_on_failure=step_data.get("continue_on_failure", False),
                    nist_phase=step_data.get("nist_phase", "containment"),
                )
            )

        esc_data = playbook_data.get("escalation_policy", {})
        escalation = EscalationPolicy(
            notify_on_failure=esc_data.get("notify_on_failure", True),
            escalation_contacts=esc_data.get("escalation_contacts", []),
            escalation_threshold=esc_data.get("escalation_threshold", 2),
            auto_escalate_severity=esc_data.get(
                "auto_escalate_severity", ["critical"]
            ),
        )

        return cls(
            name=playbook_data["name"],
            description=playbook_data.get("description", ""),
            nist_phase=playbook_data.get("nist_phase", "containment"),
            trigger_conditions=trigger,
            steps=steps,
            escalation_policy=escalation,
            version=playbook_data.get("version", "1.0"),
            author=playbook_data.get("author", "AEGIS"),
            tags=playbook_data.get("tags", []),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize playbook to a dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "nist_phase": self.nist_phase,
            "version": self.version,
            "author": self.author,
            "tags": self.tags,
            "steps_count": len(self.steps),
            "steps": [
                {"name": s.name, "action": s.action, "nist_phase": s.nist_phase}
                for s in self.steps
            ],
        }
