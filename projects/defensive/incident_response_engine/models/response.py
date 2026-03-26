"""Response and execution result data models."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ExecutionStatus(str, Enum):
    """Execution status for steps and overall playbook runs."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"
    ESCALATED = "escalated"

    def __str__(self) -> str:
        return self.value


@dataclass
class StepResult:
    """Result of executing a single playbook step.

    Attributes:
        step_name: Name of the step that was executed.
        action: Action type that was performed.
        status: Execution status.
        started_at: When execution started.
        completed_at: When execution completed.
        output: Output produced by the action.
        error: Error message if the step failed.
        nist_phase: NIST 800-61 phase for this step.
        evidence: Any evidence collected during this step.
    """

    step_name: str
    action: str
    status: ExecutionStatus = ExecutionStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    output: str = ""
    error: str = ""
    nist_phase: str = "containment"
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        """Calculate the duration of this step in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize step result to a dictionary."""
        return {
            "step_name": self.step_name,
            "action": self.action,
            "status": str(self.status),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "output": self.output,
            "error": self.error,
            "nist_phase": self.nist_phase,
            "evidence": self.evidence,
        }


@dataclass
class ResponseResult:
    """Complete result of a playbook execution against an alert.

    Attributes:
        id: Unique response identifier.
        playbook_name: Name of the playbook that was executed.
        alert_id: ID of the alert that triggered this response.
        status: Overall execution status.
        started_at: When the playbook execution started.
        completed_at: When the playbook execution completed.
        steps_executed: List of individual step results.
        evidence_collected: Aggregated evidence from all steps.
        escalated: Whether the incident was escalated.
        escalation_reason: Reason for escalation, if applicable.
    """

    playbook_name: str
    alert_id: str
    id: str = field(default_factory=lambda: f"RESP-{uuid.uuid4().hex[:8].upper()}")
    status: ExecutionStatus = ExecutionStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    steps_executed: list[StepResult] = field(default_factory=list)
    evidence_collected: list[dict[str, Any]] = field(default_factory=list)
    escalated: bool = False
    escalation_reason: str = ""

    @property
    def duration_seconds(self) -> float:
        """Calculate total execution duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0.0

    @property
    def timeline(self) -> list[dict[str, Any]]:
        """Generate an ordered timeline of all step executions."""
        entries: list[dict[str, Any]] = []
        for step in self.steps_executed:
            entries.append(
                {
                    "timestamp": step.started_at.isoformat() if step.started_at else "",
                    "event": f"Step started: {step.step_name}",
                    "nist_phase": step.nist_phase,
                    "status": str(step.status),
                }
            )
            entries.append(
                {
                    "timestamp": step.completed_at.isoformat() if step.completed_at else "",
                    "event": f"Step completed: {step.step_name}",
                    "nist_phase": step.nist_phase,
                    "status": str(step.status),
                }
            )
        return entries

    @property
    def success_count(self) -> int:
        """Count of successfully completed steps."""
        return sum(1 for s in self.steps_executed if s.status == ExecutionStatus.SUCCESS)

    @property
    def failure_count(self) -> int:
        """Count of failed steps."""
        return sum(1 for s in self.steps_executed if s.status == ExecutionStatus.FAILED)

    def to_dict(self) -> dict[str, Any]:
        """Serialize response result to a dictionary."""
        return {
            "id": self.id,
            "playbook_name": self.playbook_name,
            "alert_id": self.alert_id,
            "status": str(self.status),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "steps_executed": [s.to_dict() for s in self.steps_executed],
            "evidence_collected": self.evidence_collected,
            "timeline": self.timeline,
            "escalated": self.escalated,
            "escalation_reason": self.escalation_reason,
            "summary": {
                "total_steps": len(self.steps_executed),
                "successful": self.success_count,
                "failed": self.failure_count,
            },
        }
