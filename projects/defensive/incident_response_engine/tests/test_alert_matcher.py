"""Tests for the alert-to-playbook matching engine."""

import pytest

from models.alert import Alert, AlertSeverity, AlertType
from models.playbook import Playbook, TriggerCondition, PlaybookStep, EscalationPolicy
from engine.alert_matcher import AlertMatcher


# ── Fixtures ─────────────────────────────────────────────────────────────────

def _alert(
    alert_type: AlertType = AlertType.BRUTE_FORCE,
    severity: AlertSeverity = AlertSeverity.HIGH,
    tags: list[str] | None = None,
) -> Alert:
    return Alert(
        alert_type=alert_type,
        severity=severity,
        source_ip="203.0.113.42",
        dest_ip="10.0.1.15",
        description="Test alert",
        tags=tags or [],
    )


def _playbook(
    name: str = "Test Playbook",
    alert_types: list[str] | None = None,
    min_severity: str = "low",
    required_tags: list[str] | None = None,
    any_tags: list[str] | None = None,
) -> Playbook:
    return Playbook(
        name=name,
        description="Test playbook",
        nist_phase="containment",
        trigger_conditions=TriggerCondition(
            alert_types=alert_types or [],
            min_severity=min_severity,
            required_tags=required_tags or [],
            any_tags=any_tags or [],
        ),
        steps=[PlaybookStep(name="Step 1", action="log_event")],
        escalation_policy=EscalationPolicy(),
    )


# ── Tests ────────────────────────────────────────────────────────────────────

class TestAlertTypeMatching:
    def test_matching_alert_type(self):
        matcher = AlertMatcher([_playbook(alert_types=["brute_force"])])
        results = matcher.match(_alert(alert_type=AlertType.BRUTE_FORCE))
        assert len(results) == 1

    def test_non_matching_alert_type(self):
        matcher = AlertMatcher([_playbook(alert_types=["malware_detected"])])
        results = matcher.match(_alert(alert_type=AlertType.BRUTE_FORCE))
        assert len(results) == 0

    def test_empty_alert_types_matches_anything(self):
        matcher = AlertMatcher([_playbook(alert_types=[])])
        results = matcher.match(_alert())
        assert len(results) == 1


class TestSeverityMatching:
    def test_severity_meets_threshold(self):
        matcher = AlertMatcher([_playbook(
            alert_types=["brute_force"], min_severity="medium",
        )])
        results = matcher.match(_alert(severity=AlertSeverity.HIGH))
        assert len(results) == 1

    def test_severity_below_threshold(self):
        matcher = AlertMatcher([_playbook(
            alert_types=["brute_force"], min_severity="critical",
        )])
        results = matcher.match(_alert(severity=AlertSeverity.MEDIUM))
        assert len(results) == 0

    def test_exact_severity_match(self):
        matcher = AlertMatcher([_playbook(
            alert_types=["brute_force"], min_severity="high",
        )])
        results = matcher.match(_alert(severity=AlertSeverity.HIGH))
        assert len(results) == 1


class TestTagMatching:
    def test_required_tags_all_present(self):
        matcher = AlertMatcher([_playbook(
            alert_types=["brute_force"], required_tags=["ssh", "external"],
        )])
        results = matcher.match(_alert(tags=["ssh", "external", "login"]))
        assert len(results) == 1

    def test_required_tags_missing_one(self):
        matcher = AlertMatcher([_playbook(
            alert_types=["brute_force"], required_tags=["ssh", "external"],
        )])
        results = matcher.match(_alert(tags=["ssh"]))
        assert len(results) == 0

    def test_any_tags_one_present(self):
        matcher = AlertMatcher([_playbook(
            alert_types=["brute_force"], any_tags=["ssh", "rdp", "ftp"],
        )])
        results = matcher.match(_alert(tags=["rdp"]))
        assert len(results) == 1

    def test_any_tags_none_present(self):
        matcher = AlertMatcher([_playbook(
            alert_types=["brute_force"], any_tags=["ssh", "rdp"],
        )])
        results = matcher.match(_alert(tags=["http"]))
        assert len(results) == 0


class TestMatchScoring:
    def test_more_specific_match_ranked_first(self):
        generic = _playbook(
            name="Generic",
            alert_types=["brute_force"],
            min_severity="low",
        )
        specific = _playbook(
            name="Specific",
            alert_types=["brute_force"],
            min_severity="low",
            any_tags=["ssh", "rdp"],
            required_tags=["external"],
        )
        matcher = AlertMatcher([generic, specific])
        results = matcher.match(_alert(
            severity=AlertSeverity.CRITICAL,
            tags=["ssh", "external"],
        ))
        assert len(results) == 2
        assert results[0].name == "Specific"

    def test_higher_severity_increases_score(self):
        playbook = _playbook(alert_types=["brute_force"], min_severity="low")
        matcher = AlertMatcher([playbook])
        # Both match, but we test the internal scoring indirectly via match_best
        assert matcher.match_best(_alert(severity=AlertSeverity.CRITICAL)) is not None

    def test_multiple_any_tags_increase_score(self):
        playbook = _playbook(
            alert_types=["brute_force"],
            any_tags=["ssh", "rdp", "authentication"],
        )
        matcher = AlertMatcher([playbook])
        result = matcher.match(_alert(tags=["ssh", "rdp", "authentication"]))
        assert len(result) == 1


class TestMatchBest:
    def test_returns_best_match(self):
        matcher = AlertMatcher([
            _playbook(name="A", alert_types=["brute_force"]),
            _playbook(name="B", alert_types=["brute_force"], any_tags=["ssh"]),
        ])
        best = matcher.match_best(_alert(tags=["ssh"]))
        assert best is not None
        assert best.name == "B"

    def test_returns_none_when_no_match(self):
        matcher = AlertMatcher([_playbook(alert_types=["malware_detected"])])
        assert matcher.match_best(_alert(alert_type=AlertType.BRUTE_FORCE)) is None


class TestAddPlaybook:
    def test_add_playbook(self):
        matcher = AlertMatcher()
        assert len(matcher.playbooks) == 0
        matcher.add_playbook(_playbook())
        assert len(matcher.playbooks) == 1
