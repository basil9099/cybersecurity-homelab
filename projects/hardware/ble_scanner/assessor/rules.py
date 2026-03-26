"""
Security Assessment Engine
--------------------------
Loads rules from config and dispatches checks against a DeviceProfile.
Uses introspection to discover check_* functions in checks.py.
"""

from __future__ import annotations

import importlib
from typing import Any

from models import DeviceProfile, SecurityFinding, AssessmentReport, BLEDevice
from config import Config, AssessmentRule


class SecurityAssessor:
    """Run security assessment rules against a BLE device profile."""

    def __init__(self, config: Config):
        self.config = config
        self._checks = self._load_checks()

    def _load_checks(self) -> dict[str, Any]:
        """Discover all check_* functions from the checks module."""
        mod = importlib.import_module("assessor.checks")
        checks: dict[str, Any] = {}
        for name in sorted(dir(mod)):
            if name.startswith("check_") and callable(getattr(mod, name)):
                checks[name] = getattr(mod, name)
        return checks

    def assess(self, profile: DeviceProfile) -> list[SecurityFinding]:
        """Run all enabled assessment rules against the device profile.

        Returns:
            List of SecurityFinding instances.
        """
        all_findings: list[SecurityFinding] = []

        for rule in self.config.assessment_rules:
            if not rule.enabled:
                continue

            check_fn = self._checks.get(rule.check)
            if check_fn is None:
                continue

            # Build extra kwargs for checks that need config data
            kwargs: dict[str, Any] = {}
            if rule.check == "check_sensitive_data_exposure":
                kwargs["sensitive_patterns"] = self.config.sensitive_data_patterns
            elif rule.check == "check_known_vulnerable_uuids":
                kwargs["known_vulnerable"] = self.config.known_vulnerable_uuids

            findings = check_fn(profile, rule, **kwargs)
            all_findings.extend(findings)

        return all_findings

    @staticmethod
    def compute_risk_score(findings: list[SecurityFinding]) -> float:
        """Compute a weighted risk score from findings, capped at 10.0.

        Weights: critical=4, high=3, medium=2, low=1, info=0
        """
        weights = {
            "critical": 4.0,
            "high": 3.0,
            "medium": 2.0,
            "low": 1.0,
            "info": 0.0,
        }
        total = sum(weights.get(f.severity, 0) for f in findings)
        return min(total, 10.0)

    def full_assessment(
        self,
        profile: DeviceProfile,
        scan_time: str = "",
    ) -> AssessmentReport:
        """Run assessment and return a complete report."""
        findings = self.assess(profile)
        risk_score = self.compute_risk_score(findings)

        return AssessmentReport(
            target=profile.device,
            profile=profile,
            findings=findings,
            risk_score=risk_score,
            scan_time=scan_time,
            metadata={
                "tool": "PHANTOM",
                "rules_evaluated": len([r for r in self.config.assessment_rules if r.enabled]),
                "findings_count": len(findings),
            },
        )
