"""
Rules Evaluator
----------------
Connects rule definitions to scanner check methods and computes
compliance scores.
"""

from dataclasses import dataclass, field
from typing import Any

from .rule_loader import RuleDefinition
from scanner.base_scanner import BaseScanner, Finding


@dataclass
class ComplianceScore:
    """Compliance score for a provider or category."""

    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0

    @property
    def percentage(self) -> float:
        denominator = self.passed + self.failed
        if denominator == 0:
            return 0.0
        return (self.passed / denominator) * 100


@dataclass
class ScanReport:
    """Aggregated results from a cloud security scan."""

    findings: list[Finding] = field(default_factory=list)
    provider_scores: dict[str, ComplianceScore] = field(default_factory=dict)
    overall_score: ComplianceScore = field(default_factory=ComplianceScore)
    metadata: dict[str, Any] = field(default_factory=dict)


class Evaluator:
    """Runs scanner checks based on rule definitions and computes scores."""

    def evaluate(
        self,
        scanner: BaseScanner,
        rules: list[RuleDefinition],
    ) -> list[Finding]:
        """Run all enabled rules against the given scanner."""
        findings: list[Finding] = []

        for rule in rules:
            if not rule.enabled:
                continue

            method = getattr(scanner, rule.check_method, None)
            if method is None:
                findings.append(Finding(
                    rule_id=rule.id,
                    provider=rule.provider,
                    resource_type=rule.resource_type,
                    resource_id="N/A",
                    region="N/A",
                    severity=rule.severity,
                    status="ERROR",
                    title=rule.title,
                    description=f"Check method '{rule.check_method}' not found",
                    remediation=rule.remediation,
                    cis_benchmark=rule.cis_benchmark,
                ))
                continue

            method()

        findings.extend(scanner.findings)
        return findings

    @staticmethod
    def compute_scores(findings: list[Finding]) -> ScanReport:
        """Compute compliance scores from a list of findings."""
        report = ScanReport(findings=findings)

        for finding in findings:
            provider = finding.provider

            if provider not in report.provider_scores:
                report.provider_scores[provider] = ComplianceScore()

            score = report.provider_scores[provider]
            overall = report.overall_score

            score.total_checks += 1
            overall.total_checks += 1

            if finding.status == "PASS":
                score.passed += 1
                overall.passed += 1
            elif finding.status == "FAIL":
                score.failed += 1
                overall.failed += 1
            else:
                score.errors += 1
                overall.errors += 1

        return report
