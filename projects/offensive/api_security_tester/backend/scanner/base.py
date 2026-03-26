"""
Base scanner class and shared data models.
All scanners inherit from BaseScanner and return ScanResult objects.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"


@dataclass
class Finding:
    """A single vulnerability finding from a scan."""
    title: str
    severity: Severity
    description: str
    evidence: str          # What the scanner observed
    remediation: str       # How to fix it
    attack_explanation: str  # How an attacker exploits this


@dataclass
class ScanResult:
    """Results from one scanner module."""
    scanner: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    raw_requests: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "scanner": self.scanner,
            "target": self.target,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "attack_explanation": f.attack_explanation,
                }
                for f in self.findings
            ],
            "raw_requests": self.raw_requests,
            "error": self.error,
        }


class BaseScanner:
    """
    Base class for all scanners.

    Each scanner sends HTTP requests to the target, analyses responses,
    and returns a list of Finding objects.  The raw_requests list
    captures every request/response pair so the UI can show exactly
    what was sent — great for learning.
    """

    NAME = "base"

    def __init__(self, target: str, headers: dict[str, str], timeout: int = 10):
        self.target = target.rstrip("/")
        self.headers = headers
        self.timeout = timeout

    async def run(self) -> ScanResult:
        raise NotImplementedError
