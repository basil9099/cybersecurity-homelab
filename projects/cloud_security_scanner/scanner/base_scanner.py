"""
Base Scanner Module
-------------------
Defines the Finding dataclass and BaseScanner abstract base class
that all cloud provider scanners inherit from.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Finding:
    """A single security finding from a cloud scan."""

    rule_id: str
    provider: str
    resource_type: str
    resource_id: str
    region: str
    severity: str          # critical, high, medium, low, info
    status: str            # PASS, FAIL, ERROR
    title: str
    description: str
    remediation: str
    cis_benchmark: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BaseScanner(ABC):
    """Abstract base class for cloud provider scanners."""

    PROVIDER: str = ""

    def __init__(self, regions: list[str] | None = None, demo_mode: bool = False):
        self.regions = regions or self.default_regions()
        self.demo_mode = demo_mode
        self.findings: list[Finding] = []

    @abstractmethod
    def default_regions(self) -> list[str]:
        ...

    @abstractmethod
    def authenticate(self) -> bool:
        ...

    def run_all_checks(self) -> list[Finding]:
        """Discover and run all check_* methods via introspection."""
        self.findings = []
        for name in sorted(dir(self)):
            if name.startswith("check_") and callable(getattr(self, name)):
                getattr(self, name)()
        return self.findings

    def add_finding(self, **kwargs: Any) -> None:
        kwargs.setdefault("provider", self.PROVIDER)
        self.findings.append(Finding(**kwargs))
