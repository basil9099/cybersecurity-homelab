"""
Rule Loader
------------
Parses YAML rule definition files from the rules/ directory.
"""

import os
from dataclasses import dataclass, field
from typing import Any

import yaml


@dataclass
class RuleDefinition:
    """A single CIS benchmark rule definition loaded from YAML."""

    id: str
    title: str
    description: str
    severity: str
    provider: str
    resource_type: str
    check_method: str
    cis_benchmark: str
    remediation: str
    enabled: bool = True
    tags: list[str] = field(default_factory=list)


class RuleLoader:
    """Loads and filters YAML rule definitions."""

    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir

    def load_all(self) -> list[RuleDefinition]:
        """Load all rule files from the rules directory."""
        rules: list[RuleDefinition] = []
        if not os.path.isdir(self.rules_dir):
            return rules

        for filename in sorted(os.listdir(self.rules_dir)):
            if filename.endswith((".yaml", ".yml")):
                filepath = os.path.join(self.rules_dir, filename)
                rules.extend(self._load_file(filepath))
        return rules

    def load_for_provider(self, provider: str) -> list[RuleDefinition]:
        """Load rules filtered by provider name."""
        return [r for r in self.load_all() if r.provider == provider and r.enabled]

    def _load_file(self, filepath: str) -> list[RuleDefinition]:
        """Parse a single YAML rule file."""
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "rules" not in data:
            return []

        rules: list[RuleDefinition] = []
        for entry in data["rules"]:
            rules.append(RuleDefinition(
                id=entry["id"],
                title=entry["title"],
                description=entry["description"],
                severity=entry["severity"],
                provider=entry["provider"],
                resource_type=entry["resource_type"],
                check_method=entry["check_method"],
                cis_benchmark=entry["cis_benchmark"],
                remediation=entry["remediation"],
                enabled=entry.get("enabled", True),
                tags=entry.get("tags", []),
            ))
        return rules
