"""Alert matcher that maps incoming alerts to applicable playbooks.

Matching is based on alert type, severity, and tags as defined
in each playbook's trigger conditions.
"""

from __future__ import annotations

from models.alert import Alert, AlertSeverity
from models.playbook import Playbook

# Severity ordering for comparison
_SEVERITY_ORDER: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


class AlertMatcher:
    """Matches incoming security alerts to applicable playbooks.

    The matcher evaluates each playbook's trigger conditions against
    the alert properties. A playbook matches if:
      1. The alert type is in the playbook's alert_types list.
      2. The alert severity meets or exceeds the playbook's min_severity.
      3. All required_tags are present on the alert.
      4. At least one any_tags tag is present (if any_tags is specified).

    Attributes:
        playbooks: List of loaded playbooks to match against.
    """

    def __init__(self, playbooks: list[Playbook] | None = None) -> None:
        self.playbooks: list[Playbook] = playbooks or []

    def add_playbook(self, playbook: Playbook) -> None:
        """Register a playbook for matching.

        Args:
            playbook: The playbook to add to the matcher.
        """
        self.playbooks.append(playbook)

    def match(self, alert: Alert) -> list[Playbook]:
        """Find all playbooks that match the given alert.

        Args:
            alert: The incoming alert to match.

        Returns:
            A list of matching playbooks, ordered by specificity
            (most specific match first).
        """
        matches: list[tuple[int, Playbook]] = []

        for playbook in self.playbooks:
            score = self._evaluate_match(alert, playbook)
            if score > 0:
                matches.append((score, playbook))

        # Sort by match score descending (most specific first)
        matches.sort(key=lambda m: m[0], reverse=True)
        return [playbook for _, playbook in matches]

    def match_best(self, alert: Alert) -> Playbook | None:
        """Find the single best-matching playbook for an alert.

        Args:
            alert: The incoming alert to match.

        Returns:
            The best matching playbook, or None if no match is found.
        """
        results = self.match(alert)
        return results[0] if results else None

    def _evaluate_match(self, alert: Alert, playbook: Playbook) -> int:
        """Evaluate the match score between an alert and a playbook.

        Args:
            alert: The alert to evaluate.
            playbook: The playbook to evaluate against.

        Returns:
            A positive integer score if matched, 0 if not matched.
            Higher scores indicate more specific matches.
        """
        trigger = playbook.trigger_conditions
        score = 0

        # Check alert type match (required)
        if trigger.alert_types:
            if str(alert.alert_type) not in trigger.alert_types:
                return 0
            score += 10

        # Check severity threshold
        alert_level = _SEVERITY_ORDER.get(str(alert.severity), 0)
        min_level = _SEVERITY_ORDER.get(trigger.min_severity, 0)
        if alert_level < min_level:
            return 0
        # Bonus for higher severity
        score += alert_level

        # Check required tags (all must be present)
        if trigger.required_tags:
            if not all(tag in alert.tags for tag in trigger.required_tags):
                return 0
            score += len(trigger.required_tags) * 2

        # Check any_tags (at least one must be present, if specified)
        if trigger.any_tags:
            if not any(tag in alert.tags for tag in trigger.any_tags):
                return 0
            matching_count = sum(1 for tag in trigger.any_tags if tag in alert.tags)
            score += matching_count

        return score
