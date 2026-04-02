"""Tests for MITRE ATT&CK mappings."""

from mappings.mitre_attack import (
    TACTIC_ORDER,
    ALERT_MAPPINGS,
    DEFAULT_MAPPING,
    map_alert,
    tactic_stage,
    is_progression,
)


class TestTacticOrder:
    def test_all_14_tactics_present(self):
        assert len(TACTIC_ORDER) == 14

    def test_stages_are_sequential(self):
        stages = sorted(TACTIC_ORDER.values())
        assert stages == list(range(1, 15))

    def test_reconnaissance_is_first(self):
        assert TACTIC_ORDER["reconnaissance"] == 1

    def test_impact_is_last(self):
        assert TACTIC_ORDER["impact"] == 14


class TestTacticStage:
    def test_known_tactic(self):
        assert tactic_stage("discovery") == 9

    def test_unknown_tactic_returns_zero(self):
        assert tactic_stage("nonexistent") == 0


class TestIsProgression:
    def test_forward_progression(self):
        assert is_progression("reconnaissance", "initial_access") is True

    def test_backward_is_not_progression(self):
        assert is_progression("exfiltration", "discovery") is False

    def test_same_tactic_not_progression(self):
        assert is_progression("discovery", "discovery") is False


class TestMapAlert:
    def test_known_mapping(self):
        result = map_alert("network_baseline", "port_scan")
        assert "T1046" in result.technique_ids
        assert result.tactic == "discovery"

    def test_unknown_mapping_returns_default(self):
        result = map_alert("unknown_source", "unknown_type")
        assert result == DEFAULT_MAPPING

    def test_all_mappings_have_valid_tactics(self):
        for key, mapping in ALERT_MAPPINGS.items():
            assert mapping.tactic in TACTIC_ORDER, (
                f"Mapping {key} has invalid tactic: {mapping.tactic}"
            )

    def test_all_mappings_have_technique_ids(self):
        for key, mapping in ALERT_MAPPINGS.items():
            assert len(mapping.technique_ids) > 0, (
                f"Mapping {key} has no technique IDs"
            )
