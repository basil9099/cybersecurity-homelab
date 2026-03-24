"""Tests for the reporter module."""

import json
import os
import stat
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import reporter


def _minimal_profile():
    """Return a minimal but valid profile for testing report generation."""
    return {
        "meta": {
            "target": "example.com",
            "generated_at": "2025-01-01T00:00:00Z",
            "framework": "OSINT-Framework v1.0",
        },
        "organisation": {"domain": "example.com", "registrar": "TestRegistrar"},
        "infrastructure": {
            "dns": {
                "records": {"A": ["1.2.3.4"]},
                "nameservers": ["ns1.example.com"],
                "mx_servers": [{"priority": 10, "host": "mail.example.com"}],
                "email_security": {"spf": "v=spf1 ~all"},
                "zone_transfer": {"attempted": True, "success": False},
            },
            "subdomains": [{"subdomain": "www.example.com", "A": ["1.2.3.4"], "AAAA": [], "CNAME": []}],
            "services": [],
            "certificates": ["api.example.com"],
        },
        "people": {
            "github_members": [{"login": "user1", "html_url": "https://github.com/user1"}],
            "email_candidates": ["admin@example.com"],
            "linkedin_dorks": [],
        },
        "breach_exposure": {"summary": {}, "detail": []},
        "historical": {"wayback_snapshots": [], "archived_urls": []},
        "recon_dorks": {},
        "risk_assessment": {
            "overall_risk": "LOW",
            "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 1},
            "findings": [{"severity": "INFO", "category": "Test", "description": "test finding"}],
        },
        "relationships": [{"from": "example.com", "to": "ns1.example.com", "type": "nameserver"}],
    }


class TestBuildTargetProfile:
    def test_basic_profile_creation(self):
        profile = reporter.build_target_profile("example.com")
        assert profile["meta"]["target"] == "example.com"
        assert "risk_assessment" in profile
        assert "relationships" in profile

    def test_profile_includes_whois(self):
        whois = {"parsed": {"registrar": "TestReg", "domain_name": "example.com"}, "errors": []}
        profile = reporter.build_target_profile("example.com", whois_result=whois)
        assert profile["organisation"]["registrar"] == "TestReg"


class TestBuildRiskAssessment:
    def test_zone_transfer_critical(self):
        profile = _minimal_profile()
        profile["infrastructure"]["dns"]["zone_transfer"] = {"success": True, "nameserver": "ns1.example.com"}
        risk = reporter._build_risk_assessment(profile)
        assert risk["overall_risk"] == "CRITICAL"
        assert risk["counts"]["CRITICAL"] >= 1

    def test_missing_spf_high(self):
        profile = _minimal_profile()
        profile["infrastructure"]["dns"]["email_security"] = {}
        risk = reporter._build_risk_assessment(profile)
        assert risk["counts"]["HIGH"] >= 1

    def test_low_risk_with_full_email_security(self):
        profile = _minimal_profile()
        # Add DMARC so email security doesn't trigger HIGH
        profile["infrastructure"]["dns"]["email_security"] = {
            "spf": "v=spf1 ~all",
            "dmarc": "v=DMARC1; p=reject",
            "dmarc_policy": "reject",
        }
        risk = reporter._build_risk_assessment(profile)
        assert risk["overall_risk"] in ("LOW", "MEDIUM")


class TestBuildRelationships:
    def test_creates_edges(self):
        profile = _minimal_profile()
        edges = reporter._build_relationships(profile)
        types = [e["type"] for e in edges]
        assert "nameserver" in types
        assert "mail_server" in types


class TestGenerateJSONReport:
    def test_valid_json_output(self, tmp_path):
        profile = _minimal_profile()
        out = tmp_path / "report.json"
        reporter.generate_json_report(profile, str(out))
        data = json.loads(out.read_text())
        assert data["meta"]["target"] == "example.com"

    def test_file_permissions(self, tmp_path):
        profile = _minimal_profile()
        out = tmp_path / "report.json"
        reporter.generate_json_report(profile, str(out))
        mode = stat.S_IMODE(os.stat(str(out)).st_mode)
        assert mode == 0o600


class TestGenerateTextReport:
    def test_contains_target(self, tmp_path):
        profile = _minimal_profile()
        out = tmp_path / "report.txt"
        reporter.generate_text_report(profile, str(out))
        text = out.read_text()
        assert "example.com" in text
        assert "OSINT RECONNAISSANCE REPORT" in text

    def test_file_permissions(self, tmp_path):
        profile = _minimal_profile()
        out = tmp_path / "report.txt"
        reporter.generate_text_report(profile, str(out))
        mode = stat.S_IMODE(os.stat(str(out)).st_mode)
        assert mode == 0o600


class TestGenerateHTMLReport:
    def test_valid_html(self, tmp_path):
        profile = _minimal_profile()
        out = tmp_path / "report.html"
        reporter.generate_html_report(profile, str(out))
        html = out.read_text()
        assert "<!DOCTYPE html>" in html
        assert "example.com" in html

    def test_file_permissions(self, tmp_path):
        profile = _minimal_profile()
        out = tmp_path / "report.html"
        reporter.generate_html_report(profile, str(out))
        mode = stat.S_IMODE(os.stat(str(out)).st_mode)
        assert mode == 0o600


class TestGenerateAllReports:
    def test_generates_three_formats(self, tmp_path):
        profile = _minimal_profile()
        paths = reporter.generate_all_reports(profile, str(tmp_path))
        assert "json" in paths
        assert "text" in paths
        assert "html" in paths
        for fmt, path in paths.items():
            assert os.path.isfile(path)
