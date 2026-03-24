"""Tests for the social_recon module."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import social_recon


class TestGenerateLinkedInDorks:
    def test_returns_dorks(self):
        result = social_recon.generate_linkedin_dorks("Acme Corp")
        assert len(result["dorks"]) > 0
        assert all("linkedin.com" in d for d in result["dorks"])

    def test_includes_domain_dorks(self):
        result = social_recon.generate_linkedin_dorks("Acme", domain="acme.com")
        assert any("acme.com" in d for d in result["dorks"])


class TestGenerateEmailPatterns:
    def test_generates_patterns(self):
        emails = social_recon.generate_email_patterns("John", "Doe", "example.com")
        assert "john.doe@example.com" in emails
        assert "jdoe@example.com" in emails
        assert "john@example.com" in emails

    def test_empty_name(self):
        # Should not crash on empty first/last
        emails = social_recon.generate_email_patterns("", "", "example.com")
        assert isinstance(emails, list)


class TestInferEmailPattern:
    def test_infers_first_dot_last(self):
        known = ["john.doe@corp.com", "jane.smith@corp.com"]
        pattern = social_recon.infer_email_pattern_from_samples(known, "corp.com")
        assert pattern == "{first}.{last}"

    def test_returns_none_for_empty(self):
        assert social_recon.infer_email_pattern_from_samples([], "corp.com") is None


class TestGitHubHeaders:
    def test_no_token(self):
        headers = social_recon._gh_headers(None)
        assert "Authorization" not in headers

    def test_with_token(self):
        headers = social_recon._gh_headers("ghp_test123")
        assert headers["Authorization"] == "Bearer ghp_test123"
