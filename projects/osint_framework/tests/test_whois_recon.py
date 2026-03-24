"""Tests for the whois_recon module."""

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import whois_recon


class TestExtractEmailsFromWhois:
    def test_extracts_emails_from_raw(self):
        result = {
            "raw": "Registrant Email: admin@example.com\nTech: tech@example.com",
            "parsed": {},
        }
        emails = whois_recon.extract_emails_from_whois(result)
        assert "admin@example.com" in emails
        assert "tech@example.com" in emails

    def test_extracts_from_parsed_fields(self):
        result = {
            "raw": "",
            "parsed": {"registrant_email": "user@example.org"},
        }
        emails = whois_recon.extract_emails_from_whois(result)
        assert "user@example.org" in emails

    def test_empty_whois(self):
        assert whois_recon.extract_emails_from_whois({"raw": "", "parsed": {}}) == []


class TestExtractHostingHints:
    def test_detects_cloudflare(self):
        result = {
            "parsed": {"name_servers": ["a.ns.cloudflare.com", "b.ns.cloudflare.com"]},
        }
        whois_recon._extract_hosting_hints(result)
        assert "Cloudflare" in result["parsed"]["hosting_hints"]

    def test_detects_aws(self):
        result = {
            "parsed": {"name_servers": ["ns-100.awsdns-12.com", "ns-200.awsdns-34.net"]},
        }
        whois_recon._extract_hosting_hints(result)
        assert "AWS Route 53" in result["parsed"]["hosting_hints"]

    def test_no_hints_for_unknown(self):
        result = {"parsed": {"name_servers": ["ns1.unknown-provider.net"]}}
        whois_recon._extract_hosting_hints(result)
        assert "hosting_hints" not in result["parsed"]


class TestIsIP:
    def test_ipv4(self):
        assert whois_recon._is_ip("1.2.3.4") is True

    def test_ipv6(self):
        assert whois_recon._is_ip("::1") is True

    def test_domain(self):
        assert whois_recon._is_ip("example.com") is False


class TestQueryDomainWhoisGraceful:
    """Test graceful degradation when libraries are unavailable."""

    @patch("modules.whois_recon.WHOIS_AVAILABLE", False)
    @patch("modules.whois_recon.REQUESTS_AVAILABLE", False)
    def test_returns_error_when_no_libs(self):
        result = whois_recon.query_domain_whois("example.com")
        assert result["errors"]
        assert result["parsed"] == {}
