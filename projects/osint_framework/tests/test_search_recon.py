"""Tests for the search_recon module."""

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import search_recon


class TestGenerateReconDorks:
    def test_returns_all_categories(self):
        dorks = search_recon.generate_recon_dorks("example.com")
        assert "general" in dorks
        assert "sensitive_files" in dorks
        assert "admin_panels" in dorks

    def test_dorks_contain_domain(self):
        dorks = search_recon.generate_recon_dorks("target.org")
        for category, queries in dorks.items():
            for q in queries:
                assert "target.org" in q


class TestShodanHostInfo:
    def test_requires_api_key(self):
        result = search_recon.shodan_host_info("1.2.3.4", "")
        assert result["errors"]
        assert "API key" in result["errors"][0]

    @patch("modules.search_recon.REQUESTS_AVAILABLE", False)
    def test_graceful_without_requests(self):
        result = search_recon.shodan_host_info("1.2.3.4", "fake-key")
        assert any("requests" in e for e in result["errors"])


class TestCrtshSubdomainEnum:
    @patch("modules.search_recon.REQUESTS_AVAILABLE", True)
    @patch("modules.search_recon.requests.get")
    def test_extracts_subdomains(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"name_value": "www.example.com"},
            {"name_value": "api.example.com\nmail.example.com"},
            {"name_value": "*.example.com"},
        ]
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = search_recon.crtsh_subdomain_enum("example.com")
        assert "www.example.com" in result["subdomains"]
        assert "api.example.com" in result["subdomains"]
        assert "mail.example.com" in result["subdomains"]
        assert result["cert_count"] == 3


class TestWaybackAvailability:
    @patch("modules.search_recon.REQUESTS_AVAILABLE", True)
    @patch("modules.search_recon.requests.get")
    def test_archived_url(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "archived_snapshots": {
                "closest": {
                    "available": True,
                    "url": "https://web.archive.org/web/20230101/https://example.com",
                    "timestamp": "20230101120000",
                    "status": "200",
                }
            }
        }
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = search_recon.wayback_availability("https://example.com")
        assert result["archived"] is True
        assert result["snapshot"]["timestamp"] == "20230101120000"

    @patch("modules.search_recon.REQUESTS_AVAILABLE", False)
    def test_graceful_without_requests(self):
        result = search_recon.wayback_availability("https://example.com")
        assert result["archived"] is False


class TestExtractDomain:
    def test_extracts_netloc(self):
        assert search_recon._extract_domain("https://example.com/path") == "example.com"

    def test_empty_string(self):
        assert search_recon._extract_domain("") == ""
