"""Tests for the breach_check module."""

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import breach_check


class TestCheckEmailHIBP:
    def test_requires_api_key(self):
        result = breach_check.check_email_hibp("user@example.com", "")
        assert result["errors"]
        assert "API key" in result["errors"][0]

    @patch("modules.breach_check.REQUESTS_AVAILABLE", False)
    def test_graceful_without_requests(self):
        result = breach_check.check_email_hibp("user@example.com", "fake-key")
        assert any("requests" in e for e in result["errors"])


class TestCheckPasswordHIBP:
    @patch("modules.breach_check.REQUESTS_AVAILABLE", True)
    @patch("modules.breach_check.requests.get")
    def test_detects_pwned_password(self, mock_get):
        # SHA-1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\nOTHERHASH:1"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = breach_check.check_password_hibp("password")
        assert result["pwned"] is True
        assert result["count"] == 3861493

    @patch("modules.breach_check.REQUESTS_AVAILABLE", True)
    @patch("modules.breach_check.requests.get")
    def test_clean_password(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "AAAAAAAAAA:1\nBBBBBBBBBB:2"
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        result = breach_check.check_password_hibp("some-very-unique-passphrase-xyz-123")
        assert result["pwned"] is False


class TestSummariseBreachRisk:
    def test_critical_when_passwords_exposed(self):
        results = [{
            "email": "test@example.com",
            "breached": True,
            "breaches": [{"name": "TestBreach", "data_classes": ["Passwords", "Email addresses"]}],
        }]
        summary = breach_check.summarise_breach_risk(results)
        assert summary["risk_level"] == "CRITICAL"

    def test_high_when_sensitive_data(self):
        results = [{
            "email": "test@example.com",
            "breached": True,
            "breaches": [{"name": "TestBreach", "data_classes": ["Phone numbers", "Dates of birth"]}],
        }]
        summary = breach_check.summarise_breach_risk(results)
        assert summary["risk_level"] == "HIGH"

    def test_medium_when_breached_no_sensitive(self):
        results = [{
            "email": "test@example.com",
            "breached": True,
            "breaches": [{"name": "TestBreach", "data_classes": ["Email addresses"]}],
        }]
        summary = breach_check.summarise_breach_risk(results)
        assert summary["risk_level"] == "MEDIUM"

    def test_low_when_clean(self):
        results = [{
            "email": "clean@example.com",
            "breached": False,
            "breaches": [],
        }]
        summary = breach_check.summarise_breach_risk(results)
        assert summary["risk_level"] == "LOW"

    def test_empty_input(self):
        summary = breach_check.summarise_breach_risk([])
        assert summary["total_emails_checked"] == 0


class TestURLEncode:
    def test_encodes_at_sign(self):
        assert breach_check.urllib_encode("user@example.com") == "user%40example.com"

    def test_encodes_spaces(self):
        assert breach_check.urllib_encode("hello world") == "hello%20world"


class TestStripHTML:
    def test_removes_tags(self):
        assert breach_check._strip_html("<b>bold</b>") == "bold"

    def test_no_tags(self):
        assert breach_check._strip_html("plain text") == "plain text"
