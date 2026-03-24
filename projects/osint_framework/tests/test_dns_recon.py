"""Tests for the dns_recon module."""

import os
import socket
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules import dns_recon


class TestQueryRecords:
    """Tests for _query_records internal helper."""

    @patch("modules.dns_recon.DNS_AVAILABLE", False)
    def test_returns_empty_when_dns_unavailable(self):
        assert dns_recon._query_records("example.com", "A") == []

    @patch("modules.dns_recon.DNS_AVAILABLE", True)
    @patch("modules.dns_recon.dns.resolver.Resolver")
    def test_returns_records_on_success(self, mock_resolver_cls):
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        # Simulate resolved answers
        mock_answer = [MagicMock(__str__=lambda s: "1.2.3.4")]
        mock_resolver.resolve.return_value = mock_answer
        result = dns_recon._query_records("example.com", "A")
        assert result == ["1.2.3.4"]


class TestParseEmailSecurity:
    def test_extracts_spf(self):
        txt = ['"v=spf1 include:_spf.google.com ~all"']
        result = dns_recon._parse_email_security(txt)
        assert "spf" in result
        assert "include:_spf.google.com" in result["spf"]

    def test_extracts_dmarc(self):
        txt = ['"v=DMARC1; p=reject; rua=mailto:d@example.com"']
        result = dns_recon._parse_email_security(txt)
        assert result.get("dmarc_policy") == "reject"

    def test_empty_txt(self):
        assert dns_recon._parse_email_security([]) == {}


class TestParseNameservers:
    def test_strips_trailing_dot(self):
        ns = ["ns1.example.com.", "ns2.example.com."]
        result = dns_recon._parse_nameservers(ns)
        assert result == ["ns1.example.com", "ns2.example.com"]


class TestParseMX:
    def test_parses_priority_and_host(self):
        mx = ["10 mail.example.com.", "20 backup.example.com."]
        result = dns_recon._parse_mx(mx)
        assert result[0]["priority"] == 10
        assert result[0]["host"] == "mail.example.com"

    def test_sorts_by_priority(self):
        mx = ["20 backup.example.com.", "5 primary.example.com."]
        result = dns_recon._parse_mx(mx)
        assert result[0]["priority"] == 5


class TestReverseDNS:
    @patch("modules.dns_recon.socket.gethostbyaddr")
    def test_returns_hostname(self, mock_lookup):
        mock_lookup.return_value = ("host.example.com", [], ["1.2.3.4"])
        assert dns_recon.reverse_dns("1.2.3.4") == "host.example.com"

    @patch("modules.dns_recon.socket.gethostbyaddr", side_effect=socket.herror)
    def test_returns_none_on_failure(self, mock_lookup):
        assert dns_recon.reverse_dns("1.2.3.4") is None


class TestBruteforceSubdomains:
    """Test that brute-force returns resolved subdomains and respects batching."""

    @patch("modules.dns_recon._query_records")
    def test_finds_resolving_subdomains(self, mock_query):
        def side_effect(fqdn, rtype):
            if fqdn == "www.example.com" and rtype == "A":
                return ["1.2.3.4"]
            return []
        mock_query.side_effect = side_effect

        result = dns_recon._bruteforce_subdomains("example.com", ["www", "nonexistent"], threads=2)
        assert len(result) == 1
        assert result[0]["subdomain"] == "www.example.com"
