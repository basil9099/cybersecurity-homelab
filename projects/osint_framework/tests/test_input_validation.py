"""Tests for CLI input validation functions in osint_framework.py."""

import argparse
import os

import pytest

# Ensure the project root is importable
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from osint_framework import validate_target, validate_ip, validate_wordlist


# ---------------------------------------------------------------------------
# validate_target
# ---------------------------------------------------------------------------

class TestValidateTarget:
    def test_valid_domain(self):
        assert validate_target("example.com") == "example.com"

    def test_valid_subdomain(self):
        assert validate_target("sub.example.com") == "sub.example.com"

    def test_valid_ipv4(self):
        assert validate_target("192.168.1.1") == "192.168.1.1"

    def test_normalises_to_lowercase(self):
        assert validate_target("Example.COM") == "example.com"

    def test_strips_whitespace(self):
        assert validate_target("  example.com  ") == "example.com"

    def test_rejects_empty_string(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_target("")

    def test_rejects_bare_word(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_target("notadomain")

    def test_rejects_special_characters(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_target("ex@mple.com")

    def test_rejects_path_traversal(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_target("../../etc/passwd")


# ---------------------------------------------------------------------------
# validate_ip
# ---------------------------------------------------------------------------

class TestValidateIP:
    def test_valid_ipv4(self):
        assert validate_ip("10.0.0.1") == "10.0.0.1"

    def test_valid_ipv6(self):
        assert validate_ip("::1") == "::1"

    def test_rejects_domain(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_ip("example.com")

    def test_rejects_invalid_octets(self):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_ip("999.999.999.999")


# ---------------------------------------------------------------------------
# validate_wordlist
# ---------------------------------------------------------------------------

class TestValidateWordlist:
    def test_valid_small_file(self, tmp_path):
        wl = tmp_path / "wordlist.txt"
        wl.write_text("www\nmail\nftp\n")
        assert validate_wordlist(str(wl)) == str(wl)

    def test_rejects_missing_file(self):
        with pytest.raises(argparse.ArgumentTypeError, match="not found"):
            validate_wordlist("/nonexistent/wordlist.txt")

    def test_rejects_oversized_file(self, tmp_path):
        wl = tmp_path / "huge.txt"
        wl.write_bytes(b"x" * (11 * 1024 * 1024))  # 11 MB
        with pytest.raises(argparse.ArgumentTypeError, match="too large"):
            validate_wordlist(str(wl))
