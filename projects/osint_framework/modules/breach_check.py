"""
Breach Database Integration Module
------------------------------------
Checks email addresses and usernames against known breach databases to
identify compromised credentials and associated personal data.

APIs used:
  • HaveIBeenPwned (HIBP) v3 — https://haveibeenpwned.com/API/v3
      Requires a paid API key ($3.50/month as of 2024).
      Returns list of breaches and pastes an address appears in.
  • HIBP Pwned Passwords — checks if a password hash prefix has been seen;
      uses k-anonymity model (sends only first 5 chars of SHA-1 hash —
      the server NEVER receives the full password or hash).
  • DeHashed — https://www.dehashed.com/
      Commercial breach search engine (paid tier required for full results).

Educational note: Breach data reveals:
  - Compromised credentials → credential stuffing risk
  - Personal data (DOB, phone) → social engineering attack surface
  - Password patterns → aid password audits during assessments
  - Reused passwords across services → lateral movement opportunities
"""

import hashlib
import time
import re
from typing import Any

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


HIBP_API_BASE     = "https://haveibeenpwned.com/api/v3"
HIBP_PWNED_PASS   = "https://api.pwnedpasswords.com/range"
DEHASHED_API_BASE = "https://api.dehashed.com/search"

# HIBP requires this User-Agent
HIBP_USER_AGENT   = "OSINT-Framework-Educational/1.0"


# ---------------------------------------------------------------------------
# HaveIBeenPwned
# ---------------------------------------------------------------------------

def check_email_hibp(email: str, api_key: str,
                      include_unverified: bool = True) -> dict[str, Any]:
    """
    Check an email address against HaveIBeenPwned v3 breach database.

    *api_key* is required — obtain from https://haveibeenpwned.com/API/v3
    Returns breach names, domains, dates, and data classes exposed.
    """
    result: dict[str, Any] = {
        "email":    email,
        "breached": False,
        "breach_count": 0,
        "breaches":  [],
        "pastes":    [],
        "errors":    [],
    }

    if not api_key:
        result["errors"].append(
            "HIBP API key required. Purchase at https://haveibeenpwned.com/API/v3"
        )
        return result

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not installed")
        return result

    headers = {
        "hibp-api-key": api_key,
        "User-Agent":   HIBP_USER_AGENT,
        "Accept":       "application/json",
    }

    # --- Breaches -----------------------------------------------------------
    try:
        params = {"truncateResponse": "false"}
        if include_unverified:
            params["includeUnverified"] = "true"
        r = requests.get(
            f"{HIBP_API_BASE}/breachedaccount/{urllib_encode(email)}",
            headers=headers,
            params=params,
            timeout=10,
        )

        if r.status_code == 200:
            breaches = r.json()
            result["breached"] = True
            result["breach_count"] = len(breaches)
            result["breaches"] = [
                {
                    "name":         b.get("Name"),
                    "domain":       b.get("Domain"),
                    "breach_date":  b.get("BreachDate"),
                    "added_date":   b.get("AddedDate"),
                    "pwn_count":    b.get("PwnCount"),
                    "description":  _strip_html(b.get("Description", "")),
                    "data_classes": b.get("DataClasses", []),
                    "is_verified":  b.get("IsVerified"),
                    "is_sensitive": b.get("IsSensitive"),
                }
                for b in breaches
            ]
        elif r.status_code == 404:
            result["breached"] = False  # clean email
        elif r.status_code == 401:
            result["errors"].append("Invalid or missing HIBP API key")
        elif r.status_code == 429:
            result["errors"].append("HIBP rate limit hit — wait before retrying")
        else:
            result["errors"].append(f"HIBP breaches HTTP {r.status_code}")
    except Exception as e:
        result["errors"].append(f"breaches: {e}")

    time.sleep(1.5)  # HIBP enforces max 1 req/1500ms per key

    # --- Pastes -------------------------------------------------------------
    try:
        r = requests.get(
            f"{HIBP_API_BASE}/pasteaccount/{urllib_encode(email)}",
            headers=headers,
            timeout=10,
        )
        if r.status_code == 200:
            pastes = r.json()
            result["pastes"] = [
                {
                    "source":  p.get("Source"),
                    "id":      p.get("Id"),
                    "title":   p.get("Title"),
                    "date":    p.get("Date"),
                    "email_count": p.get("EmailCount"),
                }
                for p in pastes
            ]
    except Exception as e:
        result["errors"].append(f"pastes: {e}")

    return result


def check_password_hibp(password: str) -> dict[str, Any]:
    """
    Check if a password appears in HIBP's Pwned Passwords list.

    Uses k-anonymity: only the first 5 hex characters of the SHA-1 hash are
    sent to the API.  The server returns all hashes matching that prefix,
    and the full hash comparison happens locally.  The server NEVER sees the
    full password or hash.

    This is safe to use even during live engagements.
    """
    result: dict[str, Any] = {
        "pwned": False,
        "count": 0,  # number of times seen in breach corpus
        "errors": [],
    }

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix    = sha1_hash[:5]
    suffix    = sha1_hash[5:]

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not installed")
        return result

    try:
        r = requests.get(f"{HIBP_PWNED_PASS}/{prefix}",
                         headers={"User-Agent": HIBP_USER_AGENT},
                         timeout=10)
        r.raise_for_status()
        for line in r.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].upper() == suffix:
                result["pwned"] = True
                result["count"] = int(parts[1])
                break
    except Exception as e:
        result["errors"].append(str(e))

    return result


def bulk_check_emails_hibp(emails: list[str], api_key: str,
                             delay: float = 1.6) -> list[dict[str, Any]]:
    """
    Check multiple emails against HIBP, respecting rate limits.
    *delay* seconds between requests (HIBP allows ~1 req/1500ms).
    """
    results = []
    for email in emails:
        results.append(check_email_hibp(email, api_key))
        time.sleep(delay)
    return results


# ---------------------------------------------------------------------------
# DeHashed
# ---------------------------------------------------------------------------

def search_dehashed(query: str, api_email: str, api_key: str,
                    query_type: str = "email") -> dict[str, Any]:
    """
    Search DeHashed breach search engine.

    *query_type* can be: email, username, ip_address, name, address, phone,
                         vin, password, hashed_password, domain

    Requires a DeHashed paid account.
    """
    result: dict[str, Any] = {
        "query":      query,
        "query_type": query_type,
        "total":      0,
        "entries":    [],
        "errors":     [],
    }

    if not api_key or not api_email:
        result["errors"].append(
            "DeHashed API credentials required. "
            "Obtain from https://www.dehashed.com/profile"
        )
        return result

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not installed")
        return result

    try:
        params = {query_type: query, "size": 100}
        r = requests.get(
            DEHASHED_API_BASE,
            auth=(api_email, api_key),
            params=params,
            headers={"Accept": "application/json"},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        result["total"] = data.get("total", 0)
        result["entries"] = [
            {
                "id":               e.get("id"),
                "email":            e.get("email"),
                "username":         e.get("username"),
                "password":         e.get("password"),
                "hashed_password":  e.get("hashed_password"),
                "name":             e.get("name"),
                "vin":              e.get("vin"),
                "address":          e.get("address"),
                "ip_address":       e.get("ip_address"),
                "phone":            e.get("phone"),
                "database_name":    e.get("database_name"),
            }
            for e in data.get("entries", []) or []
        ]
    except requests.exceptions.HTTPError as e:
        result["errors"].append(f"HTTP {r.status_code}: {e}")
    except Exception as e:
        result["errors"].append(str(e))

    return result


# ---------------------------------------------------------------------------
# Breach risk summary
# ---------------------------------------------------------------------------

def summarise_breach_risk(hibp_results: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Aggregate HIBP results for multiple emails into a risk summary.
    Highlights high-risk data classes (passwords, financial data).
    """
    high_risk_classes = {
        "Passwords", "Password hints", "Credit cards",
        "Bank account numbers", "Social security numbers",
        "Dates of birth", "Phone numbers", "Physical addresses",
    }

    total_emails     = len(hibp_results)
    breached_emails  = [r for r in hibp_results if r.get("breached")]
    all_data_classes: set[str] = set()
    all_breach_names: set[str] = set()

    for r in breached_emails:
        for breach in r.get("breaches", []):
            all_data_classes.update(breach.get("data_classes", []))
            if breach.get("name"):
                all_breach_names.add(breach["name"])

    high_risk_exposed = all_data_classes & high_risk_classes
    risk_level = "LOW"
    if high_risk_exposed:
        risk_level = "CRITICAL" if "Passwords" in high_risk_exposed else "HIGH"
    elif breached_emails:
        risk_level = "MEDIUM"

    return {
        "total_emails_checked": total_emails,
        "breached_count":        len(breached_emails),
        "breach_rate_pct":       round(len(breached_emails) / total_emails * 100, 1) if total_emails else 0,
        "unique_breaches":       sorted(all_breach_names),
        "all_data_classes":      sorted(all_data_classes),
        "high_risk_classes_exposed": sorted(high_risk_exposed),
        "risk_level":            risk_level,
        "recommendation": _risk_recommendation(risk_level, high_risk_exposed),
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def urllib_encode(value: str) -> str:
    try:
        from urllib.parse import quote
        return quote(value, safe="")
    except Exception:
        return value


def _strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", "", text)


def _risk_recommendation(level: str, exposed: set[str]) -> str:
    if level == "CRITICAL":
        return (
            "Passwords found in breach data. Immediately enforce password resets, "
            "enable MFA, and audit for credential stuffing on exposed accounts."
        )
    if level == "HIGH":
        return (
            f"Sensitive data ({', '.join(sorted(exposed))}) exposed. "
            "Review impacted accounts and notify affected users per breach disclosure obligations."
        )
    if level == "MEDIUM":
        return (
            "Email addresses appear in breaches. Monitor for phishing campaigns "
            "targeting these accounts and ensure MFA is enabled."
        )
    return "No breach exposure detected. Continue monitoring."
