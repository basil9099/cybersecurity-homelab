"""
Social Media & People Search Module
-------------------------------------
Gathers intelligence from publicly accessible social platforms and code
repositories without requiring authentication where possible.

Sources covered:
  • GitHub — public repositories, users, org members, code search for secrets
  • LinkedIn — public profile search via Google dork (no scraping login wall)
  • Twitter/X — public profile metadata via nitter mirrors
  • General people search — generates Google/Bing dorks for analysts
  • Email pattern inference from discovered employee names + domain

Note on legality: All queries target public data or use legitimate search
operator techniques. No credentials are stored or bypassed. Respect platform
Terms of Service and applicable privacy laws (GDPR, CCPA) when using output.
"""

import re
import time
from typing import Any

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


GITHUB_API = "https://api.github.com"

# Common email patterns used by organisations — enumeration aid for analysts
EMAIL_PATTERNS = [
    "{first}.{last}@{domain}",
    "{first}{last}@{domain}",
    "{f}{last}@{domain}",
    "{first}_{last}@{domain}",
    "{last}.{first}@{domain}",
    "{last}{f}@{domain}",
    "{first}@{domain}",
    "{last}@{domain}",
]


# ---------------------------------------------------------------------------
# GitHub reconnaissance
# ---------------------------------------------------------------------------

def github_search_org(org_name: str, token: str | None = None) -> dict[str, Any]:
    """
    Return public organisation metadata, members, and repositories from GitHub.

    *token* is optional but dramatically increases the rate limit from 60 to
    5,000 requests/hour.  Use a classic PAT (read:org, public_repo scopes).
    """
    result: dict[str, Any] = {
        "org": org_name,
        "metadata": {},
        "members": [],
        "repositories": [],
        "errors": [],
    }

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not installed")
        return result

    headers = _gh_headers(token)

    # Org metadata
    try:
        r = requests.get(f"{GITHUB_API}/orgs/{org_name}", headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            result["metadata"] = {
                "name":         data.get("name"),
                "description":  data.get("description"),
                "blog":         data.get("blog"),
                "email":        data.get("email"),
                "location":     data.get("location"),
                "public_repos": data.get("public_repos"),
                "public_members": data.get("public_members_url"),
                "created_at":   data.get("created_at"),
                "html_url":     data.get("html_url"),
            }
        else:
            result["errors"].append(f"org lookup HTTP {r.status_code}")
    except Exception as e:
        result["errors"].append(f"org metadata: {e}")

    # Public members (page through up to 5 pages = 500 members)
    try:
        members = _gh_paginate(f"{GITHUB_API}/orgs/{org_name}/public_members",
                               headers=headers, max_pages=5)
        result["members"] = [
            {
                "login":    m.get("login"),
                "html_url": m.get("html_url"),
                "avatar":   m.get("avatar_url"),
            }
            for m in members
        ]
    except Exception as e:
        result["errors"].append(f"members: {e}")

    # Public repositories
    try:
        repos = _gh_paginate(f"{GITHUB_API}/orgs/{org_name}/repos?type=public&sort=updated",
                             headers=headers, max_pages=3)
        result["repositories"] = [
            {
                "name":        r.get("name"),
                "description": r.get("description"),
                "language":    r.get("language"),
                "stars":       r.get("stargazers_count"),
                "forks":       r.get("forks_count"),
                "updated_at":  r.get("updated_at"),
                "html_url":    r.get("html_url"),
                "topics":      r.get("topics", []),
            }
            for r in repos
        ]
    except Exception as e:
        result["errors"].append(f"repos: {e}")

    return result


def github_user_profile(username: str, token: str | None = None) -> dict[str, Any]:
    """Fetch public profile data for a GitHub user."""
    result: dict[str, Any] = {
        "username": username,
        "profile": {},
        "repositories": [],
        "emails_found": [],
        "errors": [],
    }

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not installed")
        return result

    headers = _gh_headers(token)

    try:
        r = requests.get(f"{GITHUB_API}/users/{username}", headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            result["profile"] = {
                "name":       data.get("name"),
                "email":      data.get("email"),
                "bio":        data.get("bio"),
                "company":    data.get("company"),
                "location":   data.get("location"),
                "blog":       data.get("blog"),
                "twitter":    data.get("twitter_username"),
                "followers":  data.get("followers"),
                "following":  data.get("following"),
                "public_repos": data.get("public_repos"),
                "created_at": data.get("created_at"),
                "html_url":   data.get("html_url"),
            }
            if data.get("email"):
                result["emails_found"].append(data["email"])
    except Exception as e:
        result["errors"].append(f"profile: {e}")

    # Repos (check README and commit emails)
    try:
        repos = _gh_paginate(f"{GITHUB_API}/users/{username}/repos?sort=updated",
                              headers=headers, max_pages=2)
        result["repositories"] = [
            {
                "name":     r.get("name"),
                "language": r.get("language"),
                "stars":    r.get("stargazers_count"),
                "updated":  r.get("updated_at"),
                "url":      r.get("html_url"),
            }
            for r in repos
        ]
    except Exception as e:
        result["errors"].append(f"repos: {e}")

    return result


def github_code_search(query: str, token: str | None = None,
                        max_results: int = 30) -> dict[str, Any]:
    """
    Search GitHub code for sensitive strings (secrets, config files, etc.).

    Example queries for pen-testing context:
      "org:TargetCorp password"
      "org:TargetCorp AWS_SECRET_ACCESS_KEY"
      "user:targetuser .env"
      "filename:.env DB_PASSWORD org:TargetCorp"

    Requires a GitHub token — unauthenticated code search is disabled.
    """
    result: dict[str, Any] = {
        "query": query,
        "total_count": 0,
        "items": [],
        "errors": [],
    }

    if not token:
        result["errors"].append(
            "GitHub token required for code search. "
            "Create one at https://github.com/settings/tokens (public_repo scope)."
        )
        return result

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not installed")
        return result

    headers = _gh_headers(token)
    headers["Accept"] = "application/vnd.github.text-match+json"

    try:
        params = {"q": query, "per_page": min(max_results, 100)}
        r = requests.get(f"{GITHUB_API}/search/code", headers=headers,
                         params=params, timeout=15)
        r.raise_for_status()
        data = r.json()
        result["total_count"] = data.get("total_count", 0)
        result["items"] = [
            {
                "repo":     item["repository"]["full_name"],
                "path":     item.get("path"),
                "html_url": item.get("html_url"),
                "matches":  [m.get("fragment", "") for m in item.get("text_matches", [])],
            }
            for item in data.get("items", [])
        ]
    except requests.exceptions.HTTPError as e:
        if r.status_code == 403:
            result["errors"].append("Rate limited or token lacks code search permission.")
        else:
            result["errors"].append(f"HTTP {r.status_code}: {e}")
    except Exception as e:
        result["errors"].append(str(e))

    return result


# ---------------------------------------------------------------------------
# LinkedIn / people search dorks
# ---------------------------------------------------------------------------

def generate_linkedin_dorks(company: str, domain: str | None = None) -> dict[str, Any]:
    """
    Generate Google search operator strings to find LinkedIn profiles for
    employees of *company*.  Returns the dork strings — the analyst pastes
    them into a browser (or uses the search_recon module to automate).

    No LinkedIn scraping is performed here (violates ToS; requires login).
    """
    dorks = [
        f'site:linkedin.com/in "{company}"',
        f'site:linkedin.com/in "{company}" engineer',
        f'site:linkedin.com/in "{company}" security',
        f'site:linkedin.com/in "{company}" developer',
        f'site:linkedin.com/in "{company}" IT',
        f'site:linkedin.com/in "{company}" manager',
        f'site:linkedin.com/in "{company}" CEO OR CTO OR CISO',
    ]
    if domain:
        dorks += [
            f'site:linkedin.com/in "{company}" "{domain}"',
            f'"{domain}" site:linkedin.com',
        ]

    return {
        "company":    company,
        "platform":   "LinkedIn (via Google dork)",
        "dorks":      dorks,
        "note": (
            "Paste these into Google/Bing to discover public LinkedIn profiles. "
            "LinkedIn's own search requires authentication. Respect GDPR/CCPA "
            "when collecting and storing personal data."
        ),
    }


def generate_twitter_dorks(company: str, domain: str | None = None) -> dict[str, Any]:
    """Generate Twitter/X search dorks for company and employee discovery."""
    dorks = [
        f'from:{company.lower().replace(" ", "")} lang:en',
        f'"{company}" lang:en since:2023-01-01',
        f'"{company}" filter:links',
    ]
    if domain:
        dorks.append(f'"{domain}" lang:en')

    return {
        "company":  company,
        "platform": "Twitter/X (via search operators)",
        "dorks":    dorks,
    }


# ---------------------------------------------------------------------------
# Email pattern generation
# ---------------------------------------------------------------------------

def generate_email_patterns(first: str, last: str, domain: str) -> list[str]:
    """
    Generate candidate email addresses for a person given name components and domain.
    Useful after discovering employee names via LinkedIn / GitHub.
    """
    f = first[0].lower() if first else ""
    l_initial = last[0].lower() if last else ""  # noqa: E741
    substitutions = {
        "first":  first.lower(),
        "last":   last.lower(),
        "f":      f,
        "l":      l_initial,
        "domain": domain,
    }
    emails = []
    for pattern in EMAIL_PATTERNS:
        try:
            emails.append(pattern.format(**substitutions))
        except KeyError:
            pass
    return emails


def infer_email_pattern_from_samples(known_emails: list[str],
                                      domain: str) -> str | None:
    """
    Given a list of known valid email addresses for a domain, infer the pattern
    the organisation uses (e.g. first.last@domain).

    This is useful once a few emails are discovered through WHOIS or GitHub
    to predict addresses for other employees.
    """
    if not known_emails:
        return None

    patterns_detected: dict[str, int] = {}
    local_parts = [e.split("@")[0] for e in known_emails if "@" in e]

    for local in local_parts:
        if "." in local:
            parts = local.split(".")
            if len(parts) == 2:
                patterns_detected["{first}.{last}"] = patterns_detected.get("{first}.{last}", 0) + 1
        elif re.match(r"^[a-z]\w+", local):
            # Could be first initial + last or just first
            if len(local) > 6:
                patterns_detected["{f}{last}"] = patterns_detected.get("{f}{last}", 0) + 1
            else:
                patterns_detected["{first}"] = patterns_detected.get("{first}", 0) + 1
        elif "_" in local:
            patterns_detected["{first}_{last}"] = patterns_detected.get("{first}_{last}", 0) + 1

    if not patterns_detected:
        return None
    # Return the most common pattern
    return max(patterns_detected, key=lambda k: patterns_detected[k])


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _gh_headers(token: str | None) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _gh_paginate(url: str, headers: dict, max_pages: int = 3) -> list[dict]:
    """Fetch up to *max_pages* pages of results from a GitHub list endpoint."""
    if not REQUESTS_AVAILABLE:
        return []
    items: list[dict] = []
    page = 1
    while page <= max_pages:
        sep = "&" if "?" in url else "?"
        r = requests.get(f"{url}{sep}per_page=100&page={page}",
                         headers=headers, timeout=10)
        if r.status_code != 200:
            break
        data = r.json()
        if not data:
            break
        items.extend(data)
        # Respect rate limits — check remaining header
        remaining = int(r.headers.get("X-RateLimit-Remaining", 999))
        if remaining < 5:
            break
        page += 1
        time.sleep(0.3)  # Be polite to the API
    return items
