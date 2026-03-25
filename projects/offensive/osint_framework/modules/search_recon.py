"""
Search Engine & Archive Reconnaissance Module
----------------------------------------------
Discovers web-accessible resources, historical data, and exposed services
using public search APIs and the Internet Archive.

Sources covered:
  • Shodan — internet-wide scanner; finds services on non-standard ports,
             exposed IoT, misconfigurations, banners, CVEs
  • Google Custom Search API — programmatic Google search (dorks)
  • Bing Search API — alternative search engine
  • Wayback Machine (Internet Archive CDX API) — free, no key required;
             returns historical snapshots for any URL
  • Certificate Transparency (crt.sh) — free; reveals all TLS certificates
             issued for a domain, exposing subdomains

Dork techniques demonstrated:
  site:      — restrict to domain
  filetype:  — find exposed config / backup files
  intitle:   — page title matching
  inurl:     — URL pattern matching
  cache:     — Google's cached version
"""

import urllib.parse
from typing import Any

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


SHODAN_API_BASE  = "https://api.shodan.io"
WAYBACK_CDX_API  = "https://web.archive.org/cdx/search/cdx"
CRTSH_API        = "https://crt.sh/?q={}&output=json"
GOOGLE_CSE_API   = "https://www.googleapis.com/customsearch/v1"
BING_SEARCH_API  = "https://api.bing.microsoft.com/v7.0/search"


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------

def shodan_host_info(ip: str, api_key: str) -> dict[str, Any]:
    """
    Return Shodan host information: open ports, banners, CVEs, geolocation.

    *api_key*: obtain free key at https://account.shodan.io/
    Free tier allows host lookups but not real-time scanning.
    """
    result: dict[str, Any] = {
        "ip": ip,
        "ports": [],
        "services": [],
        "vulnerabilities": [],
        "geolocation": {},
        "os": None,
        "hostnames": [],
        "errors": [],
    }

    if not api_key:
        result["errors"].append(
            "Shodan API key required. Register free at https://account.shodan.io/"
        )
        return result

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not installed")
        return result

    try:
        r = requests.get(
            f"{SHODAN_API_BASE}/shodan/host/{ip}",
            params={"key": api_key},
            timeout=15,
        )
        if r.status_code == 200:
            data = r.json()
            result["ports"]    = sorted(data.get("ports", []))
            result["os"]       = data.get("os")
            result["hostnames"] = data.get("hostnames", [])
            result["geolocation"] = {
                "country":  data.get("country_name"),
                "city":     data.get("city"),
                "region":   data.get("region_code"),
                "lat":      data.get("latitude"),
                "lon":      data.get("longitude"),
                "org":      data.get("org"),
                "isp":      data.get("isp"),
                "asn":      data.get("asn"),
            }
            result["vulnerabilities"] = data.get("vulns", [])
            result["services"] = [
                {
                    "port":      svc.get("port"),
                    "transport": svc.get("transport"),
                    "banner":    svc.get("data", "")[:500],  # truncate long banners
                    "product":   svc.get("product"),
                    "version":   svc.get("version"),
                    "cpe":       svc.get("cpe", []),
                }
                for svc in data.get("data", [])
            ]
        elif r.status_code == 404:
            result["errors"].append("No Shodan data for this IP")
        elif r.status_code == 401:
            result["errors"].append("Invalid Shodan API key")
        else:
            result["errors"].append(f"Shodan HTTP {r.status_code}")
    except Exception as e:
        result["errors"].append(str(e))

    return result


def shodan_search(query: str, api_key: str, max_results: int = 50) -> dict[str, Any]:
    """
    Execute a Shodan search query.

    Example queries:
      'org:"Target Corp"'
      'hostname:targetcorp.com'
      'ssl:"targetcorp.com"'
      'http.title:"Target Portal" country:US'
      'port:8443 org:"Target Corp"'
    """
    result: dict[str, Any] = {
        "query": query,
        "total": 0,
        "matches": [],
        "errors": [],
    }

    if not api_key:
        result["errors"].append("Shodan API key required")
        return result

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not installed")
        return result

    try:
        r = requests.get(
            f"{SHODAN_API_BASE}/shodan/host/search",
            params={"key": api_key, "query": query, "limit": max_results},
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        result["total"] = data.get("total", 0)
        result["matches"] = [
            {
                "ip":       m.get("ip_str"),
                "port":     m.get("port"),
                "org":      m.get("org"),
                "country":  m.get("location", {}).get("country_name"),
                "hostnames": m.get("hostnames", []),
                "banner":   m.get("data", "")[:300],
                "product":  m.get("product"),
                "version":  m.get("version"),
                "vulns":    list(m.get("vulns", {}).keys()),
            }
            for m in data.get("matches", [])
        ]
    except Exception as e:
        result["errors"].append(str(e))

    return result


# ---------------------------------------------------------------------------
# Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------

def crtsh_subdomain_enum(domain: str, include_expired: bool = False) -> dict[str, Any]:
    """
    Query crt.sh for TLS certificates issued to *domain* and extract subdomains.

    Certificate Transparency logs are public and free to query.  Every TLS
    cert issued by a CA is logged, making this one of the best passive
    subdomain sources — no DNS interaction required.
    """
    result: dict[str, Any] = {
        "domain":     domain,
        "subdomains": [],
        "cert_count": 0,
        "errors":     [],
    }

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not installed")
        return result

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        r = requests.get(url, timeout=20)
        r.raise_for_status()
        certs = r.json()
        result["cert_count"] = len(certs)

        subdomains: set[str] = set()
        for cert in certs:
            name_value = cert.get("name_value", "")
            # name_value can contain multiple names separated by newlines
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name.endswith(f".{domain}") or name == domain:
                    # Wildcard certs contain *.domain — strip the wildcard
                    name = name.lstrip("*.")
                    if name:
                        subdomains.add(name)

        result["subdomains"] = sorted(subdomains)
    except Exception as e:
        result["errors"].append(str(e))

    return result


# ---------------------------------------------------------------------------
# Wayback Machine / Internet Archive
# ---------------------------------------------------------------------------

def wayback_availability(url: str) -> dict[str, Any]:
    """
    Check if a URL is archived in the Wayback Machine and return the most
    recent snapshot URL.  Free, no API key required.
    """
    result: dict[str, Any] = {
        "url":      url,
        "archived": False,
        "snapshot": None,
        "errors":   [],
    }

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not installed")
        return result

    try:
        r = requests.get(
            "https://archive.org/wayback/available",
            params={"url": url},
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        closest = data.get("archived_snapshots", {}).get("closest")
        if closest and closest.get("available"):
            result["archived"] = True
            result["snapshot"] = {
                "url":       closest.get("url"),
                "timestamp": closest.get("timestamp"),
                "status":    closest.get("status"),
            }
    except Exception as e:
        result["errors"].append(str(e))

    return result


def wayback_history(url: str, limit: int = 50,
                     from_date: str = "", to_date: str = "") -> dict[str, Any]:
    """
    Return historical snapshots for a URL from the Wayback CDX API.

    *from_date* / *to_date* format: YYYYMMDD  e.g. "20200101"

    This reveals infrastructure and content changes over time — useful for
    finding old admin panels, removed files, and historical employee data.
    """
    result: dict[str, Any] = {
        "url":       url,
        "snapshots": [],
        "errors":    [],
    }

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not installed")
        return result

    try:
        params: dict[str, Any] = {
            "url":      url,
            "output":   "json",
            "fl":       "timestamp,statuscode,mimetype,digest",
            "limit":    limit,
            "collapse": "digest",   # deduplicate identical content
        }
        if from_date:
            params["from"] = from_date
        if to_date:
            params["to"] = to_date

        r = requests.get(WAYBACK_CDX_API, params=params, timeout=20)
        r.raise_for_status()
        rows = r.json()

        # First row is the field header
        if rows and len(rows) > 1:
            fields = rows[0]
            for row in rows[1:]:
                snapshot = dict(zip(fields, row))
                ts = snapshot.get("timestamp", "")
                # Build the full Wayback URL
                if ts:
                    snapshot["wayback_url"] = (
                        f"https://web.archive.org/web/{ts}/{url}"
                    )
                result["snapshots"].append(snapshot)
    except Exception as e:
        result["errors"].append(str(e))

    return result


def wayback_domain_urls(domain: str, limit: int = 200) -> dict[str, Any]:
    """
    Extract all unique URLs archived under a domain from the Wayback CDX API.
    Reveals the full URL structure including hidden/removed paths.
    """
    result: dict[str, Any] = {
        "domain": domain,
        "urls":   [],
        "errors": [],
    }

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not installed")
        return result

    try:
        params = {
            "url":      f"*.{domain}/*",
            "output":   "json",
            "fl":       "original",
            "limit":    limit,
            "collapse": "urlkey",
        }
        r = requests.get(WAYBACK_CDX_API, params=params, timeout=30)
        r.raise_for_status()
        rows = r.json()
        if rows and len(rows) > 1:
            result["urls"] = sorted({row[0] for row in rows[1:] if row})
    except Exception as e:
        result["errors"].append(str(e))

    return result


# ---------------------------------------------------------------------------
# Google Custom Search (dorks)
# ---------------------------------------------------------------------------

def google_search(query: str, api_key: str, cse_id: str,
                   num: int = 10) -> dict[str, Any]:
    """
    Execute a Google search via the Custom Search JSON API.

    *api_key*: Google Cloud API key with Custom Search API enabled
    *cse_id*:  Programmable Search Engine ID (cx)

    Create a search engine at https://programmablesearchengine.google.com/
    Enable "Search the entire web" for dork-style searches.
    """
    result: dict[str, Any] = {
        "query":   query,
        "results": [],
        "errors":  [],
    }

    if not api_key or not cse_id:
        result["errors"].append(
            "Google Custom Search API key and Search Engine ID required. "
            "See: https://developers.google.com/custom-search/v1/overview"
        )
        return result

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not installed")
        return result

    try:
        params = {
            "key": api_key,
            "cx":  cse_id,
            "q":   query,
            "num": min(num, 10),  # Max 10 per request
        }
        r = requests.get(GOOGLE_CSE_API, params=params, timeout=15)
        r.raise_for_status()
        data = r.json()
        result["results"] = [
            {
                "title":   item.get("title"),
                "link":    item.get("link"),
                "snippet": item.get("snippet"),
                "domain":  _extract_domain(item.get("link", "")),
            }
            for item in data.get("items", [])
        ]
    except Exception as e:
        result["errors"].append(str(e))

    return result


def generate_recon_dorks(domain: str) -> dict[str, list[str]]:
    """
    Generate a comprehensive set of Google/Bing dorks for *domain*.

    These are standard OSINT queries used in penetration testing to discover
    exposed data, admin panels, login pages, and sensitive files.
    """
    return {
        "general": [
            f"site:{domain}",
            f"site:{domain} -www",  # Subdomains other than www
        ],
        "sensitive_files": [
            f'site:{domain} filetype:pdf "confidential"',
            f'site:{domain} filetype:xls OR filetype:xlsx',
            f'site:{domain} filetype:csv',
            f'site:{domain} filetype:xml',
            f'site:{domain} filetype:json',
            f'site:{domain} filetype:sql',
            f'site:{domain} filetype:bak OR filetype:backup',
            f'site:{domain} filetype:log',
            f'site:{domain} filetype:env',
            f'site:{domain} filetype:conf OR filetype:config',
        ],
        "admin_panels": [
            f'site:{domain} intitle:"admin" OR intitle:"login" OR intitle:"dashboard"',
            f'site:{domain} inurl:admin OR inurl:administrator OR inurl:wp-admin',
            f'site:{domain} inurl:login OR inurl:signin OR inurl:auth',
            f'site:{domain} inurl:panel OR inurl:cpanel',
        ],
        "exposed_services": [
            f'site:{domain} inurl:phpinfo',
            f'site:{domain} inurl:".git" OR inurl:".svn"',
            f'site:{domain} intitle:"Index of"',
            f'site:{domain} intitle:"Apache Status"',
            f'site:{domain} inurl:".env" OR inurl:"config.php"',
            f'site:{domain} inurl:"wp-config.php.bak"',
        ],
        "emails_and_people": [
            f'site:{domain} "@{domain}"',
            f'"{domain}" email contact',
            f'site:linkedin.com "{domain}"',
            f'"{domain}" resume OR CV site:linkedin.com',
        ],
        "error_pages": [
            f'site:{domain} intext:"sql syntax" OR intext:"mysql_fetch"',
            f'site:{domain} intext:"ORA-" OR intext:"PLS-"',  # Oracle errors
            f'site:{domain} intext:"stack trace" OR intext:"Exception"',
        ],
        "cached_and_historical": [
            f'cache:{domain}',
            f'"{domain}" site:web.archive.org',
            f'site:pastebin.com "{domain}"',
            f'site:github.com "{domain}"',
        ],
    }


# ---------------------------------------------------------------------------
# Bing Search API
# ---------------------------------------------------------------------------

def bing_search(query: str, api_key: str, count: int = 10) -> dict[str, Any]:
    """
    Execute a Bing Web Search.

    *api_key*: Azure Cognitive Services key with Bing Search enabled.
    Create at https://portal.azure.com/ → Bing Search v7
    """
    result: dict[str, Any] = {
        "query":   query,
        "results": [],
        "errors":  [],
    }

    if not api_key:
        result["errors"].append(
            "Bing Search API key required. "
            "Create at https://portal.azure.com/"
        )
        return result

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not installed")
        return result

    try:
        r = requests.get(
            BING_SEARCH_API,
            headers={"Ocp-Apim-Subscription-Key": api_key},
            params={"q": query, "count": count, "textFormat": "Raw"},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
        result["results"] = [
            {
                "title":   item.get("name"),
                "link":    item.get("url"),
                "snippet": item.get("snippet"),
                "domain":  _extract_domain(item.get("url", "")),
            }
            for item in data.get("webPages", {}).get("value", [])
        ]
    except Exception as e:
        result["errors"].append(str(e))

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str:
    try:
        return urllib.parse.urlparse(url).netloc
    except Exception:
        return ""
