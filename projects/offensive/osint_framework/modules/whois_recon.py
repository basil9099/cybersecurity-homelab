"""
WHOIS Reconnaissance Module
----------------------------
Queries WHOIS databases for domain and IP registration data including registrant
details, nameservers, creation/expiration dates, and hosting provider clues.

Technique: passive reconnaissance against public WHOIS databases — no target
interaction required (queries go to IANA/ARIN/RIPE, not the target).
"""

import re
import ipaddress
from typing import Any

try:
    import whois  # python-whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# RDAP (Registration Data Access Protocol) endpoints — modern replacement for
# plain WHOIS, returns structured JSON rather than free-form text.
RDAP_BASE = "https://rdap.org"
ARIN_RDAP  = "https://rdap.arin.net/registry"
RIPE_RDAP  = "https://rdap.db.ripe.net"


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def query_domain_whois(domain: str) -> dict[str, Any]:
    """
    Return WHOIS data for a domain.

    Uses python-whois for parsing and falls back to RDAP JSON API when the
    library is unavailable so the module works in minimal environments.
    """
    result: dict[str, Any] = {
        "target": domain,
        "type": "domain",
        "source": None,
        "raw": None,
        "parsed": {},
        "errors": [],
    }

    # --- python-whois path ---------------------------------------------------
    if WHOIS_AVAILABLE:
        try:
            w = whois.whois(domain)
            result["source"] = "python-whois"
            result["raw"] = str(w)

            # Normalise dates (python-whois sometimes returns lists)
            def _first(v):
                return v[0] if isinstance(v, list) else v

            parsed = {
                "domain_name":      _first(w.domain_name),
                "registrar":        _first(w.registrar),
                "registrant_name":  _first(getattr(w, "name", None)),
                "registrant_org":   _first(getattr(w, "org", None)),
                "registrant_email": _first(getattr(w, "emails", None)),
                "registrant_country": _first(getattr(w, "country", None)),
                "creation_date":    str(_first(w.creation_date)) if w.creation_date else None,
                "expiration_date":  str(_first(w.expiration_date)) if w.expiration_date else None,
                "updated_date":     str(_first(w.updated_date)) if w.updated_date else None,
                "name_servers":     list(w.name_servers) if w.name_servers else [],
                "status":           w.status if isinstance(w.status, list) else ([w.status] if w.status else []),
                "dnssec":           getattr(w, "dnssec", None),
            }
            # Deduplicate nameservers, lower-case
            parsed["name_servers"] = sorted({ns.lower() for ns in parsed["name_servers"] if ns})
            result["parsed"] = {k: v for k, v in parsed.items() if v is not None}
            _extract_hosting_hints(result)
            return result
        except Exception as e:
            result["errors"].append(f"python-whois: {e}")

    # --- RDAP fallback -------------------------------------------------------
    if REQUESTS_AVAILABLE:
        try:
            url = f"{RDAP_BASE}/domain/{domain}"
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            result["source"] = "rdap"
            result["raw"] = str(data)

            parsed: dict[str, Any] = {"domain_name": domain}
            # Events → dates
            for ev in data.get("events", []):
                action = ev.get("eventAction", "")
                date   = ev.get("eventDate", "")
                if "registration" in action:
                    parsed["creation_date"] = date
                elif "expiration" in action:
                    parsed["expiration_date"] = date
                elif "last changed" in action:
                    parsed["updated_date"] = date

            # Nameservers
            parsed["name_servers"] = sorted(
                ns["ldhName"].lower()
                for ns in data.get("nameservers", [])
                if "ldhName" in ns
            )

            # Status flags
            parsed["status"] = data.get("status", [])

            # Registrar from entities
            for ent in data.get("entities", []):
                roles = ent.get("roles", [])
                vcard = ent.get("vcardArray", [None, []])[1]
                name_val = None
                email_val = None
                for field in vcard:
                    if field[0] == "fn":
                        name_val = field[3]
                    if field[0] == "email":
                        email_val = field[3]
                if "registrar" in roles:
                    parsed["registrar"] = name_val
                if "registrant" in roles:
                    parsed["registrant_name"] = name_val
                    if email_val:
                        parsed["registrant_email"] = email_val

            result["parsed"] = {k: v for k, v in parsed.items() if v is not None}
            _extract_hosting_hints(result)
            return result
        except Exception as e:
            result["errors"].append(f"rdap: {e}")

    result["errors"].append("Neither python-whois nor requests is available.")
    return result


def query_ip_whois(ip: str) -> dict[str, Any]:
    """
    Return WHOIS/RDAP data for an IP address showing ownership and ISP details.

    Queries ARIN RDAP first; falls back to generic RDAP and then plain socket
    WHOIS against whois.iana.org to determine the correct RIR.
    """
    result: dict[str, Any] = {
        "target": ip,
        "type": "ip",
        "source": None,
        "raw": None,
        "parsed": {},
        "errors": [],
    }

    if not REQUESTS_AVAILABLE:
        result["errors"].append("requests library not available")
        return result

    # Try ARIN first (covers most North American allocations)
    for base in (ARIN_RDAP, f"{RDAP_BASE}"):
        try:
            url = f"{base}/ip/{ip}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                result["source"] = base
                result["raw"] = str(data)

                parsed: dict[str, Any] = {"ip": ip}
                parsed["cidr"] = data.get("handle", "")
                parsed["network_name"] = data.get("name", "")
                parsed["country"] = data.get("country", "")
                parsed["type"] = data.get("type", "")

                # Start / end address
                parsed["start_address"] = data.get("startAddress", "")
                parsed["end_address"]   = data.get("endAddress", "")

                # Organisation / ISP from entities
                for ent in data.get("entities", []):
                    roles = ent.get("roles", [])
                    vcard = ent.get("vcardArray", [None, []])[1]
                    name_val = None
                    for field in vcard:
                        if field[0] == "fn":
                            name_val = field[3]
                    if "registrant" in roles or "administrative" in roles:
                        parsed["owner"] = name_val
                    if "abuse" in roles:
                        parsed["abuse_contact"] = name_val

                result["parsed"] = {k: v for k, v in parsed.items() if v}
                return result
        except Exception as e:
            result["errors"].append(f"{base}: {e}")

    return result


def bulk_domain_whois(domains: list[str]) -> list[dict[str, Any]]:
    """Run domain WHOIS for each entry in *domains* and return a list of results."""
    return [query_domain_whois(d.strip()) for d in domains if d.strip()]


def extract_emails_from_whois(whois_result: dict[str, Any]) -> list[str]:
    """Pull email addresses out of a WHOIS result dict."""
    emails: set[str] = set()
    pattern = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    raw = whois_result.get("raw", "") or ""
    emails.update(pattern.findall(raw))
    # Also check parsed fields
    for v in whois_result.get("parsed", {}).values():
        if isinstance(v, str):
            emails.update(pattern.findall(v))
    return sorted(emails)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_hosting_hints(result: dict[str, Any]) -> None:
    """
    Infer hosting provider from nameservers and add hints to parsed data.
    These patterns help analysts quickly identify CDN/cloud providers.
    """
    ns_list = result["parsed"].get("name_servers", [])
    hints = []
    ns_str = " ".join(ns_list).lower()

    provider_patterns = {
        "Cloudflare":     ["cloudflare.com"],
        "AWS Route 53":   ["awsdns"],
        "Google Cloud":   ["googledomains.com", "google.com"],
        "Azure DNS":      ["azure-dns", "msft.net"],
        "GoDaddy":        ["domaincontrol.com"],
        "Namecheap":      ["registrar-servers.com"],
        "DigitalOcean":   ["digitalocean.com"],
        "Fastly":         ["fastly.net"],
    }
    for provider, patterns in provider_patterns.items():
        if any(p in ns_str for p in patterns):
            hints.append(provider)

    if hints:
        result["parsed"]["hosting_hints"] = hints
