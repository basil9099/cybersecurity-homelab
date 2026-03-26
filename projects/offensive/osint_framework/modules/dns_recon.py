"""
DNS Reconnaissance Module
--------------------------
Maps organisational infrastructure by querying multiple DNS record types and
performing subdomain enumeration.

Techniques covered:
  • Record-type enumeration (A, AAAA, MX, TXT, NS, CNAME, SOA, PTR, SRV, CAA)
  • Zone transfer attempt (AXFR) — succeeds on misconfigured nameservers
  • Subdomain brute-force using a built-in wordlist
  • SPF / DMARC / DKIM policy extraction from TXT records
  • Reverse DNS (PTR) lookups on discovered IPs
  • DNS-based email server mapping via MX records
"""

import socket
import re
import time
import concurrent.futures
from typing import Any

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.rdatatype
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ---------------------------------------------------------------------------
# Common subdomain wordlist — covers typical enterprise naming conventions
# ---------------------------------------------------------------------------
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "remote",
    "vpn", "gateway", "portal", "admin", "login", "secure", "mx",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "dev", "staging", "stage", "test", "uat", "qa", "preprod",
    "api", "api2", "v1", "v2", "rest", "graphql",
    "app", "apps", "web", "cloud", "cdn",
    "blog", "shop", "store", "pay", "payment", "checkout",
    "help", "support", "docs", "wiki", "kb", "status",
    "git", "gitlab", "github", "svn", "jenkins", "ci", "jira",
    "confluence", "slack", "chat",
    "monitor", "metrics", "grafana", "kibana", "elastic",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "backup", "archive",
    "mobile", "m", "www2",
    "internal", "intranet", "corp", "extranet",
    "download", "downloads", "update", "updates", "assets", "static",
    "img", "images", "media", "files",
    "auth", "sso", "oauth", "login", "accounts",
    "calendar", "meet", "video", "webex",
    "exchange", "owa", "autodiscover",
    "mx1", "mx2", "relay", "outbound", "inbound",
]

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA", "SRV"]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enumerate_dns(domain: str, subdomains: list[str] | None = None,
                  threads: int = 20) -> dict[str, Any]:
    """
    Full DNS enumeration for *domain*.

    Returns a structured result with all record types, zone transfer attempt,
    subdomain brute-force results, and extracted metadata (SPF, DMARC, MX
    servers, nameservers).
    """
    result: dict[str, Any] = {
        "target": domain,
        "records": {},
        "zone_transfer": {"attempted": False, "success": False, "records": []},
        "subdomains": [],
        "email_security": {},
        "nameservers": [],
        "mx_servers": [],
        "errors": [],
    }

    if not DNS_AVAILABLE:
        result["errors"].append("dnspython not installed — install with: pip install dnspython")
        return result

    # --- Standard record queries -------------------------------------------
    for rtype in RECORD_TYPES:
        records = _query_records(domain, rtype)
        if records:
            result["records"][rtype] = records

    # Post-process well-known record types
    result["nameservers"]  = _parse_nameservers(result["records"].get("NS", []))
    result["mx_servers"]   = _parse_mx(result["records"].get("MX", []))
    result["email_security"] = _parse_email_security(result["records"].get("TXT", []))

    # --- Zone transfer (AXFR) ----------------------------------------------
    # Misconfigured DNS servers allow any client to request a full zone dump.
    # This is a quick passive check — no brute-force involved.
    _attempt_zone_transfer(domain, result)

    # --- Subdomain brute-force ---------------------------------------------
    wordlist = subdomains if subdomains else COMMON_SUBDOMAINS
    result["subdomains"] = _bruteforce_subdomains(domain, wordlist, threads)

    return result


def query_record(domain: str, rtype: str) -> dict[str, Any]:
    """Convenience wrapper — query a single record type."""
    return {
        "target": domain,
        "type": rtype,
        "records": _query_records(domain, rtype),
    }


def reverse_dns(ip: str) -> str | None:
    """PTR lookup: IP → hostname."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def bulk_reverse_dns(ips: list[str], threads: int = 20) -> dict[str, str | None]:
    """Reverse DNS for a list of IPs, returns {ip: hostname}."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(reverse_dns, ip): ip for ip in ips}
        return {futures[f]: f.result() for f in concurrent.futures.as_completed(futures)}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _query_records(domain: str, rtype: str) -> list[str]:
    """Query *domain* for *rtype* DNS records; return list of string values."""
    if not DNS_AVAILABLE:
        return []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, rtype)
        results = []
        for rdata in answers:
            results.append(str(rdata))
        return results
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout,
            dns.exception.DNSException, dns.resolver.NoNameservers):
        return []
    except Exception:
        return []


def _attempt_zone_transfer(domain: str, result: dict[str, Any]) -> None:
    """
    Try AXFR zone transfer against each authoritative nameserver.
    Most modern servers refuse this (REFUSED response), but legacy or
    misconfigured servers may comply, leaking the entire zone.
    """
    ns_list = result["nameservers"]
    if not ns_list:
        # Resolve NS records manually
        ns_list = _query_records(domain, "NS")

    result["zone_transfer"]["attempted"] = bool(ns_list)

    for i, ns in enumerate(ns_list):
        if i > 0:
            time.sleep(0.5)  # Brief delay between AXFR attempts to reduce IDS triggers
        ns_clean = ns.rstrip(".")
        try:
            ns_ip = socket.gethostbyname(ns_clean)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
            # If we get here, zone transfer succeeded (misconfiguration!)
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(f"{name}.{domain} {rdataset.ttl} "
                                       f"{dns.rdatatype.to_text(rdataset.rdtype)} {rdata}")
            result["zone_transfer"]["success"] = True
            result["zone_transfer"]["nameserver"] = ns_clean
            result["zone_transfer"]["records"] = records
            return  # Stop after first successful transfer
        except Exception:
            continue  # Most servers will refuse — this is expected


def _bruteforce_subdomains(domain: str, wordlist: list[str],
                            threads: int,
                            batch_size: int = 50,
                            batch_delay: float = 0.3) -> list[dict[str, Any]]:
    """
    Resolve each subdomain candidate against DNS in batches.

    Processes *batch_size* candidates at a time, pausing *batch_delay* seconds
    between batches to avoid overwhelming the target's nameservers or triggering
    IDS alerts.
    """
    found: list[dict[str, Any]] = []

    def _check(sub: str) -> dict[str, Any] | None:
        fqdn = f"{sub}.{domain}"
        a_records = _query_records(fqdn, "A")
        aaaa_records = _query_records(fqdn, "AAAA")
        cname_records = _query_records(fqdn, "CNAME")
        if a_records or aaaa_records or cname_records:
            return {
                "subdomain": fqdn,
                "A": a_records,
                "AAAA": aaaa_records,
                "CNAME": cname_records,
            }
        return None

    # Process in batches to control query rate
    for batch_start in range(0, len(wordlist), batch_size):
        batch = wordlist[batch_start:batch_start + batch_size]
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(_check, sub) for sub in batch]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    found.append(res)
        # Pause between batches (skip delay after final batch)
        if batch_start + batch_size < len(wordlist):
            time.sleep(batch_delay)

    return sorted(found, key=lambda x: x["subdomain"])


def _parse_nameservers(ns_records: list[str]) -> list[str]:
    return sorted(ns.rstrip(".").lower() for ns in ns_records if ns)


def _parse_mx(mx_records: list[str]) -> list[dict[str, Any]]:
    """Parse MX records into {priority, host} dicts."""
    servers = []
    for rec in mx_records:
        parts = rec.strip().split()
        if len(parts) >= 2:
            servers.append({
                "priority": int(parts[0]) if parts[0].isdigit() else 0,
                "host": parts[1].rstrip("."),
            })
    return sorted(servers, key=lambda x: x["priority"])


def _parse_email_security(txt_records: list[str]) -> dict[str, Any]:
    """
    Extract SPF, DMARC, and DKIM hints from TXT records.

    SPF  → "v=spf1 ..."   restricts which IPs may send email for the domain
    DMARC→ "v=DMARC1 ..."  specifies policy for failing SPF/DKIM messages
    """
    info: dict[str, Any] = {}
    for txt in txt_records:
        txt_clean = txt.strip('"')
        if txt_clean.startswith("v=spf1"):
            info["spf"] = txt_clean
            # Summarise allowed senders
            allowed = re.findall(r"(?:ip4|ip6|include|a|mx):[^\s]+", txt_clean)
            info["spf_allowed_sources"] = allowed
        elif txt_clean.startswith("v=DMARC1"):
            info["dmarc"] = txt_clean
            policy_match = re.search(r"p=(\w+)", txt_clean)
            if policy_match:
                info["dmarc_policy"] = policy_match.group(1)  # none/quarantine/reject
        elif "v=DKIM1" in txt_clean or "_domainkey" in txt_clean:
            info.setdefault("dkim_hints", []).append(txt_clean[:80])
    return info
