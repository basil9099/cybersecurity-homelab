#!/usr/bin/env python3
"""
OSINT Reconnaissance Framework
================================
Aggregates publicly available intelligence about targets from multiple sources:
  WHOIS/RDAP, DNS, GitHub, breach databases, Shodan, Google, and the Wayback Machine.

Designed for penetration testing, threat intelligence, and security research.

Usage examples:
  # Full recon on a domain (no API keys — uses free sources only)
  python osint_framework.py -t example.com --all

  # Domain recon with GitHub org and breach checking
  python osint_framework.py -t example.com --whois --dns --github --breach \\
      --github-org exampleorg --github-token ghp_xxx --hibp-key YOUR_KEY

  # Shodan + certificate transparency
  python osint_framework.py -t example.com --shodan --crtsh \\
      --shodan-key YOUR_KEY

  # Wayback Machine historical data
  python osint_framework.py -t example.com --wayback

  # Generate all report formats into ./reports/
  python osint_framework.py -t example.com --all --output-dir ./reports

Legal notice:
  Use only against targets you own or have explicit written authorization to test.
  OSINT is legal when querying public data, but storage and use of personal data
  may be regulated (GDPR, CCPA). Consult applicable laws before use.
"""

import argparse
import logging
import os
import re
import sys
import time
from typing import Any

# Ensure the project root is on the path for module imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import (
    whois_recon,
    dns_recon,
    social_recon,
    breach_check,
    search_recon,
    reporter,
)

VERSION = "1.0.0"
BANNER  = r"""
  ___  ____ ___ _   _ _____   _____ ____      _    __  __ _____
 / _ \/ ___|_ _| \ | |_   _| |  ___|  _ \    / \  |  \/  | ____|
| | | \___ \| ||  \| | | |   | |_  | |_) |  / _ \ | |\/| |  _|
| |_| |___) | || |\  | | |   |  _| |  _ <  / ___ \| |  | | |___
 \___/|____/___|_| \_| |_|   |_|   |_| \_\/_/   \_\_|  |_|_____|

  OSINT Reconnaissance Framework v{version}
  For authorized penetration testing and threat intelligence only.
""".format(version=VERSION)


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")  # simplified check

MAX_WORDLIST_BYTES = 10 * 1024 * 1024  # 10 MB


def validate_target(target: str) -> str:
    """Validate that *target* looks like a domain name or IP address."""
    target = target.strip().lower()
    if _DOMAIN_RE.match(target) or _IPV4_RE.match(target) or _IPV6_RE.match(target):
        return target
    raise argparse.ArgumentTypeError(
        f"Invalid target '{target}'. Provide a valid domain (e.g. example.com) or IP address."
    )


def validate_ip(ip: str) -> str:
    """Validate an explicit IP address argument."""
    ip = ip.strip()
    if _IPV4_RE.match(ip) or _IPV6_RE.match(ip):
        return ip
    raise argparse.ArgumentTypeError(f"Invalid IP address: '{ip}'")


def validate_wordlist(path: str) -> str:
    """Ensure wordlist file exists and is not excessively large."""
    if not os.path.isfile(path):
        raise argparse.ArgumentTypeError(f"Wordlist file not found: {path}")
    size = os.path.getsize(path)
    if size > MAX_WORDLIST_BYTES:
        raise argparse.ArgumentTypeError(
            f"Wordlist too large ({size / 1024 / 1024:.1f} MB). Maximum is "
            f"{MAX_WORDLIST_BYTES / 1024 / 1024:.0f} MB."
        )
    return path


# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool = False, log_file: str | None = None) -> logging.Logger:
    """Configure the framework logger.

    By default only WARNING+ messages are emitted (operational security).
    ``--verbose`` lowers the threshold to DEBUG and ``--log-file`` writes to disk.
    """
    logger = logging.getLogger("osint_framework")
    logger.setLevel(logging.DEBUG if verbose else logging.WARNING)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    if verbose:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        logger.addHandler(sh)

    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


# ---------------------------------------------------------------------------
# Configuration file support
# ---------------------------------------------------------------------------

def load_config_file(path: str | None) -> dict[str, Any]:
    """Load API keys and options from a TOML config file.

    Returns an empty dict if *path* is ``None`` or the file does not exist.
    Warns if the file has overly permissive permissions (world-readable).
    """
    if not path:
        return {}
    if not os.path.isfile(path):
        return {}

    # Permission check (Unix only)
    try:
        mode = os.stat(path).st_mode & 0o777
        if mode & 0o044:
            print(f"  [!] Config file {path} is world/group-readable (mode {oct(mode)}). "
                  "Consider: chmod 600", file=sys.stderr)
    except OSError:
        pass

    # Python 3.11+ has tomllib in stdlib
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError:
            print("  [!] TOML support requires Python 3.11+ or 'pip install tomli'",
                  file=sys.stderr)
            return {}

    with open(path, "rb") as fh:
        return tomllib.load(fh)


def apply_config(args: argparse.Namespace, config: dict[str, Any]) -> None:
    """Merge config-file values into *args*, CLI flags take precedence."""
    key_map = {
        "hibp_key":       "hibp-key",
        "shodan_key":     "shodan-key",
        "github_token":   "github-token",
        "google_key":     "google-key",
        "google_cse_id":  "google-cse-id",
        "bing_key":       "bing-key",
        "dehashed_email": "dehashed-email",
        "dehashed_key":   "dehashed-key",
    }
    api_section = config.get("api_keys", config)
    for attr, _toml_key in key_map.items():
        if not getattr(args, attr, None):
            value = api_section.get(attr) or api_section.get(_toml_key)
            if value:
                setattr(args, attr, value)


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="osint_framework",
        description="OSINT Reconnaissance Framework — aggregate public intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Target (not required when --gui is used)
    p.add_argument("-t", "--target", type=validate_target,
                   help="Target domain (e.g. example.com) or IP address")
    p.add_argument("--ip", metavar="IP", type=validate_ip,
                   help="Specific IP address to query (optional, auto-resolved if omitted)")

    # Module selection
    modules = p.add_argument_group("Module selection (combine freely; --all enables everything)")
    modules.add_argument("--all",    action="store_true", help="Run all modules")
    modules.add_argument("--whois",  action="store_true", help="WHOIS / RDAP domain & IP lookup")
    modules.add_argument("--dns",    action="store_true", help="DNS enumeration and zone transfer")
    modules.add_argument("--github", action="store_true", help="GitHub org & user reconnaissance")
    modules.add_argument("--breach", action="store_true", help="HaveIBeenPwned breach check")
    modules.add_argument("--shodan", action="store_true", help="Shodan host & search queries")
    modules.add_argument("--crtsh",  action="store_true", help="Certificate transparency (crt.sh)")
    modules.add_argument("--wayback",action="store_true", help="Wayback Machine / Internet Archive")
    modules.add_argument("--dorks",  action="store_true", help="Generate search engine dork queries")

    # API keys
    keys = p.add_argument_group("API keys (all optional; expand data available)")
    keys.add_argument("--hibp-key",      metavar="KEY",   help="HaveIBeenPwned v3 API key")
    keys.add_argument("--shodan-key",    metavar="KEY",   help="Shodan API key")
    keys.add_argument("--github-token",  metavar="TOKEN", help="GitHub personal access token")
    keys.add_argument("--google-key",    metavar="KEY",   help="Google Custom Search API key")
    keys.add_argument("--google-cse-id", metavar="ID",    help="Google Programmable Search Engine ID")
    keys.add_argument("--bing-key",      metavar="KEY",   help="Bing Search API key")
    keys.add_argument("--dehashed-email",metavar="EMAIL", help="DeHashed account email")
    keys.add_argument("--dehashed-key",  metavar="KEY",   help="DeHashed API key")

    # Target details
    targeting = p.add_argument_group("Target details")
    targeting.add_argument("--github-org",   metavar="ORG",
                            help="GitHub organisation name (defaults to target domain prefix)")
    targeting.add_argument("--github-users", metavar="USER", nargs="+",
                            help="GitHub usernames to profile")
    targeting.add_argument("--emails", metavar="EMAIL", nargs="+",
                            help="Email addresses to check for breaches")
    targeting.add_argument("--subdomain-wordlist", metavar="FILE", type=validate_wordlist,
                            help="Path to custom subdomain wordlist (one per line, max 10 MB)")

    # DNS options
    dns_opts = p.add_argument_group("DNS options")
    dns_opts.add_argument("--dns-threads", metavar="N", type=int, default=20,
                          help="Threads for subdomain brute-force (default: 20)")
    dns_opts.add_argument("--skip-zone-transfer", action="store_true",
                          help="Skip zone transfer attempt")

    # Shodan options
    shodan_opts = p.add_argument_group("Shodan options")
    shodan_opts.add_argument("--shodan-query", metavar="Q",
                              help='Custom Shodan query (e.g. \'org:"Example Corp"\')')

    # Wayback options
    wb_opts = p.add_argument_group("Wayback Machine options")
    wb_opts.add_argument("--wayback-from", metavar="YYYYMMDD", help="Start date for history")
    wb_opts.add_argument("--wayback-to",   metavar="YYYYMMDD", help="End date for history")
    wb_opts.add_argument("--wayback-limit", metavar="N", type=int, default=50,
                          help="Max snapshots to retrieve (default: 50)")

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("--output-dir", metavar="DIR", default="./osint_reports",
                     help="Directory for generated reports (default: ./osint_reports)")
    out.add_argument("--output-format", choices=["json", "text", "html", "all"],
                     default="all", help="Report format (default: all)")
    out.add_argument("--quiet", action="store_true", help="Suppress progress output")
    out.add_argument("--no-banner", action="store_true", help="Skip ASCII banner")

    # GUI
    gui = p.add_argument_group("Web GUI")
    gui.add_argument("--gui", action="store_true",
                     help="Launch web-based GUI instead of running a CLI scan")
    gui.add_argument("--gui-port", metavar="PORT", type=int, default=8080,
                     help="Port for the GUI web server (default: 8080)")

    # Logging
    log = p.add_argument_group("Logging")
    log.add_argument("--verbose", action="store_true",
                     help="Enable verbose/debug logging to stderr")
    log.add_argument("--log-file", metavar="FILE",
                     help="Write structured logs to FILE")

    # Configuration file
    cfg = p.add_argument_group("Configuration")
    cfg.add_argument("--config", metavar="FILE",
                     help="Path to TOML config file with API keys and options")

    return p


# ---------------------------------------------------------------------------
# Progress helpers
# ---------------------------------------------------------------------------

class Progress:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet

    def info(self, msg: str):
        if not self.quiet:
            print(f"  [*] {msg}")

    def ok(self, msg: str):
        if not self.quiet:
            print(f"  [+] {msg}")

    def warn(self, msg: str):
        if not self.quiet:
            print(f"  [!] {msg}")

    def section(self, title: str):
        if not self.quiet:
            print(f"\n{'─'*60}")
            print(f"  {title}")
            print(f"{'─'*60}")


# ---------------------------------------------------------------------------
# Module runners
# ---------------------------------------------------------------------------

def run_whois(args: argparse.Namespace, prog: Progress) -> tuple[dict, dict]:
    prog.section("WHOIS / RDAP")
    prog.info(f"Querying domain WHOIS for {args.target} ...")
    domain_result = whois_recon.query_domain_whois(args.target)
    if domain_result.get("errors"):
        for e in domain_result["errors"]:
            prog.warn(f"WHOIS: {e}")
    else:
        parsed = domain_result.get("parsed", {})
        prog.ok(f"Registrar : {parsed.get('registrar', 'N/A')}")
        prog.ok(f"Registrant: {parsed.get('registrant_name', 'N/A')}")
        prog.ok(f"Created   : {parsed.get('creation_date', 'N/A')}")
        hints = parsed.get("hosting_hints", [])
        if hints:
            prog.ok(f"Hosting   : {', '.join(hints)}")
        # Extract emails from WHOIS
        emails = whois_recon.extract_emails_from_whois(domain_result)
        if emails:
            prog.ok(f"Emails found in WHOIS: {emails}")

    # IP WHOIS
    ip = args.ip
    ip_result: dict[str, Any] = {}
    if ip:
        prog.info(f"Querying IP WHOIS for {ip} ...")
        ip_result = whois_recon.query_ip_whois(ip)
        parsed_ip = ip_result.get("parsed", {})
        prog.ok(f"IP owner: {parsed_ip.get('owner', 'N/A')} / {parsed_ip.get('network_name', 'N/A')}")

    return domain_result, ip_result


def run_dns(args: argparse.Namespace, prog: Progress) -> dict[str, Any]:
    prog.section("DNS Reconnaissance")

    wordlist = None
    if args.subdomain_wordlist:
        try:
            with open(args.subdomain_wordlist, encoding="utf-8", errors="ignore") as fh:
                wordlist = [
                    line.strip()
                    for line in fh
                    if line.strip() and line.strip().isascii() and not line.startswith("#")
                ]
            prog.info(f"Loaded {len(wordlist)} subdomains from {args.subdomain_wordlist}")
        except Exception as e:
            prog.warn(f"Could not load wordlist: {e}")

    prog.info(f"Enumerating DNS records for {args.target} ...")
    result = dns_recon.enumerate_dns(args.target, subdomains=wordlist,
                                      threads=args.dns_threads)

    if result.get("errors"):
        for e in result["errors"]:
            prog.warn(e)

    records = result.get("records", {})
    for rtype, values in records.items():
        prog.ok(f"{rtype}: {values}")

    ns = result.get("nameservers", [])
    if ns:
        prog.ok(f"Nameservers: {ns}")

    mx = result.get("mx_servers", [])
    if mx:
        prog.ok(f"MX servers: {[m['host'] for m in mx]}")

    es = result.get("email_security", {})
    if es.get("spf"):
        prog.ok(f"SPF: {es['spf'][:80]}")
    else:
        prog.warn("No SPF record found")
    if es.get("dmarc"):
        prog.ok(f"DMARC policy: {es.get('dmarc_policy', 'none')}")
    else:
        prog.warn("No DMARC record found")

    zt = result.get("zone_transfer", {})
    if zt.get("success"):
        prog.warn(f"ZONE TRANSFER SUCCEEDED via {zt.get('nameserver')} — {len(zt.get('records', []))} records leaked!")
    elif zt.get("attempted"):
        prog.ok("Zone transfer refused (expected/good)")

    subs = result.get("subdomains", [])
    prog.ok(f"Subdomains discovered: {len(subs)}")
    for sub in subs[:10]:
        prog.info(f"  {sub['subdomain']}: {sub.get('A', [])}")
    if len(subs) > 10:
        prog.info(f"  ... and {len(subs)-10} more")

    return result


def run_github(args: argparse.Namespace, prog: Progress) -> tuple[dict, list]:
    prog.section("GitHub Reconnaissance")
    token   = args.github_token
    org_name = args.github_org or args.target.split(".")[0]

    prog.info(f"Querying GitHub org: {org_name} ...")
    org_result = social_recon.github_search_org(org_name, token=token)
    if org_result.get("errors"):
        for e in org_result["errors"]:
            prog.warn(f"GitHub org: {e}")
    else:
        meta = org_result.get("metadata", {})
        prog.ok(f"Org: {meta.get('name')} — {meta.get('public_repos')} public repos")
        prog.ok(f"Members: {len(org_result.get('members', []))}")

    # Profile specific users if given
    user_profiles: list[dict] = []
    if args.github_users:
        for username in args.github_users:
            prog.info(f"Profiling GitHub user: {username}")
            profile = social_recon.github_user_profile(username, token=token)
            user_profiles.append(profile)
            p = profile.get("profile", {})
            prog.ok(f"  {username}: {p.get('name')} / {p.get('company')} / {p.get('location')}")
            if profile.get("emails_found"):
                prog.ok(f"  Emails: {profile['emails_found']}")

    # LinkedIn dorks
    ld = social_recon.generate_linkedin_dorks(args.github_org or args.target.split(".")[0],
                                               domain=args.target)
    prog.ok(f"Generated {len(ld['dorks'])} LinkedIn dork queries")

    return org_result, user_profiles


def run_breach(args: argparse.Namespace, prog: Progress) -> tuple[list, dict]:
    prog.section("Breach Database Check (HaveIBeenPwned)")

    emails = args.emails or []
    # Collect emails from WHOIS (passed via run state later; use empty list here)
    if not emails:
        prog.warn("No email addresses specified (--emails). Use --emails addr@domain.com ...")
        return [], {}

    if not args.hibp_key:
        prog.warn("HIBP API key not provided (--hibp-key). Skipping breach check.")
        return [], {}

    prog.info(f"Checking {len(emails)} email(s) against HaveIBeenPwned ...")
    results = breach_check.bulk_check_emails_hibp(emails, args.hibp_key)

    for r in results:
        email = r["email"]
        if r.get("breached"):
            prog.warn(f"{email} BREACHED in {r['breach_count']} database(s): "
                      f"{[b['name'] for b in r.get('breaches', [])[:3]]}")
        else:
            prog.ok(f"{email} not found in known breaches")

    summary = breach_check.summarise_breach_risk(results)
    prog.ok(f"Breach risk level: {summary['risk_level']} "
            f"({summary['breached_count']}/{summary['total_emails_checked']} breached)")

    return results, summary


def run_shodan(args: argparse.Namespace, prog: Progress,
               discovered_ips: list[str]) -> list[dict]:
    prog.section("Shodan Reconnaissance")

    if not args.shodan_key:
        prog.warn("Shodan API key not provided (--shodan-key). Skipping Shodan.")
        return []

    results: list[dict] = []

    # Host lookups for discovered IPs
    for ip in discovered_ips[:5]:  # Limit to 5 to avoid excessive API usage
        prog.info(f"Shodan host lookup: {ip}")
        r = search_recon.shodan_host_info(ip, args.shodan_key)
        if not r.get("errors"):
            prog.ok(f"  {ip}: ports={r.get('ports',[])} vulns={r.get('vulnerabilities',[])}")
            results.append(r)
        else:
            for e in r["errors"]:
                prog.warn(f"  Shodan: {e}")
        time.sleep(1)  # Rate limit

    # Custom query
    query = args.shodan_query or f'org:"{args.target}"'
    prog.info(f"Shodan search: {query}")
    sr = search_recon.shodan_search(query, args.shodan_key, max_results=20)
    if not sr.get("errors"):
        prog.ok(f"Shodan search found {sr.get('total',0)} results")
        for match in sr.get("matches", [])[:5]:
            prog.info(f"  {match.get('ip')}:{match.get('port')} — {match.get('org')}")

    return results


def run_crtsh(args: argparse.Namespace, prog: Progress) -> dict:
    prog.section("Certificate Transparency (crt.sh)")
    prog.info(f"Querying crt.sh for {args.target} ...")
    result = search_recon.crtsh_subdomain_enum(args.target)
    if result.get("errors"):
        for e in result["errors"]:
            prog.warn(f"crt.sh: {e}")
    else:
        subs = result.get("subdomains", [])
        prog.ok(f"Certificate transparency: {result.get('cert_count',0)} certs, {len(subs)} unique subdomains")
        for s in subs[:10]:
            prog.info(f"  {s}")
    return result


def run_wayback(args: argparse.Namespace, prog: Progress) -> tuple[dict, dict]:
    prog.section("Wayback Machine / Internet Archive")

    prog.info(f"Checking Wayback Machine availability for {args.target} ...")
    avail = search_recon.wayback_availability(f"https://{args.target}")
    if avail.get("archived") and avail.get("snapshot"):
        snap = avail["snapshot"]
        prog.ok(f"Most recent snapshot: {snap.get('timestamp')} — {snap.get('url')}")

    prog.info(f"Fetching snapshot history (limit={args.wayback_limit}) ...")
    history = search_recon.wayback_history(
        f"https://{args.target}",
        limit=args.wayback_limit,
        from_date=args.wayback_from or "",
        to_date=args.wayback_to or "",
    )
    snapshots = history.get("snapshots", [])
    prog.ok(f"Retrieved {len(snapshots)} snapshots")
    for snap in snapshots[:5]:
        prog.info(f"  [{snap.get('timestamp','')}] HTTP {snap.get('statuscode','?')}")

    prog.info(f"Fetching archived URLs for *.{args.target} ...")
    urls = search_recon.wayback_domain_urls(args.target, limit=200)
    archived = urls.get("urls", [])
    prog.ok(f"Found {len(archived)} archived URLs")

    return history, urls


def run_dorks(args: argparse.Namespace, prog: Progress) -> dict:
    prog.section("Search Engine Dorks")
    dorks = search_recon.generate_recon_dorks(args.target)
    total = sum(len(v) for v in dorks.values())
    prog.ok(f"Generated {total} dork queries across {len(dorks)} categories")
    for cat, queries in dorks.items():
        prog.info(f"  {cat}: {len(queries)} queries")
    return dorks


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def collect_all_emails(whois_result: dict, github_org: dict,
                        github_users: list[dict], extra: list[str]) -> list[str]:
    """Aggregate all discovered email addresses from all modules."""
    emails: set[str] = set(extra or [])
    # From WHOIS
    emails.update(whois_recon.extract_emails_from_whois(whois_result))
    # From GitHub org metadata
    org_email = (github_org.get("metadata") or {}).get("email")
    if org_email:
        emails.add(org_email)
    # From GitHub user profiles
    for user in github_users:
        p = user.get("profile", {})
        if p.get("email"):
            emails.add(p["email"])
        emails.update(user.get("emails_found", []))
    return sorted(e for e in emails if e)


def resolve_target_ips(target: str) -> list[str]:
    """Resolve a domain to IPs for Shodan lookups."""
    import socket
    try:
        return list({r[4][0] for r in socket.getaddrinfo(target, None)})
    except Exception:
        return []


def main():
    parser = build_arg_parser()
    args   = parser.parse_args()

    # Launch web GUI if requested (no target needed)
    if args.gui:
        from gui.app import launch_gui
        launch_gui(host="0.0.0.0", port=args.gui_port)
        return

    # In CLI mode, --target is required
    if not args.target:
        parser.error("the following arguments are required: -t/--target")

    prog   = Progress(quiet=args.quiet)

    # Logging
    logger = setup_logging(verbose=args.verbose, log_file=args.log_file)
    logger.info("OSINT Framework started — target: %s", args.target)

    # Config file
    if args.config:
        config = load_config_file(args.config)
        if config:
            apply_config(args, config)
            logger.info("Loaded config from %s", args.config)

    if not args.no_banner:
        print(BANNER)

    # Expand --all
    if args.all:
        args.whois = args.dns = args.github = args.breach = True
        args.shodan = args.crtsh = args.wayback = args.dorks = True

    if not any([args.whois, args.dns, args.github, args.breach,
                args.shodan, args.crtsh, args.wayback, args.dorks]):
        prog.warn("No modules selected. Use --all or specify modules (--whois, --dns, etc.)")
        parser.print_usage()
        sys.exit(1)

    prog.info(f"Target: {args.target}")
    if args.ip:
        prog.info(f"IP: {args.ip}")

    # Collect results
    whois_result:    dict = {}
    ip_whois_result: dict = {}
    dns_result:      dict = {}
    github_org:      dict = {}
    github_users:    list = []
    breach_results:  list = []
    breach_summary:  dict = {}
    shodan_results:  list = []
    crtsh_result:    dict = {}
    wayback_history: dict = {}
    wayback_urls:    dict = {}
    search_dorks:    dict = {}
    linkedin_dorks:  dict = {}

    if args.whois:
        whois_result, ip_whois_result = run_whois(args, prog)

    if args.dns:
        dns_result = run_dns(args, prog)

    if args.github:
        github_org, github_users = run_github(args, prog)
        linkedin_dorks = social_recon.generate_linkedin_dorks(
            args.github_org or args.target.split(".")[0], domain=args.target
        )

    # Gather all discovered emails
    all_emails = collect_all_emails(whois_result, github_org, github_users, args.emails or [])
    if all_emails:
        prog.ok(f"Total emails collected: {len(all_emails)}: {all_emails[:5]}")

    if args.breach:
        # Use collected emails if none explicitly provided
        if not args.emails and all_emails:
            args.emails = all_emails
        breach_results, breach_summary = run_breach(args, prog)

    # Resolve IPs for Shodan
    target_ips: list[str] = []
    if args.ip:
        target_ips = [args.ip]
    elif dns_result.get("records", {}).get("A"):
        target_ips = dns_result["records"]["A"]
    else:
        target_ips = resolve_target_ips(args.target)

    if args.shodan:
        shodan_results = run_shodan(args, prog, target_ips)

    if args.crtsh:
        crtsh_result = run_crtsh(args, prog)

    if args.wayback:
        wayback_history, wayback_urls = run_wayback(args, prog)

    if args.dorks:
        search_dorks = run_dorks(args, prog)

    # Build unified profile
    prog.section("Building Target Profile")
    profile = reporter.build_target_profile(
        target          = args.target,
        whois_result    = whois_result    or None,
        ip_whois        = ip_whois_result or None,
        dns_result      = dns_result      or None,
        github_org      = github_org      or None,
        github_users    = github_users    or None,
        breach_results  = breach_results  or None,
        breach_summary  = breach_summary  or None,
        shodan_results  = shodan_results  or None,
        crtsh_result    = crtsh_result    or None,
        wayback_urls    = wayback_urls    or None,
        wayback_history = wayback_history or None,
        search_dorks    = search_dorks    or None,
        linkedin_dorks  = linkedin_dorks  or None,
        emails_found    = all_emails      or None,
    )

    # Print risk summary
    risk = profile["risk_assessment"]
    prog.section("Risk Assessment")
    prog.info(f"Overall risk: {risk['overall_risk']}")
    counts = risk["counts"]
    prog.info(f"  Critical:{counts['CRITICAL']}  High:{counts['HIGH']}  "
              f"Medium:{counts['MEDIUM']}  Low:{counts['LOW']}  Info:{counts['INFO']}")
    for finding in risk["findings"][:10]:
        prog.info(f"  [{finding['severity']}] {finding['description']}")

    # Generate reports
    prog.section("Generating Reports")
    fmt = args.output_format
    if fmt == "all":
        paths = reporter.generate_all_reports(profile, args.output_dir)
    else:
        os.makedirs(args.output_dir, exist_ok=True)
        from datetime import datetime
        ts   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base = f"{args.target.replace('.','_')}_{ts}"
        ext_map = {"json": ".json", "text": ".txt", "html": ".html"}
        out_path = os.path.join(args.output_dir, base + ext_map[fmt])
        if fmt == "json":
            reporter.generate_json_report(profile, out_path)
        elif fmt == "text":
            reporter.generate_text_report(profile, out_path)
        elif fmt == "html":
            reporter.generate_html_report(profile, out_path)
        paths = {fmt: out_path}

    for fmt_name, path in paths.items():
        prog.ok(f"Report [{fmt_name.upper()}]: {os.path.abspath(path)}")

    prog.section("Complete")
    prog.ok(f"OSINT reconnaissance finished for {args.target}")

    return profile


if __name__ == "__main__":
    _frozen = getattr(sys, "frozen", False)
    try:
        main()
    except SystemExit as exc:
        if _frozen:
            input("\nPress Enter to exit...")
        raise
    except Exception as exc:
        print(f"\n[!] Unexpected error: {exc}", file=sys.stderr)
        if _frozen:
            input("\nPress Enter to exit...")
        sys.exit(1)
    else:
        if _frozen:
            input("\nPress Enter to exit...")
