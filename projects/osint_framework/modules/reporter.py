"""
Target Profile Aggregator & Reporter
--------------------------------------
Correlates results from all OSINT modules into a unified target dossier and
generates structured reports in JSON, plain-text, and HTML formats.

Profile sections:
  • Organisation overview (WHOIS registrant, GitHub org)
  • Infrastructure map (DNS records, subdomains, Shodan services)
  • People / employees (GitHub members, LinkedIn dorks, emails)
  • Email security posture (SPF, DMARC, MX)
  • Breach exposure summary (HIBP results)
  • Historical data (Wayback Machine snapshots, cert transparency)
  • Search dorks (ready-to-use recon queries)
  • Risk assessment matrix
  • Relationship map (entity links for mind-map generation)
"""

import json
import os
import re
import textwrap
from datetime import datetime
from typing import Any


# ---------------------------------------------------------------------------
# Profile aggregation
# ---------------------------------------------------------------------------

def build_target_profile(
    target: str,
    whois_result:   dict[str, Any] | None = None,
    ip_whois:       dict[str, Any] | None = None,
    dns_result:     dict[str, Any] | None = None,
    github_org:     dict[str, Any] | None = None,
    github_users:   list[dict[str, Any]] | None = None,
    breach_results: list[dict[str, Any]] | None = None,
    breach_summary: dict[str, Any] | None = None,
    shodan_results: list[dict[str, Any]] | None = None,
    crtsh_result:   dict[str, Any] | None = None,
    wayback_urls:   dict[str, Any] | None = None,
    wayback_history:dict[str, Any] | None = None,
    search_dorks:   dict[str, list[str]] | None = None,
    linkedin_dorks: dict[str, Any] | None = None,
    emails_found:   list[str] | None = None,
) -> dict[str, Any]:
    """
    Assemble all module outputs into a single profile dictionary.
    This is the canonical data structure for report generation.
    """
    profile: dict[str, Any] = {
        "meta": {
            "target":      target,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "framework":   "OSINT-Framework v1.0",
        },
        "organisation": {},
        "infrastructure": {
            "dns":         {},
            "subdomains":  [],
            "services":    [],
            "certificates": [],
        },
        "people": {
            "github_members": [],
            "email_candidates": [],
            "linkedin_dorks": [],
        },
        "breach_exposure": {
            "summary": {},
            "detail":  [],
        },
        "historical": {
            "wayback_snapshots": [],
            "archived_urls":    [],
        },
        "recon_dorks": {},
        "risk_assessment": {},
        "relationships": [],
    }

    # --- Organisation -------------------------------------------------------
    if whois_result:
        parsed = whois_result.get("parsed", {})
        profile["organisation"].update({
            "domain":           parsed.get("domain_name", target),
            "registrar":        parsed.get("registrar"),
            "registrant_name":  parsed.get("registrant_name"),
            "registrant_org":   parsed.get("registrant_org"),
            "registrant_email": parsed.get("registrant_email"),
            "registrant_country": parsed.get("registrant_country"),
            "created":          parsed.get("creation_date"),
            "expires":          parsed.get("expiration_date"),
            "nameservers":      parsed.get("name_servers", []),
            "hosting_hints":    parsed.get("hosting_hints", []),
            "whois_errors":     whois_result.get("errors", []),
        })
    if ip_whois:
        parsed = ip_whois.get("parsed", {})
        profile["organisation"]["ip_info"] = {
            "owner":   parsed.get("owner"),
            "cidr":    parsed.get("cidr"),
            "country": parsed.get("country"),
            "isp":     parsed.get("network_name"),
        }
    if github_org:
        meta = github_org.get("metadata", {})
        profile["organisation"]["github"] = {
            "name":         meta.get("name"),
            "description":  meta.get("description"),
            "blog":         meta.get("blog"),
            "email":        meta.get("email"),
            "location":     meta.get("location"),
            "public_repos": meta.get("public_repos"),
        }

    # --- Infrastructure -----------------------------------------------------
    if dns_result:
        profile["infrastructure"]["dns"] = {
            "records":      dns_result.get("records", {}),
            "nameservers":  dns_result.get("nameservers", []),
            "mx_servers":   dns_result.get("mx_servers", []),
            "email_security": dns_result.get("email_security", {}),
            "zone_transfer": dns_result.get("zone_transfer", {}),
        }
        profile["infrastructure"]["subdomains"] = dns_result.get("subdomains", [])
    if crtsh_result:
        profile["infrastructure"]["certificates"] = crtsh_result.get("subdomains", [])
    # Merge cert subdomains into DNS subdomains (deduplicated)
    dns_subs  = {s["subdomain"] for s in profile["infrastructure"]["subdomains"]}
    cert_subs = set(profile["infrastructure"]["certificates"])
    extra = cert_subs - dns_subs
    if extra:
        profile["infrastructure"]["cert_only_subdomains"] = sorted(extra)

    if shodan_results:
        profile["infrastructure"]["services"] = shodan_results

    # --- People -------------------------------------------------------------
    if github_org:
        profile["people"]["github_members"] = github_org.get("members", [])
    if github_users:
        profile["people"]["github_user_profiles"] = github_users
    if emails_found:
        # Deduplicate preserving order
        seen: set[str] = set()
        unique_emails = []
        for e in emails_found:
            if e and e not in seen:
                seen.add(e)
                unique_emails.append(e)
        profile["people"]["email_candidates"] = unique_emails
    if linkedin_dorks:
        profile["people"]["linkedin_dorks"] = linkedin_dorks.get("dorks", [])

    # --- Breach exposure ----------------------------------------------------
    if breach_summary:
        profile["breach_exposure"]["summary"] = breach_summary
    if breach_results:
        profile["breach_exposure"]["detail"] = breach_results

    # --- Historical ---------------------------------------------------------
    if wayback_history:
        profile["historical"]["wayback_snapshots"] = wayback_history.get("snapshots", [])
    if wayback_urls:
        profile["historical"]["archived_urls"] = wayback_urls.get("urls", [])

    # --- Dorks --------------------------------------------------------------
    if search_dorks:
        profile["recon_dorks"] = search_dorks

    # --- Risk assessment ----------------------------------------------------
    profile["risk_assessment"] = _build_risk_assessment(profile)

    # --- Relationships -------------------------------------------------------
    profile["relationships"] = _build_relationships(profile)

    return profile


# ---------------------------------------------------------------------------
# Risk assessment
# ---------------------------------------------------------------------------

def _build_risk_assessment(profile: dict[str, Any]) -> dict[str, Any]:
    """
    Generate a risk matrix based on findings across all modules.
    Each finding has a severity (CRITICAL/HIGH/MEDIUM/LOW/INFO).
    """
    findings: list[dict[str, str]] = []
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    def add_finding(severity: str, category: str, description: str):
        findings.append({"severity": severity, "category": category, "description": description})
        risk_counts[severity] += 1

    # Zone transfer
    zt = profile["infrastructure"]["dns"].get("zone_transfer", {})
    if zt.get("success"):
        add_finding("CRITICAL", "DNS", "Zone transfer (AXFR) succeeded — full DNS zone exposed")

    # Breach data
    bs = profile["breach_exposure"].get("summary", {})
    if bs.get("risk_level") == "CRITICAL":
        add_finding("CRITICAL", "Breach", "Passwords found in breach databases — credential stuffing risk")
    elif bs.get("risk_level") == "HIGH":
        add_finding("HIGH", "Breach", f"Sensitive data classes exposed: {', '.join(bs.get('high_risk_classes_exposed', []))}")
    elif bs.get("risk_level") == "MEDIUM":
        add_finding("MEDIUM", "Breach", f"{bs.get('breach_count', 0)} email(s) found in breach databases")

    # Email security
    email_sec = profile["infrastructure"]["dns"].get("email_security", {})
    if not email_sec.get("spf"):
        add_finding("HIGH", "Email Security", "No SPF record — domain vulnerable to email spoofing")
    if not email_sec.get("dmarc"):
        add_finding("HIGH", "Email Security", "No DMARC policy — phishing emails may not be rejected")
    else:
        policy = email_sec.get("dmarc_policy", "none")
        if policy == "none":
            add_finding("MEDIUM", "Email Security", "DMARC policy is 'none' — monitoring only, no enforcement")

    # Subdomains
    sub_count = len(profile["infrastructure"]["subdomains"])
    cert_only = len(profile["infrastructure"].get("cert_only_subdomains", []))
    if sub_count + cert_only > 20:
        add_finding("INFO", "Attack Surface", f"Large subdomain footprint: {sub_count + cert_only} subdomains discovered")
    elif sub_count + cert_only > 0:
        add_finding("INFO", "Attack Surface", f"{sub_count + cert_only} subdomains discovered")

    # Shodan services
    services = profile["infrastructure"].get("services", [])
    for svc in services:
        vulns = svc.get("vulnerabilities", []) if isinstance(svc, dict) else []
        if vulns:
            add_finding("CRITICAL", "Vulnerabilities",
                        f"Shodan reports CVEs on {svc.get('ip','?')}: {', '.join(vulns[:3])}")
        ports = svc.get("ports", []) if isinstance(svc, dict) else []
        exposed_risky = [p for p in ports if p in (21, 23, 3389, 5900, 445, 139, 3306, 5432, 27017, 6379)]
        if exposed_risky:
            add_finding("HIGH", "Exposed Services",
                        f"Risky ports exposed on {svc.get('ip', '?')}: {exposed_risky}")

    # Historical data
    arc_count = len(profile["historical"].get("archived_urls", []))
    if arc_count > 0:
        add_finding("INFO", "Historical", f"{arc_count} URLs archived in Wayback Machine — may reveal historical paths")

    # People / employees
    member_count = len(profile["people"].get("github_members", []))
    if member_count > 0:
        add_finding("INFO", "People", f"{member_count} GitHub org members enumerated")

    email_count = len(profile["people"].get("email_candidates", []))
    if email_count > 0:
        add_finding("INFO", "People", f"{email_count} email addresses collected")

    overall = "LOW"
    if risk_counts["CRITICAL"] > 0:
        overall = "CRITICAL"
    elif risk_counts["HIGH"] > 0:
        overall = "HIGH"
    elif risk_counts["MEDIUM"] > 0:
        overall = "MEDIUM"

    return {
        "overall_risk": overall,
        "counts":       risk_counts,
        "findings":     sorted(findings, key=lambda f: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(f["severity"])),
    }


# ---------------------------------------------------------------------------
# Relationship mapping
# ---------------------------------------------------------------------------

def _build_relationships(profile: dict[str, Any]) -> list[dict[str, str]]:
    """
    Build an entity relationship list for mind-map / graph visualisation.
    Each entry is {from, to, relationship_type}.
    """
    edges: list[dict[str, str]] = []
    target = profile["meta"]["target"]

    # Domain → Registrar
    registrar = profile["organisation"].get("registrar")
    if registrar:
        edges.append({"from": target, "to": registrar, "type": "registered_with"})

    # Domain → Nameservers
    for ns in profile["infrastructure"]["dns"].get("nameservers", []):
        edges.append({"from": target, "to": ns, "type": "nameserver"})

    # Domain → MX servers
    for mx in profile["infrastructure"]["dns"].get("mx_servers", []):
        edges.append({"from": target, "to": mx["host"], "type": "mail_server"})

    # Domain → Subdomains
    for sub in profile["infrastructure"]["subdomains"][:20]:  # cap at 20 for readability
        edges.append({"from": target, "to": sub["subdomain"], "type": "subdomain"})

    # Domain → GitHub members
    for member in profile["people"].get("github_members", [])[:15]:
        edges.append({"from": target, "to": member.get("login", "?"), "type": "employee_github"})

    # Domain → Email candidates
    for email in profile["people"].get("email_candidates", [])[:10]:
        edges.append({"from": target, "to": email, "type": "email"})

    # Email → Breaches
    for breach_r in profile["breach_exposure"].get("detail", []):
        email = breach_r.get("email", "")
        for breach in breach_r.get("breaches", []):
            bname = breach.get("name", "")
            if email and bname:
                edges.append({"from": email, "to": bname, "type": "breached_in"})

    return edges


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_json_report(profile: dict[str, Any], output_path: str) -> str:
    """Serialise the profile as pretty-printed JSON."""
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(profile, fh, indent=2, default=str)
    return output_path


def generate_text_report(profile: dict[str, Any], output_path: str) -> str:
    """Generate a human-readable plain-text report."""
    lines: list[str] = []

    def section(title: str):
        lines.append("")
        lines.append("=" * 70)
        lines.append(f"  {title}")
        lines.append("=" * 70)

    def sub(title: str):
        lines.append(f"\n  [{title}]")

    def kv(key: str, value: Any, indent: int = 4):
        prefix = " " * indent
        if isinstance(value, list):
            if not value:
                return
            lines.append(f"{prefix}{key}:")
            for item in value:
                lines.append(f"{prefix}  - {item}")
        else:
            if value:
                lines.append(f"{prefix}{key}: {value}")

    meta = profile["meta"]
    lines.append("╔══════════════════════════════════════════════════════════════════════╗")
    lines.append(f"║  OSINT RECONNAISSANCE REPORT                                        ║")
    lines.append(f"║  Target    : {meta['target']:<57}║")
    lines.append(f"║  Generated : {meta['generated_at']:<57}║")
    lines.append("╚══════════════════════════════════════════════════════════════════════╝")

    # Risk banner
    risk = profile["risk_assessment"].get("overall_risk", "UNKNOWN")
    risk_banner = {
        "CRITICAL": "!!! CRITICAL RISK !!!",
        "HIGH":     "*** HIGH RISK ***",
        "MEDIUM":   "--- MEDIUM RISK ---",
        "LOW":      "    LOW RISK    ",
        "UNKNOWN":  "    UNKNOWN     ",
    }
    lines.append(f"\n  OVERALL RISK: {risk_banner.get(risk, risk)}")
    counts = profile["risk_assessment"].get("counts", {})
    lines.append(f"  Findings: {counts.get('CRITICAL',0)} Critical  "
                 f"{counts.get('HIGH',0)} High  "
                 f"{counts.get('MEDIUM',0)} Medium  "
                 f"{counts.get('LOW',0)} Low  "
                 f"{counts.get('INFO',0)} Info")

    # Organisation
    section("ORGANISATION")
    org = profile["organisation"]
    kv("Domain",            org.get("domain"))
    kv("Registrar",         org.get("registrar"))
    kv("Registrant",        org.get("registrant_name"))
    kv("Organisation",      org.get("registrant_org"))
    kv("Contact Email",     org.get("registrant_email"))
    kv("Country",           org.get("registrant_country"))
    kv("Created",           org.get("created"))
    kv("Expires",           org.get("expires"))
    kv("Nameservers",       org.get("nameservers", []))
    kv("Hosting Hints",     org.get("hosting_hints", []))
    if org.get("github"):
        sub("GitHub Organisation")
        gh = org["github"]
        kv("Name",        gh.get("name"), 6)
        kv("Description", gh.get("description"), 6)
        kv("Location",    gh.get("location"), 6)
        kv("Public Repos",gh.get("public_repos"), 6)

    # Infrastructure
    section("INFRASTRUCTURE — DNS")
    dns = profile["infrastructure"]["dns"]
    records = dns.get("records", {})
    for rtype, values in records.items():
        kv(rtype, values)
    sub("Email Security")
    es = dns.get("email_security", {})
    kv("SPF",          es.get("spf"))
    kv("DMARC",        es.get("dmarc"))
    kv("DMARC Policy", es.get("dmarc_policy"))
    zt = dns.get("zone_transfer", {})
    if zt.get("success"):
        sub("⚠ ZONE TRANSFER SUCCEEDED")
        lines.append(f"    Nameserver: {zt.get('nameserver')}")
        lines.append(f"    Records leaked: {len(zt.get('records', []))}")

    sub("Subdomains Discovered")
    all_subs = profile["infrastructure"]["subdomains"]
    cert_only = profile["infrastructure"].get("cert_only_subdomains", [])
    if all_subs:
        for s in all_subs:
            ips = ", ".join(s.get("A", []))
            lines.append(f"    {s['subdomain']:<45} {ips}")
    if cert_only:
        lines.append(f"\n    Certificate-only subdomains ({len(cert_only)}):")
        for s in cert_only[:20]:
            lines.append(f"      {s}")

    # Services (Shodan)
    if profile["infrastructure"]["services"]:
        section("EXPOSED SERVICES (Shodan)")
        for svc in profile["infrastructure"]["services"]:
            if isinstance(svc, dict):
                lines.append(f"    IP: {svc.get('ip','?')}")
                kv("Ports",           svc.get("ports", []), 6)
                kv("OS",              svc.get("os"), 6)
                kv("Vulnerabilities", svc.get("vulnerabilities", []), 6)

    # People
    section("PEOPLE & EMPLOYEES")
    people = profile["people"]
    members = people.get("github_members", [])
    if members:
        sub("GitHub Members")
        for m in members[:20]:
            lines.append(f"    {m.get('login'):<30} {m.get('html_url','')}")

    emails = people.get("email_candidates", [])
    if emails:
        sub("Email Addresses")
        for e in emails:
            lines.append(f"    {e}")

    ld = people.get("linkedin_dorks", [])
    if ld:
        sub("LinkedIn Search Queries (paste into Google)")
        for d in ld:
            lines.append(f"    {d}")

    # Breach exposure
    section("BREACH EXPOSURE")
    bs = profile["breach_exposure"].get("summary", {})
    if bs:
        kv("Emails Checked",  bs.get("total_emails_checked"))
        kv("Breached",        bs.get("breached_count"))
        kv("Breach Rate",     f"{bs.get('breach_rate_pct', 0)}%")
        kv("Risk Level",      bs.get("risk_level"))
        kv("Unique Breaches", bs.get("unique_breaches", []))
        kv("Data Classes",    bs.get("all_data_classes", []))
        kv("Recommendation",  bs.get("recommendation"))
    else:
        lines.append("    No breach data collected (HIBP API key required)")

    # Historical
    section("HISTORICAL DATA (Wayback Machine)")
    snapshots = profile["historical"].get("wayback_snapshots", [])
    if snapshots:
        sub("Snapshots")
        for snap in snapshots[:10]:
            lines.append(f"    [{snap.get('timestamp','')}] HTTP {snap.get('statuscode','?')} — {snap.get('wayback_url','')}")
    archived = profile["historical"].get("archived_urls", [])
    if archived:
        sub(f"Archived URLs ({len(archived)} total, showing first 20)")
        for url in archived[:20]:
            lines.append(f"    {url}")

    # Risk findings
    section("RISK FINDINGS")
    for finding in profile["risk_assessment"].get("findings", []):
        sev = finding["severity"]
        cat = finding["category"]
        desc = finding["description"]
        lines.append(f"  [{sev:<8}] [{cat}] {desc}")

    # Dorks
    if profile["recon_dorks"]:
        section("SEARCH DORKS (Copy-paste to Google/Bing)")
        for category, dorks in profile["recon_dorks"].items():
            sub(category.replace("_", " ").title())
            for dork in dorks:
                lines.append(f"    {dork}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("  END OF REPORT — For authorized penetration testing use only.")
    lines.append("=" * 70)
    lines.append("")

    text = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return output_path


def generate_html_report(profile: dict[str, Any], output_path: str) -> str:
    """Generate a self-contained HTML report with styling and relationship table."""

    risk_colours = {
        "CRITICAL": "#d32f2f",
        "HIGH":     "#f57c00",
        "MEDIUM":   "#fbc02d",
        "LOW":      "#388e3c",
        "INFO":     "#0288d1",
        "UNKNOWN":  "#757575",
    }
    risk         = profile["risk_assessment"].get("overall_risk", "UNKNOWN")
    risk_colour  = risk_colours.get(risk, "#757575")
    meta         = profile["meta"]

    def esc(v: Any) -> str:
        return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def table_rows(items: list[dict], keys: list[str]) -> str:
        rows = []
        for item in items:
            cols = "".join(f"<td>{esc(item.get(k,''))}</td>" for k in keys)
            rows.append(f"<tr>{cols}</tr>")
        return "\n".join(rows)

    def findings_rows(findings: list[dict]) -> str:
        rows = []
        for f in findings:
            colour = risk_colours.get(f["severity"], "#757575")
            rows.append(
                f'<tr><td style="color:{colour};font-weight:bold">{esc(f["severity"])}</td>'
                f'<td>{esc(f["category"])}</td>'
                f'<td>{esc(f["description"])}</td></tr>'
            )
        return "\n".join(rows)

    def kv_rows(d: dict, keys: list[str]) -> str:
        rows = []
        for k in keys:
            v = d.get(k)
            if v is None:
                continue
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v) if v else ""
            rows.append(f'<tr><th>{esc(k.replace("_"," ").title())}</th><td>{esc(v)}</td></tr>')
        return "\n".join(rows)

    org = profile["organisation"]
    dns = profile["infrastructure"]["dns"]
    es  = dns.get("email_security", {})
    subs = profile["infrastructure"]["subdomains"]
    cert_only = profile["infrastructure"].get("cert_only_subdomains", [])
    members = profile["people"].get("github_members", [])
    emails  = profile["people"].get("email_candidates", [])
    breach_summary = profile["breach_exposure"].get("summary", {})
    findings = profile["risk_assessment"].get("findings", [])
    relationships = profile["relationships"]
    snapshots = profile["historical"].get("wayback_snapshots", [])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Report — {esc(meta['target'])}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #e0e0e0; margin: 0; padding: 0; }}
  .header {{ background: #16213e; padding: 30px 40px; border-bottom: 4px solid {risk_colour}; }}
  .header h1 {{ margin: 0; font-size: 1.8em; color: #fff; }}
  .header p {{ margin: 5px 0 0; color: #aaa; }}
  .risk-badge {{ display: inline-block; background: {risk_colour}; color: #fff;
                 padding: 4px 14px; border-radius: 4px; font-weight: bold; font-size: 1.1em; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 20px 40px; }}
  .section {{ background: #16213e; border-radius: 8px; margin: 20px 0; padding: 20px; }}
  .section h2 {{ margin: 0 0 15px; color: #4fc3f7; border-bottom: 1px solid #333; padding-bottom: 8px; }}
  .section h3 {{ color: #80cbc4; margin: 15px 0 8px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
  th {{ background: #0d1b2a; color: #aaa; text-align: left; padding: 8px 10px; width: 200px; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #1e2d3d; word-break: break-all; }}
  tr:hover td {{ background: #0d1b2a; }}
  .tag {{ display: inline-block; background: #263238; padding: 2px 8px; border-radius: 12px;
          font-size: 0.8em; margin: 2px; }}
  .warn {{ color: #ff7043; }}
  code {{ font-family: monospace; background: #0d1b2a; padding: 1px 4px; border-radius: 3px; }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  @media (max-width: 800px) {{ .grid2 {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="header">
  <h1>OSINT Reconnaissance Report</h1>
  <p>Target: <strong>{esc(meta['target'])}</strong> &nbsp;|&nbsp; Generated: {esc(meta['generated_at'])}</p>
  <p>Overall Risk: <span class="risk-badge">{esc(risk)}</span></p>
</div>
<div class="container">

<!-- Risk Findings -->
<div class="section">
  <h2>Risk Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>Description</th></tr></thead>
    <tbody>{findings_rows(findings) if findings else '<tr><td colspan="3">No findings collected</td></tr>'}</tbody>
  </table>
</div>

<div class="grid2">
<!-- Organisation -->
<div class="section">
  <h2>Organisation</h2>
  <table>
    {kv_rows(org, ['domain','registrar','registrant_name','registrant_org',
                   'registrant_email','registrant_country','created','expires'])}
  </table>
  {('<h3>Hosting Hints</h3>' + ''.join(f'<span class="tag">{esc(h)}</span>' for h in org.get('hosting_hints',[]))) if org.get('hosting_hints') else ''}
</div>

<!-- Email Security -->
<div class="section">
  <h2>Email Security</h2>
  <table>
    {kv_rows(es, ['spf','dmarc','dmarc_policy'])}
    {'<tr><td colspan="2" class="warn">⚠ No SPF record</td></tr>' if not es.get('spf') else ''}
    {'<tr><td colspan="2" class="warn">⚠ No DMARC record</td></tr>' if not es.get('dmarc') else ''}
  </table>
  <h3>MX Servers</h3>
  <table>
    <thead><tr><th>Priority</th><th>Host</th></tr></thead>
    <tbody>{''.join(f"<tr><td>{esc(m['priority'])}</td><td>{esc(m['host'])}</td></tr>" for m in dns.get('mx_servers',[]))}</tbody>
  </table>
</div>
</div>

<!-- DNS Records -->
<div class="section">
  <h2>DNS Records</h2>
  {''.join(f'<h3>{esc(rtype)}</h3><ul>{"".join(f"<li><code>{esc(v)}</code></li>" for v in vals)}</ul>'
           for rtype, vals in dns.get('records', {}).items())}
</div>

<!-- Subdomains -->
<div class="section">
  <h2>Subdomains ({len(subs) + len(cert_only)} total)</h2>
  <table>
    <thead><tr><th>Subdomain</th><th>A Records</th><th>CNAME</th><th>Source</th></tr></thead>
    <tbody>
    {''.join(f"<tr><td><code>{esc(s['subdomain'])}</code></td>"
              f"<td>{esc(', '.join(s.get('A',[])))}</td>"
              f"<td>{esc(', '.join(s.get('CNAME',[])))}</td>"
              f"<td>DNS Brute-force</td></tr>"
             for s in subs)}
    {''.join(f"<tr><td><code>{esc(s)}</code></td><td></td><td></td><td>Certificate Transparency</td></tr>"
             for s in cert_only[:50])}
    </tbody>
  </table>
</div>

<!-- People -->
<div class="section">
  <h2>People &amp; Employees</h2>
  {('<h3>GitHub Members (' + str(len(members)) + ')</h3><table><thead><tr><th>Username</th><th>Profile</th></tr></thead><tbody>' +
    ''.join(f'<tr><td>{esc(m.get("login",""))}</td><td><a href="{esc(m.get("html_url",""))}" style="color:#4fc3f7">{esc(m.get("html_url",""))}</a></td></tr>' for m in members[:30]) +
    '</tbody></table>') if members else ''}
  {('<h3>Email Addresses (' + str(len(emails)) + ')</h3><ul>' +
    ''.join(f'<li><code>{esc(e)}</code></li>' for e in emails) +
    '</ul>') if emails else ''}
</div>

<!-- Breach Exposure -->
<div class="section">
  <h2>Breach Exposure</h2>
  {('<table>' + kv_rows(breach_summary, ['total_emails_checked','breached_count','breach_rate_pct','risk_level','recommendation']) + '</table>' +
    '<h3>Data Classes Exposed</h3>' + ''.join(f'<span class="tag">{esc(c)}</span>' for c in breach_summary.get('all_data_classes', [])) +
    '<h3>Breaches</h3>' + ''.join(f'<span class="tag">{esc(b)}</span>' for b in breach_summary.get('unique_breaches', [])))
   if breach_summary else '<p>No breach data collected (HIBP API key required).</p>'}
</div>

<!-- Wayback Machine -->
<div class="section">
  <h2>Historical Data (Wayback Machine)</h2>
  {'<table><thead><tr><th>Timestamp</th><th>Status</th><th>URL</th></tr></thead><tbody>' +
   ''.join(f'<tr><td>{esc(s.get("timestamp",""))}</td><td>{esc(s.get("statuscode",""))}</td><td><a href="{esc(s.get("wayback_url",""))}" style="color:#4fc3f7">{esc(s.get("wayback_url",""))}</a></td></tr>' for s in snapshots[:15]) +
   '</tbody></table>' if snapshots else '<p>No snapshots collected.</p>'}
</div>

<!-- Relationships -->
<div class="section">
  <h2>Entity Relationships</h2>
  <table>
    <thead><tr><th>From</th><th>Relationship</th><th>To</th></tr></thead>
    <tbody>
    {''.join(f"<tr><td><code>{esc(r['from'])}</code></td><td>{esc(r['type'])}</td><td><code>{esc(r['to'])}</code></td></tr>" for r in relationships[:50])}
    </tbody>
  </table>
</div>

</div>
<footer style="text-align:center;padding:20px;color:#555;font-size:0.8em">
  OSINT Framework v1.0 &mdash; For authorized penetration testing and threat intelligence use only.
</footer>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return output_path


def generate_all_reports(profile: dict[str, Any], output_dir: str,
                          base_name: str | None = None) -> dict[str, str]:
    """Generate JSON, text, and HTML reports into *output_dir*."""
    os.makedirs(output_dir, exist_ok=True)
    ts   = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    base = base_name or profile["meta"]["target"].replace(".", "_")
    stem = f"{base}_{ts}"

    paths = {
        "json": generate_json_report(profile, os.path.join(output_dir, f"{stem}.json")),
        "text": generate_text_report(profile, os.path.join(output_dir, f"{stem}.txt")),
        "html": generate_html_report(profile, os.path.join(output_dir, f"{stem}.html")),
    }
    return paths
