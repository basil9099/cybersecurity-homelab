#!/usr/bin/env python3
"""
NIMBUS — Cloud Security Scanner
================================
A multi-cloud CSPM tool that scans AWS, Azure, and GCP for security
misconfigurations, implements CIS benchmark compliance checking, and
generates executive dashboards.

Usage:
    python main.py --providers aws,azure,gcp [options]
    python main.py --providers all --demo          # Demo mode

WARNING: Only run against cloud accounts you own or have explicit permission to audit.
"""

import argparse
import datetime
import os
import random
import sys

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False

from scanner import AWSScanner, AzureScanner, GCPScanner
from scanner.base_scanner import Finding
from rules_engine import RuleLoader, Evaluator
from rules_engine.evaluator import ScanReport
from demo import generate_demo_findings
from reporter import ReportGenerator


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

VERSION = "1.0.0"

BANNER_ART = r"""
 _   _ ___ __  __ ____  _   _ ____
| \ | |_ _|  \/  | __ )| | | / ___|
|  \| || || |\/| |  _ \| | | \___ \
| |\  || || |  | | |_) | |_| |___) |
|_| \_|___|_|  |_|____/ \___/|____/
"""

TAGLINES = [
    "Your clouds, your responsibility.",
    "Misconfiguration is the new vulnerability.",
    "Trust but verify your cloud posture.",
    "CIS benchmarks don't check themselves.",
    "See through the cloud.",
    "Every bucket tells a story.",
]

PROVIDER_NAMES = {
    "aws": "Amazon Web Services",
    "azure": "Microsoft Azure",
    "gcp": "Google Cloud Platform",
}


def print_banner() -> None:
    print(c(BANNER_ART, Fore.CYAN if COLORS else ""))
    print(c(f"       v{VERSION} — Cloud Security Scanner (CSPM)", Style.BRIGHT if COLORS else ""))
    print()
    print(c(f'  "{random.choice(TAGLINES)}"', Fore.YELLOW if COLORS else ""))
    print()
    print(c("  [ CIS Benchmarks | Multi-Cloud | Executive Dashboards ]", Fore.CYAN if COLORS else ""))
    print(c("  For authorized security assessments only.", Style.DIM if COLORS else ""))
    print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def c(text: str, color: str) -> str:
    if not COLORS:
        return text
    return f"{color}{text}{Style.RESET_ALL}"


def info(msg: str) -> None:
    print(c("[*]", Fore.CYAN) + f" {msg}")


def success(msg: str) -> None:
    print(c("[+]", Fore.GREEN) + f" {msg}")


def warn(msg: str) -> None:
    print(c("[!]", Fore.YELLOW) + f" {msg}")


def error(msg: str) -> None:
    print(c("[-]", Fore.RED) + f" {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="nimbus",
        description="Cloud Security Scanner: scan AWS/Azure/GCP → CIS compliance → executive dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --providers all --demo
  python main.py --providers aws --aws-profile prod-account
  python main.py --providers aws,gcp --severity high --format html
  python main.py --providers azure --azure-subscription <sub-id>
        """,
    )

    # Provider selection
    parser.add_argument("--providers", required=True, metavar="LIST",
                        help="Comma-separated providers: aws, azure, gcp, or 'all'")
    parser.add_argument("--demo", action="store_true",
                        help="Run in demo/simulation mode (no cloud credentials needed)")

    # AWS options
    parser.add_argument("--aws-profile", default=None, metavar="NAME",
                        help="AWS CLI profile name (default: default)")
    parser.add_argument("--aws-regions", default="us-east-1", metavar="LIST",
                        help="Comma-separated AWS regions (default: us-east-1)")

    # Azure options
    parser.add_argument("--azure-subscription", default=None, metavar="ID",
                        help="Azure subscription ID")

    # GCP options
    parser.add_argument("--gcp-project", default=None, metavar="ID",
                        help="GCP project ID")

    # Filtering
    parser.add_argument("--severity", default=None, metavar="LEVEL",
                        choices=["critical", "high", "medium", "low", "info"],
                        help="Minimum severity level to report")

    # Output
    parser.add_argument("--output", default="cloud_security_report", metavar="BASENAME",
                        help="Output file base name (default: cloud_security_report)")
    parser.add_argument("--format", default="all", choices=["html", "json", "all"],
                        help="Report format (default: all)")

    # Advanced
    parser.add_argument("--rules-dir", default=None, metavar="DIR",
                        help="Custom rules directory (default: ./rules)")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable verbose output")

    return parser.parse_args()


def resolve_providers(provider_str: str) -> list[str]:
    """Parse the --providers argument into a list of provider names."""
    if provider_str.lower() == "all":
        return ["aws", "azure", "gcp"]
    providers = [p.strip().lower() for p in provider_str.split(",")]
    valid = {"aws", "azure", "gcp"}
    for p in providers:
        if p not in valid:
            error(f"Unknown provider: '{p}'. Valid options: aws, azure, gcp, all")
            sys.exit(1)
    return providers


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def filter_by_severity(findings: list[Finding], min_severity: str | None) -> list[Finding]:
    """Filter findings to only include those at or above the minimum severity."""
    if not min_severity:
        return findings
    threshold = SEVERITY_ORDER.get(min_severity, 4)
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 4) <= threshold]


# ---------------------------------------------------------------------------
# Scan Orchestration
# ---------------------------------------------------------------------------

def scan_provider_live(provider: str, args: argparse.Namespace) -> list[Finding]:
    """Run live scans against a cloud provider."""
    if provider == "aws":
        scanner = AWSScanner(
            regions=args.aws_regions.split(","),
            profile=args.aws_profile,
        )
    elif provider == "azure":
        if not args.azure_subscription:
            error("Azure subscription ID required (--azure-subscription)")
            return []
        scanner = AzureScanner(subscription_id=args.azure_subscription)
    elif provider == "gcp":
        scanner = GCPScanner(project_id=args.gcp_project)
    else:
        return []

    info(f"Authenticating with {PROVIDER_NAMES.get(provider, provider)}...")
    if not scanner.authenticate():
        error(f"Authentication failed for {provider.upper()}. Skipping.")
        warn("Check your credentials and permissions, or use --demo for simulation mode.")
        return []

    success(f"Authenticated with {provider.upper()}")
    info(f"Running {provider.upper()} security checks...")
    findings = scanner.run_all_checks()
    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    print_banner()

    providers = resolve_providers(args.providers)

    # Print scan configuration
    print(c(f"  Providers : {', '.join(p.upper() for p in providers)}", Fore.WHITE if COLORS else ""))
    print(c(f"  Mode      : {'DEMO (simulated)' if args.demo else 'LIVE'}", Fore.WHITE if COLORS else ""))
    if args.severity:
        print(c(f"  Severity  : {args.severity}+", Fore.WHITE if COLORS else ""))
    print(c(f"  Output    : {args.output}.{{html,json}}", Fore.WHITE if COLORS else ""))
    print()

    scan_start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    all_findings: list[Finding] = []

    # ------------------------------------------------------------------
    # Run scans
    # ------------------------------------------------------------------
    if args.demo:
        info("Running in DEMO mode — generating simulated findings...")
        all_findings = generate_demo_findings(providers)
        success(f"Generated {len(all_findings)} simulated findings across {len(providers)} provider(s)")
    else:
        for provider in providers:
            findings = scan_provider_live(provider, args)
            all_findings.extend(findings)
            if findings:
                pass_count = sum(1 for f in findings if f.status == "PASS")
                fail_count = sum(1 for f in findings if f.status == "FAIL")
                success(f"{provider.upper()}: {len(findings)} checks — {pass_count} passed, {fail_count} failed")
            print()

    if not all_findings:
        warn("No findings generated. Check provider configuration or use --demo.")
        return

    # ------------------------------------------------------------------
    # Filter by severity
    # ------------------------------------------------------------------
    all_findings = filter_by_severity(all_findings, args.severity)

    # ------------------------------------------------------------------
    # Compute compliance scores
    # ------------------------------------------------------------------
    evaluator = Evaluator()
    report = evaluator.compute_scores(all_findings)
    report.metadata = {
        "scan_time": scan_start,
        "providers": providers,
        "demo_mode": args.demo,
        "tool": "NIMBUS",
        "version": VERSION,
    }

    # ------------------------------------------------------------------
    # Print summary
    # ------------------------------------------------------------------
    print()
    info("Compliance Summary:")
    print()

    for provider, score in sorted(report.provider_scores.items()):
        pct = score.percentage
        if pct >= 90:
            color = Fore.GREEN if COLORS else ""
        elif pct >= 70:
            color = Fore.YELLOW if COLORS else ""
        else:
            color = Fore.RED if COLORS else ""

        print(f"  {c(provider.upper(), Style.BRIGHT if COLORS else '')}:  "
              f"{c(f'{pct:.0f}%', color)}  "
              f"({score.passed} passed, {score.failed} failed, {score.errors} errors)")

    overall_pct = report.overall_score.percentage
    if overall_pct >= 90:
        overall_color = Fore.GREEN if COLORS else ""
    elif overall_pct >= 70:
        overall_color = Fore.YELLOW if COLORS else ""
    else:
        overall_color = Fore.RED if COLORS else ""

    print()
    print(f"  {c('OVERALL', Style.BRIGHT if COLORS else '')}:  "
          f"{c(f'{overall_pct:.0f}%', overall_color)}  "
          f"({report.overall_score.passed} passed, {report.overall_score.failed} failed)")

    # Print severity breakdown
    sev_counts: dict[str, int] = {}
    for f in all_findings:
        if f.status == "FAIL":
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    if sev_counts:
        print()
        info("Failed Findings by Severity:")
        sev_colors = {
            "critical": Fore.RED if COLORS else "",
            "high": Fore.YELLOW if COLORS else "",
            "medium": Fore.CYAN if COLORS else "",
            "low": Fore.GREEN if COLORS else "",
            "info": Fore.WHITE if COLORS else "",
        }
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sev_counts.get(sev, 0)
            if count:
                print(f"     {c(sev.upper(), sev_colors.get(sev, ''))}: {count}")

    # ------------------------------------------------------------------
    # Generate reports
    # ------------------------------------------------------------------
    print()
    reporter = ReportGenerator(args.output)
    info("Generating reports...")

    if args.format in ("json", "all"):
        path = reporter.generate_json(report)
        success(f"JSON report saved → {path}")

    if args.format in ("html", "all"):
        path = reporter.generate_html(report)
        success(f"HTML report saved → {path}")

    print()
    print(c("Scan complete.", Fore.GREEN if COLORS else ""))
    print()


if __name__ == "__main__":
    main()
