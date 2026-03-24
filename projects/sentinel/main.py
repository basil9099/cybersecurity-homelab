#!/usr/bin/env python3
"""
SENTINEL — AI Attack Chain Correlator
======================================
Ingests outputs from SPECTRE, NIMBUS, OSINT, API Security Tester,
Anomaly Detector, and Network Baseline Monitor, then uses ML
(DBSCAN, TF-IDF, IsolationForest, NetworkX) to correlate findings
into attack campaigns, map them to MITRE ATT&CK kill chain phases,
score risk, detect attack paths, and produce a unified HTML/JSON report.

Usage:
    python main.py demo                              Self-contained demo
    python main.py correlate --inputs f1.json f2.json ...
    python main.py correlate --input-dir ./scan_results/
"""

from __future__ import annotations

import argparse
import glob
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Terminal colours (consistent with rest of homelab)
# ---------------------------------------------------------------------------
try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    _COLORS = True
except ImportError:
    _COLORS = False


def _c(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}" if _COLORS else text


def info(msg: str) -> None:
    print(_c(f"[*] {msg}", Fore.CYAN if _COLORS else ""))


def success(msg: str) -> None:
    print(_c(f"[+] {msg}", Fore.GREEN if _COLORS else ""))


def warn(msg: str) -> None:
    print(_c(f"[!] {msg}", Fore.YELLOW if _COLORS else ""))


def error(msg: str) -> None:
    print(_c(f"[-] {msg}", Fore.RED if _COLORS else ""), file=sys.stderr)


def header(msg: str) -> None:
    print(_c(f"\n{'='*60}\n  {msg}\n{'='*60}", Fore.BLUE if _COLORS else ""))


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------

def run_pipeline(
    input_files: list[str],
    output_dir: str,
    fmt: str,
    dbscan_eps: float,
    dbscan_min_samples: int,
    min_risk: float,
    use_isolation_forest: bool = True,
) -> int:
    """
    Full SENTINEL pipeline.  Returns exit code (0 = success).
    """
    # ── Imports (deferred so --help works without heavy deps) ──────────────
    from ingestion.registry import load_file, PARSER_REGISTRY
    from correlation.entity_extractor import EntityExtractor
    from correlation.graph_builder import CorrelationGraph
    from correlation.clusterer import CampaignClusterer
    from correlation.kill_chain_mapper import KillChainMapper
    from correlation.path_detector import PathDetector
    from scoring.risk_scorer import RiskScorer
    from reports.generator import generate_reports
    from core.models import Campaign, NormalizedFinding
    from core.constants import PHASE_MULTIPLIERS

    t0 = time.perf_counter()

    # ── 1. Ingestion ────────────────────────────────────────────────────────
    header("Phase 1: Ingestion")
    all_findings: list[NormalizedFinding] = []
    coverage: list[dict] = []
    tool_counts: dict[str, int] = {}
    all_warnings: list[str] = []

    for filepath in input_files:
        parser, findings, warnings = load_file(filepath)
        all_warnings.extend(warnings)
        tool = parser.SOURCE_TOOL if parser else "unknown"
        tool_counts[tool] = tool_counts.get(tool, 0) + len(findings)
        all_findings.extend(findings)

        if findings:
            success(f"{tool:20s}: {len(findings):3d} findings  ({os.path.basename(filepath)})")
        else:
            for w in warnings:
                warn(w)

    for tool_name in PARSER_REGISTRY:
        coverage.append({
            "tool": tool_name,
            "count": tool_counts.get(tool_name, 0),
            "warnings": [w for w in all_warnings if tool_name in w.lower()],
        })

    if not all_findings:
        error("No findings ingested. Provide valid tool output files.")
        return 1
    if len(all_findings) < 2:
        error("Too few findings to correlate (need ≥ 2). Provide at least 2 tool outputs.")
        return 1

    info(f"Total findings ingested: {len(all_findings)}")

    # ── 2. Entity extraction ────────────────────────────────────────────────
    header("Phase 2: Entity Extraction")
    extractor = EntityExtractor()
    for f in all_findings:
        extractor.extract(f)
    info(f"Entity extraction complete for {len(all_findings)} findings")

    # ── 3. Correlation graph ────────────────────────────────────────────────
    header("Phase 3: Building Correlation Graph")
    graph = CorrelationGraph()
    for f in all_findings:
        graph.add_finding(f)
    info(f"Graph: {len(graph.G.nodes)} nodes, {len(graph.G.edges)} edges")

    # ── 4. DBSCAN clustering ────────────────────────────────────────────────
    header("Phase 4: DBSCAN Campaign Clustering")
    clusterer = CampaignClusterer(eps=dbscan_eps, min_samples=dbscan_min_samples)
    cluster_map = clusterer.cluster(all_findings)
    info(f"Formed {len(cluster_map)} campaign cluster(s)")

    # ── 5. Kill chain mapping ───────────────────────────────────────────────
    header("Phase 5: MITRE ATT&CK Kill Chain Mapping")
    mapper = KillChainMapper()
    finding_phases: dict[str, tuple[str, float]] = {}
    id_to_finding = {f.finding_id: f for f in all_findings}

    for f in all_findings:
        phase, conf = mapper.map_finding(f)
        finding_phases[f.finding_id] = (phase, conf)

    # ── 6. Build Campaign objects ───────────────────────────────────────────
    header("Phase 6: Building Campaign Objects")
    campaigns: list[Campaign] = []

    for cluster_id, finding_ids in cluster_map.items():
        members = [id_to_finding[fid] for fid in finding_ids if fid in id_to_finding]
        if not members:
            continue

        # Campaign phase = majority vote among member finding phases
        phase_votes: dict[str, float] = {}
        for fid in finding_ids:
            ph, conf = finding_phases.get(fid, ("Reconnaissance", 0.0))
            phase_votes[ph] = phase_votes.get(ph, 0.0) + conf

        camp_phase = max(phase_votes, key=lambda p: phase_votes[p]) if phase_votes else "Reconnaissance"
        camp_conf = phase_votes.get(camp_phase, 0.0) / max(1, len(finding_ids))

        # Union entities
        union_entities: dict[str, list] = {k: [] for k in ("ips", "cves", "domains", "ports", "hostnames")}
        for f in members:
            for k in union_entities:
                union_entities[k] = list(set(union_entities[k]) | set(f.entities.get(k, [])))

        tools = list({f.source_tool for f in members})
        campaigns.append(Campaign(
            campaign_id=cluster_id,
            finding_ids=finding_ids,
            kill_chain_phase=camp_phase,
            kill_chain_score=camp_conf,
            risk_score=0.0,      # filled in by scorer
            entities=union_entities,
            tools_involved=tools,
        ))

    # ── 7. Risk scoring ─────────────────────────────────────────────────────
    header("Phase 7: Risk Scoring")
    scorer = RiskScorer(use_isolation_forest=use_isolation_forest)
    finding_scores, campaigns = scorer.score_all(all_findings, finding_phases, campaigns)

    # Filter by min_risk
    campaigns_out = [c for c in campaigns if c.risk_score >= min_risk]
    info(f"Campaigns above risk threshold {min_risk}: {len(campaigns_out)}/{len(campaigns)}")

    # ── 8. Attack path detection ────────────────────────────────────────────
    header("Phase 8: Attack Path Detection")
    finding_phase_str = {fid: ph for fid, (ph, _) in finding_phases.items()}
    path_detector = PathDetector(graph.G, finding_phase_str)
    attack_paths = path_detector.detect(max_paths=10)
    info(f"Detected {len(attack_paths)} attack path(s)")

    # ── 9. Report generation ────────────────────────────────────────────────
    header("Phase 9: Generating Reports")
    written = generate_reports(
        findings=all_findings,
        campaigns=campaigns_out,
        attack_paths=attack_paths,
        finding_phases=finding_phases,
        finding_scores=finding_scores,
        coverage=coverage,
        output_dir=output_dir,
        fmt=fmt,
    )

    elapsed = time.perf_counter() - t0

    # ── Summary ─────────────────────────────────────────────────────────────
    header("SENTINEL Complete")
    success(f"Findings ingested  : {len(all_findings)}")
    success(f"Campaigns detected : {len(campaigns_out)}")
    success(f"Attack paths found : {len(attack_paths)}")
    if campaigns_out:
        max_risk = max(c.risk_score for c in campaigns_out)
        success(f"Max risk score     : {max_risk:.1f}/10")
    for path in written:
        success(f"Report written     : {path}")
    info(f"Completed in {elapsed:.1f}s")

    return 0


# ---------------------------------------------------------------------------
# Demo command
# ---------------------------------------------------------------------------

def cmd_demo(args: argparse.Namespace) -> int:
    """Self-contained demo using synthetic tool outputs."""
    from demo.synthetic_data import write_demo_files
    import tempfile

    header("SENTINEL Demo Mode")
    info("Generating synthetic tool outputs (6 tools, overlapping entities)...")

    demo_data_dir = tempfile.mkdtemp(prefix="sentinel-demo-data-")
    file_map = write_demo_files(demo_data_dir)
    success(f"Synthetic files written to {demo_data_dir}")
    for tool, path in file_map.items():
        info(f"  {tool:20s}: {os.path.basename(path)}")

    output_dir = args.output or os.path.join(tempfile.gettempdir(), "sentinel-demo-reports")

    return run_pipeline(
        input_files=list(file_map.values()),
        output_dir=output_dir,
        fmt=args.format,
        dbscan_eps=0.4,
        dbscan_min_samples=2,
        min_risk=0.0,   # show all in demo
        use_isolation_forest=True,
    )


# ---------------------------------------------------------------------------
# Correlate command
# ---------------------------------------------------------------------------

def cmd_correlate(args: argparse.Namespace) -> int:
    """Correlate real tool output files."""
    input_files: list[str] = list(args.inputs or [])

    # Glob --input-dir
    if args.input_dir:
        for pattern in ("*.json", "*.csv"):
            input_files.extend(glob.glob(os.path.join(args.input_dir, pattern)))

    if not input_files:
        error("No input files specified. Use --inputs or --input-dir.")
        return 1

    info(f"Input files: {len(input_files)}")
    for f in input_files:
        info(f"  {f}")

    return run_pipeline(
        input_files=input_files,
        output_dir=args.output or "./sentinel_reports/",
        fmt=args.format,
        dbscan_eps=args.dbscan_eps,
        dbscan_min_samples=args.dbscan_min_samples,
        min_risk=args.min_risk,
        use_isolation_forest=not args.no_isolation_forest,
    )


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="SENTINEL — AI Attack Chain Correlator for the Cybersecurity Homelab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # demo
    p_demo = sub.add_parser("demo", help="Run self-contained demo with synthetic tool data")
    p_demo.add_argument("--output", "-o", metavar="DIR",
                        help="Output directory for reports (default: system temp dir)")
    p_demo.add_argument("--format", "-f", choices=["html", "json", "both"],
                        default="both", help="Report format (default: both)")

    # correlate
    p_cor = sub.add_parser("correlate", help="Correlate real tool output files")
    p_cor.add_argument("--inputs", nargs="+", metavar="FILE",
                       help="One or more tool output files (JSON or CSV)")
    p_cor.add_argument("--input-dir", metavar="DIR",
                       help="Directory to glob for *.json and *.csv files")
    p_cor.add_argument("--output", "-o", metavar="DIR", default="./sentinel_reports/",
                       help="Output directory for reports (default: ./sentinel_reports/)")
    p_cor.add_argument("--format", "-f", choices=["html", "json", "both"],
                       default="both", help="Report format (default: both)")
    p_cor.add_argument("--dbscan-eps", type=float, default=0.4, metavar="EPS",
                       help="DBSCAN neighbourhood radius in cosine space (default: 0.4)")
    p_cor.add_argument("--dbscan-min-samples", type=int, default=2, metavar="N",
                       help="DBSCAN minimum samples to form a cluster (default: 2)")
    p_cor.add_argument("--min-risk", type=float, default=0.0, metavar="SCORE",
                       help="Minimum campaign risk score to include in report (default: 0.0)")
    p_cor.add_argument("--no-isolation-forest", action="store_true",
                       help="Disable IsolationForest re-ranking step")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "demo":
        return cmd_demo(args)
    if args.command == "correlate":
        return cmd_correlate(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
