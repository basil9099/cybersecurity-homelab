#!/usr/bin/env python3
"""
Network Baseline Monitor
========================
Establish normal traffic baselines, detect deviations, and generate reports.

Usage:
    python main.py demo                         Run self-contained demo (no root needed)
    python main.py collect -i eth0 --db net.db  Live capture for one window
    python main.py collect --pcap file.pcap     Offline PCAP analysis
    python main.py baseline --db net.db         Compute baseline profiles
    python main.py monitor -i eth0 --db net.db  Continuous monitoring
    python main.py report --db net.db -o out/   Generate HTML + JSON reports
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# ── Colorama setup ────────────────────────────────────────────────────────────
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


# ── Subcommand handlers ───────────────────────────────────────────────────────

def cmd_collect(args: argparse.Namespace) -> int:
    """Capture one or more traffic windows and store them in the database."""
    from baseline.storage import BaselineStorage
    from collector.aggregator import aggregate
    from collector.sniffer import capture_live, capture_pcap

    db = BaselineStorage(args.db)

    if args.pcap:
        info(f"Reading PCAP: {args.pcap}")
        packets = capture_pcap(args.pcap)
        info(f"Loaded {len(packets)} packets from PCAP")
        window = aggregate(packets, window_seconds=args.window)
        wid = db.insert_window(window)
        success(f"Stored window #{wid}: {window.total_packets} pkts, {window.total_bytes} bytes")
        return 0

    # Live capture
    if os.geteuid() != 0:
        error("Live capture requires root privileges. Use --pcap for offline analysis or run with sudo.")
        return 1

    iface = args.interface or _default_interface()
    info(f"Capturing on {iface} for {args.window}s windows  (Ctrl+C to stop)")

    count = 0
    try:
        while args.count == 0 or count < args.count:
            info(f"Window {count + 1}: capturing for {args.window}s …")
            packets = capture_live(iface, duration=args.window)
            window = aggregate(packets, window_seconds=args.window)
            wid = db.insert_window(window)
            success(
                f"  Window #{wid}: {window.total_packets} pkts | "
                f"{window.total_bytes} bytes | {window.external_bytes_out} ext bytes"
            )
            count += 1
    except KeyboardInterrupt:
        info("Capture stopped.")

    success(f"Collected {count} window(s) into {args.db}")
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    """Compute statistical baselines from stored traffic windows."""
    from baseline.storage import BaselineStorage
    from baseline.profiler import compute_baselines

    db = BaselineStorage(args.db)
    n_windows = db.count_windows()
    if n_windows == 0:
        error(f"No traffic windows found in {args.db}. Run 'collect' first.")
        return 1

    info(f"Computing baselines from {n_windows} windows (min_samples={args.min_samples}) …")
    summary = compute_baselines(db, min_samples=args.min_samples)

    success(f"Baseline complete:")
    info(f"  Slots with sufficient data:   {summary.slots_computed}")
    info(f"  Slots with insufficient data: {summary.slots_insufficient}")
    info(f"  Total windows used:           {summary.total_windows}")
    info(f"  Metrics stored:               {len(summary.metrics_per_slot)}")

    if summary.slots_computed == 0:
        warn(
            f"No baseline slots met the minimum sample threshold ({args.min_samples}). "
            "Collect more data or lower --min-samples."
        )
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    """Continuous monitoring: capture → detect → alert in a loop."""
    from alerts.engine import AlertConfig, AlertEngine
    from analyzer.patterns import (
        build_known_pairs,
        detect_beaconing,
        detect_exfiltration,
        detect_lateral_movement,
        detect_port_scan,
    )
    from baseline.storage import BaselineStorage
    from collector.aggregator import aggregate
    from collector.sniffer import capture_live
    from detector.statistical import score_window

    if os.geteuid() != 0:
        error("Live monitoring requires root privileges. Run with sudo.")
        return 1

    db = BaselineStorage(args.db)
    if not db.has_baseline():
        warn("No baseline found. Running in detection-only mode (statistical scoring disabled).")

    iface = args.interface or _default_interface()
    cfg = AlertConfig(
        suppress_window_seconds=args.suppress_window * 60,
        score_medium=args.threshold_medium,
        score_high=args.threshold_high,
    )
    engine = AlertEngine(db, cfg)
    known_pairs = build_known_pairs(db)

    info(f"Monitoring {iface} (window={args.window}s) — Ctrl+C to stop")
    window_count = 0

    try:
        while True:
            packets = capture_live(iface, duration=args.window)
            window = aggregate(packets, window_seconds=args.window)
            wid = db.insert_window(window)
            window_count += 1

            dt = datetime.fromtimestamp(window.timestamp)
            baseline = db.get_baseline(dt.hour, dt.weekday())
            recent = db.query_windows(limit=15)

            scores = score_window(window, baseline, recent)
            pattern_events = (
                detect_port_scan(window)
                + ([detect_exfiltration(window, baseline)] if detect_exfiltration(window, baseline) else [])
                + detect_beaconing(db, lookback=30)
                + detect_lateral_movement(window, known_pairs)
            )
            pattern_events = [e for e in pattern_events if e is not None]

            engine.process(scores, pattern_events, window.timestamp)

            info(
                f"[W#{window_count}] {dt.strftime('%H:%M:%S')} "
                f"{window.total_packets} pkts | score={scores.composite:.1f}"
            )
    except KeyboardInterrupt:
        info("Monitoring stopped.")

    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Generate anomaly reports from stored data."""
    from baseline.storage import BaselineStorage
    from reports.generator import ascii_dashboard, html_report, json_report

    db = BaselineStorage(args.db)
    windows = db.query_windows()
    alerts = db.query_alerts()

    if not windows:
        warn("No traffic windows found. Nothing to report.")
        return 0

    # Baseline means for comparison
    baseline_means: dict[str, float] = {}
    coverage = db.baseline_coverage()
    if coverage:
        # Try to get a representative baseline (noon on Monday)
        sample_bl = db.get_baseline(12, 0)
        if sample_bl:
            baseline_means = {k: v.mean for k, v in sample_bl.items()}

    ascii_dashboard(windows, alerts, baseline_means)

    output_dir = Path(args.output)
    fmt = args.format.lower()

    if fmt in ("html", "both"):
        path = html_report(windows, alerts, output_dir / "network_baseline_report.html", baseline_means)
        success(f"HTML report: {path}")

    if fmt in ("json", "both"):
        path = json_report(windows, alerts, output_dir / "network_baseline_report.json")
        success(f"JSON report: {path}")

    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """
    Run a self-contained demo: generate synthetic baseline data, inject
    known anomalies, run the full detection pipeline, and produce a report.
    No root privileges or live network required.
    """
    import random
    import tempfile
    from alerts.engine import AlertConfig, AlertEngine
    from analyzer.patterns import (
        build_known_pairs,
        detect_beaconing,
        detect_exfiltration,
        detect_lateral_movement,
        detect_port_scan,
    )
    from baseline.profiler import compute_baselines
    from baseline.storage import BaselineStorage
    from collector.aggregator import TrafficWindow, aggregate
    from collector.sniffer import synthetic_packets
    from detector.statistical import score_window
    from reports.generator import ascii_dashboard, html_report, json_report

    db_path = args.db or os.path.join(tempfile.gettempdir(), "nbm_demo.db")
    if Path(db_path).exists():
        Path(db_path).unlink()

    info("Network Baseline Monitor — Demo Mode")
    info("=" * 50)
    info("Step 1: Generating 14 days of synthetic normal traffic …")

    db = BaselineStorage(db_path)
    rng = random.Random(42)
    base_time = time.time() - 14 * 86400  # 2 weeks ago

    windows_per_day = 24 * 4  # one window per 15 minutes = 96/day
    window_secs = 900         # 15-minute windows for demo (faster)
    total_windows = windows_per_day * 14

    for i in range(total_windows):
        ts = base_time + i * window_secs
        dt = datetime.fromtimestamp(ts)
        # Traffic varies by hour: higher during business hours
        hour_factor = 1.0 + 1.5 * max(0, 1 - abs(dt.hour - 12) / 6)
        n_pkts = int(rng.gauss(200 * hour_factor, 30))
        pkts = synthetic_packets(
            n=max(n_pkts, 10),
            base_time=ts,
            duration=float(window_secs),
            seed=i,
        )
        window = aggregate(pkts, window_seconds=window_secs, timestamp=ts)
        db.insert_window(window)

    n = db.count_windows()
    success(f"  Stored {n} normal traffic windows spanning 14 days.")

    info("Step 2: Computing baseline profiles …")
    # 14 days × 15-min windows gives ~8 samples per (hour, dow) slot; use 5 as threshold
    summary = compute_baselines(db, min_samples=5)
    success(f"  Baseline ready: {summary.slots_computed} time slots, {len(summary.metrics_per_slot)} metrics each.")

    info("Step 3: Injecting 5 anomaly scenarios …")
    anomaly_ts_base = time.time() - 3600  # 1 hour ago

    injected_windows: list[TrafficWindow] = []

    # Anomaly 1: Port scan burst from 10.0.0.55
    ts1 = anomaly_ts_base
    pkts1 = synthetic_packets(n=300, base_time=ts1, duration=900.0, seed=100)
    w1 = aggregate(pkts1, window_seconds=window_secs, timestamp=ts1)
    # Inject port scan: add 40 unique ports from one source
    w1.src_port_spread["10.0.0.55"] = list(range(1, 41))
    wid1 = db.insert_window(w1)
    injected_windows.append(w1)
    info(f"  [1] Port scan burst injected (window #{wid1}, src=10.0.0.55, 40 ports)")

    # Anomaly 2: Data exfiltration spike
    ts2 = anomaly_ts_base + 900
    pkts2 = synthetic_packets(n=200, base_time=ts2, duration=900.0, seed=101)
    w2 = aggregate(pkts2, window_seconds=window_secs, timestamp=ts2)
    w2.external_bytes_out = 50 * 1024 * 1024   # 50 MB outbound
    w2.external_dst_bytes = {"203.0.113.5": 50 * 1024 * 1024}
    w2.total_bytes += w2.external_bytes_out
    wid2 = db.insert_window(w2)
    injected_windows.append(w2)
    info(f"  [2] Exfiltration spike injected (window #{wid2}, 50 MB to 203.0.113.5)")

    # Anomaly 3: Traffic volume surge (DDoS / scanning)
    ts3 = anomaly_ts_base + 1800
    pkts3 = synthetic_packets(n=2000, base_time=ts3, duration=900.0, seed=102)
    w3 = aggregate(pkts3, window_seconds=window_secs, timestamp=ts3)
    wid3 = db.insert_window(w3)
    injected_windows.append(w3)
    info(f"  [3] Volume surge injected (window #{wid3}, {w3.total_packets} packets)")

    # Anomaly 4: Lateral movement (new internal pairs)
    ts4 = anomaly_ts_base + 2700
    pkts4 = synthetic_packets(n=150, base_time=ts4, duration=900.0, seed=103)
    w4 = aggregate(pkts4, window_seconds=window_secs, timestamp=ts4)
    w4.internal_pairs.update({
        "10.0.0.10:10.0.0.15": 45,
        "10.0.0.10:10.0.0.16": 38,
        "10.0.0.10:10.0.0.17": 27,
        "10.0.0.10:10.0.0.18": 19,
    })
    wid4 = db.insert_window(w4)
    injected_windows.append(w4)
    info(f"  [4] Lateral movement injected (window #{wid4}, 4 new internal pairs)")

    # Anomaly 5: ICMP flood
    ts5 = anomaly_ts_base + 3600
    pkts5 = synthetic_packets(n=100, base_time=ts5, duration=900.0, seed=104)
    w5 = aggregate(pkts5, window_seconds=window_secs, timestamp=ts5)
    w5.bytes_per_protocol["ICMP"] = 8 * 1024 * 1024   # 8 MB of ICMP
    w5.pkts_per_protocol["ICMP"] = 5000
    w5.total_packets += 5000
    wid5 = db.insert_window(w5)
    injected_windows.append(w5)
    info(f"  [5] ICMP flood injected (window #{wid5}, 8 MB ICMP)")

    info("Step 4: Running detection pipeline on anomalous windows …")
    cfg = AlertConfig(suppress_window_seconds=0, quiet=True)  # quiet=True: no console spam
    engine = AlertEngine(db, cfg)
    known_pairs = build_known_pairs(db)
    # Remove injected pairs from known so lateral movement fires
    injected_lateral = {"10.0.0.10:10.0.0.15", "10.0.0.10:10.0.0.16", "10.0.0.10:10.0.0.17", "10.0.0.10:10.0.0.18"}
    known_pairs -= injected_lateral

    all_alerts = []
    for i, window in enumerate(injected_windows):
        dt = datetime.fromtimestamp(window.timestamp)
        baseline = db.get_baseline(dt.hour, dt.weekday())
        recent = db.query_windows(limit=15)

        scores = score_window(window, baseline, recent)
        exfil_event = detect_exfiltration(window, baseline)
        pattern_events = (
            detect_port_scan(window)
            + ([exfil_event] if exfil_event else [])
            + detect_lateral_movement(window, known_pairs)
        )

        fired = engine.process(scores, pattern_events, window.timestamp)
        all_alerts.extend(fired)
        info(f"  Window {i+1}: composite_score={scores.composite:.2f}, alerts_fired={len(fired)}")

    # Also run beaconing detection
    beaconing_events = detect_beaconing(db, lookback=50)
    info(f"  Beaconing check: {len(beaconing_events)} potential C2 patterns detected")

    success(f"Detection complete. Total alerts logged: {len(all_alerts)}")

    info("Step 5: Generating reports …")
    all_windows = db.query_windows()
    logged_alerts = db.query_alerts()
    bl_sample = db.get_baseline(12, 0)
    baseline_means = {k: v.mean for k, v in bl_sample.items()} if bl_sample else {}

    # ASCII dashboard
    info("\nASCII Dashboard (last 10 windows):")
    ascii_dashboard(all_windows[-10:] + injected_windows, logged_alerts[:5], baseline_means, max_rows=15)

    # HTML report
    out_dir = Path(args.output) if args.output else Path(tempfile.gettempdir())
    html_path = html_report(
        all_windows[-50:] + injected_windows,
        logged_alerts,
        out_dir / "network_baseline_report.html",
        baseline_means,
    )
    success(f"HTML report written: {html_path}")

    if args.format in ("json", "both"):
        json_path = json_report(
            all_windows[-50:] + injected_windows,
            logged_alerts,
            out_dir / "network_baseline_report.json",
        )
        success(f"JSON report written: {json_path}")

    success("Demo complete! Review the HTML report to explore detected anomalies.")
    return 0


# ── Helpers ───────────────────────────────────────────────────────────────────

def _default_interface() -> str:
    """Return the first non-loopback interface name."""
    try:
        import socket
        import subprocess
        result = subprocess.run(
            ["ip", "-o", "link", "show", "up"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                name = parts[1].rstrip(":")
                if name != "lo":
                    return name
    except Exception:
        pass
    return "eth0"


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="network_baseline_monitor",
        description="Network Baseline Monitor — Establish traffic baselines and detect anomalies.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Self-contained demo (no root required):
  python main.py demo

  # Collect 1 hour of traffic (requires root):
  sudo python main.py collect -i eth0 --db net.db --count 60 --window 60

  # Analyse an existing PCAP file:
  python main.py collect --pcap capture.pcap --db net.db

  # Compute baseline profiles:
  python main.py baseline --db net.db --min-samples 20

  # Start real-time monitoring:
  sudo python main.py monitor -i eth0 --db net.db

  # Generate HTML report:
  python main.py report --db net.db --format html -o ./reports/
        """,
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # ── demo ──────────────────────────────────────────────────────────────────
    p_demo = sub.add_parser("demo", help="Run self-contained demo with synthetic data")
    p_demo.add_argument("--db", default=None, help="SQLite DB path (default: temp file)")
    p_demo.add_argument("--output", "-o", default=None, help="Report output directory (default: /tmp)")
    p_demo.add_argument("--format", default="html", choices=["html", "json", "both"], help="Report format")

    # ── collect ───────────────────────────────────────────────────────────────
    p_col = sub.add_parser("collect", help="Capture traffic and store windows")
    p_col.add_argument("--interface", "-i", default=None, help="Network interface (live capture)")
    p_col.add_argument("--pcap", default=None, help="Read from PCAP file instead of live capture")
    p_col.add_argument("--db", default="network_baseline.db", help="SQLite database path")
    p_col.add_argument("--window", type=int, default=60, help="Window duration in seconds (default: 60)")
    p_col.add_argument("--count", type=int, default=0, help="Number of windows to collect (0=infinite)")

    # ── baseline ──────────────────────────────────────────────────────────────
    p_bl = sub.add_parser("baseline", help="Compute baseline profiles from stored windows")
    p_bl.add_argument("--db", default="network_baseline.db", help="SQLite database path")
    p_bl.add_argument("--min-samples", type=int, default=30,
                      help="Min windows per time slot to compute baseline (default: 30)")

    # ── monitor ───────────────────────────────────────────────────────────────
    p_mon = sub.add_parser("monitor", help="Continuous live monitoring")
    p_mon.add_argument("--interface", "-i", default=None, help="Network interface")
    p_mon.add_argument("--db", default="network_baseline.db", help="SQLite database path")
    p_mon.add_argument("--window", type=int, default=60, help="Window duration in seconds (default: 60)")
    p_mon.add_argument("--threshold-medium", type=float, default=4.0, help="Score for medium alert (default: 4.0)")
    p_mon.add_argument("--threshold-high", type=float, default=7.0, help="Score for high alert (default: 7.0)")
    p_mon.add_argument("--suppress-window", type=int, default=15,
                       help="Alert suppression window in minutes (default: 15)")

    # ── report ────────────────────────────────────────────────────────────────
    p_rep = sub.add_parser("report", help="Generate anomaly reports")
    p_rep.add_argument("--db", default="network_baseline.db", help="SQLite database path")
    p_rep.add_argument("--output", "-o", default=".", help="Output directory (default: current dir)")
    p_rep.add_argument("--format", default="html", choices=["html", "json", "both"], help="Report format")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "demo":     cmd_demo,
        "collect":  cmd_collect,
        "baseline": cmd_baseline,
        "monitor":  cmd_monitor,
        "report":   cmd_report,
    }
    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
