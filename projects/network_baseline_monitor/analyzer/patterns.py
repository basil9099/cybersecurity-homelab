#!/usr/bin/env python3
"""
analyzer/patterns.py
=====================
Traffic pattern analysis for detecting specific attack types beyond
purely statistical deviations.

Detectors:
  - Port scanning:      One source hitting many destination ports rapidly.
  - Data exfiltration:  Abnormally large outbound bytes to external IPs.
  - C2 beaconing:       Highly periodic connections (low coefficient of variation).
  - Lateral movement:   East-west traffic to hosts not seen during baseline.

Each detector returns an AnomalyEvent or None (or list thereof).
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

from baseline.storage import BaselineRow, BaselineStorage
from collector.aggregator import TrafficWindow


# ── AnomalyEvent ─────────────────────────────────────────────────────────────

@dataclass
class AnomalyEvent:
    """A specific anomaly detected by a pattern rule."""
    anomaly_type: str                   # e.g. "port_scan", "exfiltration"
    severity: str                       # "low" | "medium" | "high"
    score: float                        # 1.0–10.0
    detail: dict[str, Any]             = field(default_factory=dict)
    timestamp: float                   = field(default_factory=time.time)

    @property
    def src_ip(self) -> str:
        return self.detail.get("src_ip", "")


# ── Thresholds ────────────────────────────────────────────────────────────────

PORT_SCAN_THRESHOLD   = 20    # Unique dst ports from one src in a single window
EXFIL_MULTIPLIER      = 5.0   # External_bytes_out / baseline_mean ratio to flag
BEACONING_CV_MAX      = 0.15  # Coefficient of variation below this = suspicious
BEACONING_MIN_WINDOWS = 5     # Need at least this many windows to detect beaconing
LATERAL_THRESHOLD     = 3     # New internal pairs (unseen in baseline) to trigger


# ── Port Scan Detection ───────────────────────────────────────────────────────

def detect_port_scan(window: TrafficWindow) -> list[AnomalyEvent]:
    """
    Flag sources contacting an unusually high number of distinct destination ports.

    Heuristic: if a single src_ip touched >PORT_SCAN_THRESHOLD unique dst_ports
    in the aggregation window, it's likely scanning.

    Returns:
        List of AnomalyEvent (one per flagged source IP).
    """
    events: list[AnomalyEvent] = []
    for src_ip, ports in window.src_port_spread.items():
        n_ports = len(ports)
        if n_ports >= PORT_SCAN_THRESHOLD:
            # Score scales: 20 ports → 5.0, 50+ ports → 10.0
            score = min(5.0 + (n_ports - PORT_SCAN_THRESHOLD) * 0.17, 10.0)
            severity = "high" if score >= 7 else "medium"
            events.append(AnomalyEvent(
                anomaly_type="port_scan",
                severity=severity,
                score=round(score, 1),
                detail={
                    "src_ip": src_ip,
                    "unique_ports_contacted": n_ports,
                    "ports_sample": sorted(ports)[:10],
                    "threshold": PORT_SCAN_THRESHOLD,
                },
                timestamp=window.timestamp,
            ))
    return events


# ── Data Exfiltration Detection ───────────────────────────────────────────────

def detect_exfiltration(
    window: TrafficWindow,
    baseline: dict[str, BaselineRow] | None,
) -> AnomalyEvent | None:
    """
    Flag abnormally high outbound traffic to external destinations.

    Compares window.external_bytes_out against baseline mean.
    If no baseline is available, falls back to an absolute threshold (10 MB/window).

    Returns:
        AnomalyEvent or None.
    """
    ext_bytes = window.external_bytes_out

    if baseline and "external_bytes_out" in baseline:
        bl = baseline["external_bytes_out"]
        if bl.mean < 1024:   # Baseline mean < 1 KB: use absolute floor
            bl_mean = max(bl.mean, 1024.0)
        else:
            bl_mean = bl.mean
        ratio = ext_bytes / bl_mean
        if ratio < EXFIL_MULTIPLIER:
            return None
        score = min(5.0 + (ratio - EXFIL_MULTIPLIER) * 0.5, 10.0)
    else:
        # No baseline: flag if > 10 MB in one window
        if ext_bytes < 10 * 1024 * 1024:
            return None
        ratio = ext_bytes / (10 * 1024 * 1024)
        score = min(4.0 + ratio, 10.0)
        bl_mean = 0.0

    severity = "high" if score >= 7 else "medium"
    top_dst = sorted(window.external_dst_bytes.items(), key=lambda x: x[1], reverse=True)[:5]
    return AnomalyEvent(
        anomaly_type="exfiltration",
        severity=severity,
        score=round(score, 1),
        detail={
            "src_ip": "multiple" if len(window.external_dst_bytes) > 1 else (
                list(window.external_dst_bytes.keys())[0] if window.external_dst_bytes else "unknown"
            ),
            "external_bytes_out": ext_bytes,
            "baseline_mean_bytes": round(bl_mean, 0),
            "ratio_vs_baseline": round(ratio, 2),
            "top_destinations": [{"ip": ip, "bytes": b} for ip, b in top_dst],
        },
        timestamp=window.timestamp,
    )


# ── C2 Beaconing Detection ────────────────────────────────────────────────────

def detect_beaconing(
    db: BaselineStorage,
    lookback: int = 30,
) -> list[AnomalyEvent]:
    """
    Detect C2 beaconing patterns by analysing the periodicity of connections
    from internal sources to external destinations over recent windows.

    Beaconing: a host repeatedly contacts the same external IP at regular
    intervals (low jitter → low coefficient of variation of inter-arrival times).

    Args:
        db:       BaselineStorage to query recent windows from.
        lookback: Number of recent windows to analyse.

    Returns:
        List of AnomalyEvent (one per (src_ip, dst_ip) beaconing pair).
    """
    recent = db.query_windows(limit=lookback)
    if len(recent) < BEACONING_MIN_WINDOWS:
        return []

    # Build timeline: dst_ip -> list of (timestamp, src_ip) for external dsts
    # We'll track per src_ip -> dst_ip -> [timestamps]
    contact_times: dict[str, dict[str, list[float]]] = {}

    for window in recent:
        for dst_ip, _bytes in window.external_dst_bytes.items():
            # Find which src_ip talked to this dst
            for src_ip in window.top_talkers:
                contact_times.setdefault(src_ip, {}).setdefault(dst_ip, []).append(window.timestamp)

    events: list[AnomalyEvent] = []
    for src_ip, dst_map in contact_times.items():
        for dst_ip, timestamps in dst_map.items():
            if len(timestamps) < BEACONING_MIN_WINDOWS:
                continue
            ts_sorted = sorted(timestamps)
            intervals = [ts_sorted[i+1] - ts_sorted[i] for i in range(len(ts_sorted)-1)]
            if len(intervals) < 2:
                continue
            mean_interval = sum(intervals) / len(intervals)
            if mean_interval < 1e-9:
                continue
            variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
            std_interval = math.sqrt(variance)
            cv = std_interval / mean_interval  # coefficient of variation

            if cv <= BEACONING_CV_MAX:
                # Very regular → suspicious
                score = min(5.0 + (BEACONING_CV_MAX - cv) / BEACONING_CV_MAX * 5.0, 10.0)
                events.append(AnomalyEvent(
                    anomaly_type="c2_beaconing",
                    severity="high" if score >= 7 else "medium",
                    score=round(score, 1),
                    detail={
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "contact_count": len(timestamps),
                        "mean_interval_s": round(mean_interval, 1),
                        "interval_cv": round(cv, 4),
                        "cv_threshold": BEACONING_CV_MAX,
                    },
                    timestamp=recent[-1].timestamp,
                ))

    return events


# ── Lateral Movement Detection ────────────────────────────────────────────────

def detect_lateral_movement(
    window: TrafficWindow,
    known_pairs: set[str],
) -> list[AnomalyEvent]:
    """
    Flag new internal east-west communication pairs not seen during baseline.

    Args:
        window:      Current traffic window.
        known_pairs: Set of "src_ip:dst_ip" strings observed during baseline.

    Returns:
        List of AnomalyEvent for each new pair (up to 5 per window).
    """
    events: list[AnomalyEvent] = []
    new_pairs: list[str] = []

    for pair, count in window.internal_pairs.items():
        if pair not in known_pairs:
            new_pairs.append(pair)

    if len(new_pairs) < LATERAL_THRESHOLD:
        return []

    score = min(4.0 + len(new_pairs) * 0.5, 10.0)
    severity = "high" if score >= 7 else "medium"

    events.append(AnomalyEvent(
        anomaly_type="lateral_movement",
        severity=severity,
        score=round(score, 1),
        detail={
            "src_ip": "multiple",
            "new_internal_pairs": new_pairs[:10],
            "new_pair_count": len(new_pairs),
            "threshold": LATERAL_THRESHOLD,
        },
        timestamp=window.timestamp,
    ))
    return events


def build_known_pairs(db: BaselineStorage) -> set[str]:
    """
    Build a set of all internal communication pairs seen during the baseline period.

    Loads all stored windows and collects all internal_pairs keys.
    """
    known: set[str] = set()
    for window in db.query_windows():
        known.update(window.internal_pairs.keys())
    return known
