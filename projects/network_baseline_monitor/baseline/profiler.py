#!/usr/bin/env python3
"""
baseline/profiler.py
====================
Computes statistical baseline profiles from stored traffic windows.

Groups windows by (hour_of_day, day_of_week) and computes mean, standard
deviation, and percentiles (P25, P75) for each scalar metric.

A minimum sample count per slot is required before that slot is considered
"ready" — this prevents misleadingly narrow baselines from sparse data.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from baseline.storage import BaselineRow, BaselineStorage
from collector.aggregator import TrafficWindow


# Scalar metrics extracted from each TrafficWindow for baseline computation.
# Dict-type fields (bytes_per_protocol, top_talkers, etc.) are flattened
# into scalar metrics with the pattern "field_key" where needed.
_SCALAR_METRICS = [
    "total_bytes",
    "total_packets",
    "unique_src_ips",
    "unique_dst_ips",
    "external_bytes_out",
    # Per-protocol bytes (always include main protocols)
    "proto_TCP_bytes",
    "proto_UDP_bytes",
    "proto_ICMP_bytes",
    # Port diversity: number of distinct dst ports seen
    "distinct_dst_ports",
    # Internal pair count
    "internal_pair_count",
]


def _extract_scalars(window: TrafficWindow) -> dict[str, float]:
    """Extract scalar metric values from a TrafficWindow."""
    bpp = window.bytes_per_protocol
    return {
        "total_bytes": float(window.total_bytes),
        "total_packets": float(window.total_packets),
        "unique_src_ips": float(window.unique_src_ips),
        "unique_dst_ips": float(window.unique_dst_ips),
        "external_bytes_out": float(window.external_bytes_out),
        "proto_TCP_bytes": float(bpp.get("TCP", 0)),
        "proto_UDP_bytes": float(bpp.get("UDP", 0)),
        "proto_ICMP_bytes": float(bpp.get("ICMP", 0)),
        "distinct_dst_ports": float(len(window.port_counts)),
        "internal_pair_count": float(len(window.internal_pairs)),
    }


@dataclass
class BaselineSummary:
    """Result of a baseline computation run."""
    slots_computed: int          # Number of (hour, day) slots with sufficient data
    slots_insufficient: int      # Slots with too few samples
    total_windows: int           # Windows used for computation
    metrics_per_slot: list[str]  # Metric names stored
    min_samples_required: int


def compute_baselines(
    db: BaselineStorage,
    min_samples: int = 30,
) -> BaselineSummary:
    """
    Compute and store baseline profiles from all traffic windows in the DB.

    For each (hour_of_day, day_of_week) slot that has at least `min_samples`
    windows, computes mean, std, P25, P75 for every scalar metric and persists
    the results via db.upsert_baseline().

    Args:
        db:          Open BaselineStorage instance.
        min_samples: Minimum number of windows required per time slot.

    Returns:
        BaselineSummary describing coverage.
    """
    try:
        import numpy as np
    except ImportError:
        np = None  # type: ignore

    windows = db.query_windows()
    if not windows:
        return BaselineSummary(0, 0, 0, [], min_samples)

    # Group windows by (hour_of_day, day_of_week)
    slot_data: dict[tuple[int, int], list[dict[str, float]]] = {}
    for w in windows:
        dt = datetime.fromtimestamp(w.timestamp)
        slot = (dt.hour, dt.weekday())
        scalars = _extract_scalars(w)
        slot_data.setdefault(slot, []).append(scalars)

    slots_ok = 0
    slots_bad = 0
    metric_names = list(_extract_scalars(windows[0]).keys())

    for (hour, dow), samples in slot_data.items():
        if len(samples) < min_samples:
            slots_bad += 1
            continue

        for metric in metric_names:
            values = [s[metric] for s in samples]
            if np is not None:
                arr = np.array(values, dtype=float)
                mean = float(np.mean(arr))
                std = float(np.std(arr))
                p25 = float(np.percentile(arr, 25))
                p75 = float(np.percentile(arr, 75))
            else:
                mean, std, p25, p75 = _stats_pure(values)

            db.upsert_baseline(BaselineRow(
                hour_of_day=hour,
                day_of_week=dow,
                metric_name=metric,
                mean=mean,
                std=std,
                p25=p25,
                p75=p75,
                sample_count=len(samples),
            ))

        slots_ok += 1

    return BaselineSummary(
        slots_computed=slots_ok,
        slots_insufficient=slots_bad,
        total_windows=len(windows),
        metrics_per_slot=metric_names,
        min_samples_required=min_samples,
    )


def _stats_pure(values: list[float]) -> tuple[float, float, float, float]:
    """Fallback statistics without numpy/scipy."""
    n = len(values)
    if n == 0:
        return 0.0, 0.0, 0.0, 0.0
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    std = variance ** 0.5
    sorted_vals = sorted(values)
    p25 = _percentile(sorted_vals, 25)
    p75 = _percentile(sorted_vals, 75)
    return mean, std, p25, p75


def _percentile(sorted_vals: list[float], pct: float) -> float:
    """Linear interpolation percentile on a pre-sorted list."""
    n = len(sorted_vals)
    if n == 0:
        return 0.0
    idx = (pct / 100) * (n - 1)
    lo = int(idx)
    hi = min(lo + 1, n - 1)
    frac = idx - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def extract_scalars(window: TrafficWindow) -> dict[str, float]:
    """Public alias used by detector and analyzer modules."""
    return _extract_scalars(window)
