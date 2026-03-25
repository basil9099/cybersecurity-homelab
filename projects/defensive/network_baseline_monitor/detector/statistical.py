#!/usr/bin/env python3
"""
detector/statistical.py
========================
Statistical anomaly detection methods.

Three complementary techniques are applied to each scalar metric:
  1. Z-score:         How many standard deviations from the baseline mean.
  2. IQR method:      Is the value outside the Q1–Q3 interquartile fence?
  3. Moving average:  Is the current value far from a rolling recent average?

Each method returns a raw signal (0.0–10.0).  score_window() combines them
into per-metric anomaly scores and a composite score for the whole window.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from baseline.storage import BaselineRow
from baseline.profiler import extract_scalars
from collector.aggregator import TrafficWindow


# ── Threshold constants ───────────────────────────────────────────────────────

ZSCORE_THRESHOLD = 3.0          # Flag if z-score exceeds this
IQR_MULTIPLIER = 1.5            # Standard Tukey fence multiplier
MA_DEVIATION_THRESHOLD = 2.0    # Flag if value deviates >2x from moving avg

# Weights for composite score (must sum to 1.0)
_METRIC_WEIGHTS: dict[str, float] = {
    "total_bytes":          0.20,
    "total_packets":        0.15,
    "external_bytes_out":   0.25,
    "unique_src_ips":       0.10,
    "unique_dst_ips":       0.10,
    "proto_TCP_bytes":      0.05,
    "proto_UDP_bytes":      0.05,
    "proto_ICMP_bytes":     0.03,
    "distinct_dst_ports":   0.04,
    "internal_pair_count":  0.03,
}


# ── Core functions ────────────────────────────────────────────────────────────

def zscore_check(value: float, mean: float, std: float) -> float:
    """
    Compute the absolute z-score for a value given baseline statistics.

    Returns 0.0 if std is zero or too small (avoids division by zero).

    >>> round(zscore_check(100, 50, 10), 1)
    5.0
    >>> zscore_check(50, 50, 10)
    0.0
    """
    if std < 1e-9:
        # No variance in baseline: flag only significant absolute deviation
        if mean > 1e-9 and abs(value - mean) / mean > 0.5:
            return 3.0
        return 0.0
    return abs((value - mean) / std)


def iqr_check(value: float, p25: float, p75: float, multiplier: float = IQR_MULTIPLIER) -> bool:
    """
    Return True if value falls outside the Tukey IQR fence.

    Fence: [Q1 - multiplier*IQR, Q3 + multiplier*IQR]
    """
    iqr = p75 - p25
    lower = p25 - multiplier * iqr
    upper = p75 + multiplier * iqr
    return value < lower or value > upper


def moving_average_score(
    value: float,
    recent_values: list[float],
    threshold: float = MA_DEVIATION_THRESHOLD,
) -> float:
    """
    Compare value to the moving average of recent_values.

    Returns a score (0–10) proportional to how far value deviates from MA.
    Returns 0.0 if there are fewer than 3 recent values.
    """
    if len(recent_values) < 3:
        return 0.0
    ma = sum(recent_values) / len(recent_values)
    if ma < 1e-9:
        return 0.0
    ratio = value / ma
    # Score scales linearly: ratio of 2.0 → score 5, ratio of 4.0 → score 10
    if ratio < threshold:
        return 0.0
    score = min((ratio - 1.0) * 3.33, 10.0)
    return score


def _combine_signals(zscore: float, iqr_flagged: bool) -> float:
    """
    Combine z-score and IQR signals into a single 0–10 anomaly score.

    Z-score of 3 → score 5; z-score of 6 → score 10.
    IQR flag adds +1 bonus to encourage multi-signal confirmation.
    """
    z_score = min(zscore / 6.0 * 10.0, 10.0)
    bonus = 1.0 if iqr_flagged else 0.0
    return min(z_score + bonus, 10.0)


# ── Per-window scoring ─────────────────────────────────────────────────────────

@dataclass
class WindowScores:
    """Anomaly scores produced for a single traffic window."""
    metric_scores: dict[str, float] = field(default_factory=dict)
    composite: float = 0.0
    baseline_available: bool = False
    details: dict[str, Any] = field(default_factory=dict)


def score_window(
    window: TrafficWindow,
    baseline: dict[str, BaselineRow],
    recent_windows: list[TrafficWindow] | None = None,
) -> WindowScores:
    """
    Score a traffic window against its baseline.

    Args:
        window:          The window to evaluate.
        baseline:        Dict of metric_name -> BaselineRow for the matching
                         (hour_of_day, day_of_week) slot.
        recent_windows:  Optional list of recent windows for moving-average.

    Returns:
        WindowScores with per-metric and composite scores.
    """
    scores = WindowScores()

    if not baseline:
        scores.baseline_available = False
        return scores

    scores.baseline_available = True
    current_scalars = extract_scalars(window)

    for metric, value in current_scalars.items():
        bl = baseline.get(metric)
        if bl is None:
            continue

        # Z-score
        z = zscore_check(value, bl.mean, bl.std)

        # IQR
        flagged = iqr_check(value, bl.p25, bl.p75)

        # Moving average
        ma_score = 0.0
        if recent_windows:
            recent_vals = [
                extract_scalars(w).get(metric, 0.0)
                for w in recent_windows[-10:]
            ]
            ma_score = moving_average_score(value, recent_vals)

        combined = _combine_signals(z, flagged)
        final = max(combined, ma_score)

        scores.metric_scores[metric] = round(final, 2)
        scores.details[metric] = {
            "value": value,
            "baseline_mean": bl.mean,
            "baseline_std": bl.std,
            "zscore": round(z, 2),
            "iqr_flagged": flagged,
            "ma_score": round(ma_score, 2),
            "score": round(final, 2),
        }

    # Composite score = weighted average of per-metric scores
    if scores.metric_scores:
        total_weight = 0.0
        weighted_sum = 0.0
        for metric, s in scores.metric_scores.items():
            w = _METRIC_WEIGHTS.get(metric, 0.05)
            weighted_sum += s * w
            total_weight += w
        scores.composite = round(weighted_sum / total_weight if total_weight > 0 else 0.0, 2)

    return scores
