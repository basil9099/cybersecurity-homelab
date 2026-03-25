#!/usr/bin/env python3
"""
alerts/engine.py
================
Alert processing engine: composite scoring, graduated severity levels,
alert suppression, and coordinated incident detection.

Alert levels
------------
  low    (composite score 1.0–3.9):  write to DB only; no console output
  medium (composite score 4.0–6.9):  console warning + DB log
  high   (composite score ≥ 7.0):    bold red escalation + DB log

Suppression
-----------
  If the same (anomaly_type, src_ip) pair fired a non-suppressed alert within
  the configured suppress_window_seconds, subsequent alerts are logged as
  suppressed and do not generate console output.

Coordination
------------
  If ≥3 distinct anomaly types fire simultaneously in a single evaluation,
  an additional "coordinated_incident" high-severity alert is emitted.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from analyzer.patterns import AnomalyEvent
from baseline.storage import BaselineStorage
from detector.statistical import WindowScores


# ── Colorama setup ────────────────────────────────────────────────────────────
try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    _COLORS = True
except ImportError:
    _COLORS = False


def _c(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}" if _COLORS else text


def _warn(msg: str) -> None:
    print(_c(f"[!] {msg}", Fore.YELLOW if _COLORS else ""))


def _alert_high(msg: str) -> None:
    print(_c(f"[!!] {msg}", Fore.RED if _COLORS else ""))


def _info(msg: str) -> None:
    print(_c(f"[*] {msg}", Fore.CYAN if _COLORS else ""))


# ── Thresholds ────────────────────────────────────────────────────────────────

SCORE_MEDIUM = 4.0
SCORE_HIGH   = 7.0
COORDINATION_MIN_TYPES = 3     # Min distinct anomaly types for coordinated alert


@dataclass
class Alert:
    """A processed alert ready for logging and display."""
    timestamp: float
    anomaly_type: str
    score: float
    level: str                   # "low" | "medium" | "high"
    detail: dict[str, Any]
    suppressed: bool = False
    db_id: int = 0


@dataclass
class AlertConfig:
    suppress_window_seconds: int = 900    # 15 minutes
    score_medium: float = SCORE_MEDIUM
    score_high: float = SCORE_HIGH
    coordination_min_types: int = COORDINATION_MIN_TYPES
    quiet: bool = False                   # Suppress all console output


class AlertEngine:
    """
    Processes anomaly scores and events into alerts with suppression and
    escalation logic.

    Args:
        db:     Open BaselineStorage for alert persistence and suppression checks.
        config: AlertConfig controlling thresholds and behavior.
    """

    def __init__(self, db: BaselineStorage, config: AlertConfig | None = None):
        self.db = db
        self.cfg = config or AlertConfig()

    # ── Main entry point ──────────────────────────────────────────────────────

    def process(
        self,
        scores: WindowScores,
        pattern_events: list[AnomalyEvent],
        window_timestamp: float | None = None,
    ) -> list[Alert]:
        """
        Process a window's statistical scores and pattern events into alerts.

        Args:
            scores:          Output of detector.statistical.score_window().
            pattern_events:  Output of analyzer.patterns detect_* functions.
            window_timestamp: Timestamp of the evaluated window.

        Returns:
            List of Alert objects (including suppressed ones for audit trail).
        """
        ts = window_timestamp or time.time()
        alerts: list[Alert] = []

        # 1. Statistical anomaly alert from composite score
        if scores.composite >= 1.0:
            alert = self._make_statistical_alert(scores, ts)
            alerts.append(alert)

        # 2. Pattern-based alerts
        for event in pattern_events:
            alert = self._make_pattern_alert(event, ts)
            alerts.append(alert)

        # 3. Coordination check
        if not self.cfg.quiet:
            active_types = {
                a.anomaly_type for a in alerts
                if not a.suppressed and a.level in ("medium", "high")
            }
            if len(active_types) >= self.cfg.coordination_min_types:
                coord_alert = self._make_coordination_alert(active_types, ts)
                alerts.append(coord_alert)

        return alerts

    # ── Alert factories ───────────────────────────────────────────────────────

    def _make_statistical_alert(self, scores: WindowScores, ts: float) -> Alert:
        score = scores.composite
        level = self._level(score)
        src_ip = "statistical"

        suppressed = self._is_suppressed("statistical_anomaly", src_ip)
        detail = {
            "src_ip": src_ip,
            "composite_score": score,
            "top_metrics": self._top_metrics(scores, n=3),
        }

        alert = Alert(
            timestamp=ts,
            anomaly_type="statistical_anomaly",
            score=score,
            level=level,
            detail=detail,
            suppressed=suppressed,
        )
        alert.db_id = self.db.insert_alert(
            anomaly_type=alert.anomaly_type,
            score=alert.score,
            level=alert.level,
            detail=alert.detail,
            suppressed=alert.suppressed,
            timestamp=ts,
        )
        if not suppressed and not self.cfg.quiet:
            self._print_alert(alert)
        return alert

    def _make_pattern_alert(self, event: AnomalyEvent, ts: float) -> Alert:
        level = event.severity
        src_ip = event.src_ip or "unknown"

        suppressed = self._is_suppressed(event.anomaly_type, src_ip)

        alert = Alert(
            timestamp=ts,
            anomaly_type=event.anomaly_type,
            score=event.score,
            level=level,
            detail=event.detail,
            suppressed=suppressed,
        )
        alert.db_id = self.db.insert_alert(
            anomaly_type=alert.anomaly_type,
            score=alert.score,
            level=alert.level,
            detail=alert.detail,
            suppressed=alert.suppressed,
            timestamp=ts,
        )
        if not suppressed and not self.cfg.quiet:
            self._print_alert(alert)
        return alert

    def _make_coordination_alert(self, types: set[str], ts: float) -> Alert:
        detail = {
            "src_ip": "multiple",
            "simultaneous_types": sorted(types),
            "type_count": len(types),
        }
        alert = Alert(
            timestamp=ts,
            anomaly_type="coordinated_incident",
            score=10.0,
            level="high",
            detail=detail,
            suppressed=False,
        )
        alert.db_id = self.db.insert_alert(
            anomaly_type=alert.anomaly_type,
            score=alert.score,
            level=alert.level,
            detail=alert.detail,
            suppressed=False,
            timestamp=ts,
        )
        if not self.cfg.quiet:
            _alert_high(
                f"COORDINATED INCIDENT DETECTED — {len(types)} simultaneous anomaly "
                f"types: {', '.join(sorted(types))}"
            )
        return alert

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _level(self, score: float) -> str:
        if score >= self.cfg.score_high:
            return "high"
        if score >= self.cfg.score_medium:
            return "medium"
        return "low"

    def _is_suppressed(self, anomaly_type: str, src_ip: str) -> bool:
        return self.db.recent_alert_exists(
            anomaly_type=anomaly_type,
            src_ip=src_ip,
            within_seconds=self.cfg.suppress_window_seconds,
        )

    @staticmethod
    def _top_metrics(scores: WindowScores, n: int = 3) -> list[dict[str, Any]]:
        sorted_metrics = sorted(
            scores.metric_scores.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        result = []
        for metric, score in sorted_metrics[:n]:
            detail = scores.details.get(metric, {})
            result.append({
                "metric": metric,
                "score": score,
                "value": detail.get("value"),
                "baseline_mean": detail.get("baseline_mean"),
            })
        return result

    def _print_alert(self, alert: Alert) -> None:
        from datetime import datetime
        ts_str = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
        msg = (
            f"ALERT [{ts_str}] {alert.anomaly_type.upper()} "
            f"score={alert.score:.1f} level={alert.level.upper()}"
        )
        if alert.level == "high":
            _alert_high(msg)
        else:
            _warn(msg)
