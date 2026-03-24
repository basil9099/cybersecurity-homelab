"""
Abstract base parser for all SENTINEL ingestion parsers.
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import Any

from core.models import NormalizedFinding


class ParseError(Exception):
    """Raised when a tool output cannot be parsed."""


class BaseParser(ABC):
    """Abstract parser with graceful-degradation via safe_parse()."""

    SOURCE_TOOL: str = ""

    # ------------------------------------------------------------------
    # Concrete helpers
    # ------------------------------------------------------------------

    def load_json(self, path: str) -> Any:
        """Load JSON from *path*, raising ParseError with a clear message on failure."""
        if not os.path.exists(path):
            raise ParseError(f"File not found: {path}")
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except json.JSONDecodeError as exc:
            raise ParseError(f"Invalid JSON in {path}: {exc}") from exc

    def load_csv(self, path: str) -> list[dict]:
        """Load a CSV as a list of dicts (fallback for anomaly detector output)."""
        import csv
        if not os.path.exists(path):
            raise ParseError(f"File not found: {path}")
        try:
            with open(path, "r", encoding="utf-8", newline="") as fh:
                return list(csv.DictReader(fh))
        except Exception as exc:
            raise ParseError(f"Cannot parse CSV {path}: {exc}") from exc

    def safe_parse(self, path: str) -> tuple[list[NormalizedFinding], list[str]]:
        """
        Parse *path* without raising.  Returns (findings, warnings).
        Warnings accumulate non-fatal issues; an empty findings list indicates failure.
        """
        warnings: list[str] = []
        try:
            suffix = os.path.splitext(path)[1].lower()
            if suffix == ".csv":
                raw = self.load_csv(path)
            else:
                raw = self.load_json(path)
            findings = self.parse(raw, source_file=path)
            return findings, warnings
        except ParseError as exc:
            warnings.append(str(exc))
            return [], warnings
        except Exception as exc:
            warnings.append(f"Unexpected error parsing {path}: {exc}")
            return [], warnings

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def parse(self, data: Any, source_file: str = "") -> list[NormalizedFinding]:
        """Convert raw tool data into NormalizedFinding list."""
