"""
Zero-shot MITRE ATT&CK phase mapping using TF-IDF + cosine similarity.
No training data required — the MITRE_PHASES keyword corpus IS the "training set".
"""

from __future__ import annotations

from core.models import NormalizedFinding
from core.constants import MITRE_PHASES

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    import numpy as np
except ImportError as exc:
    raise ImportError("scikit-learn + numpy are required: pip install scikit-learn numpy") from exc

_MIN_CONFIDENCE = 0.05   # Below this, phase is considered uncertain
_DEFAULT_PHASE = "Reconnaissance"


def _phase_document(phrases: list[str]) -> str:
    """Concatenate phrase list into one document for the phase corpus."""
    return " ".join(phrases)


class KillChainMapper:
    """
    Fits a TF-IDF vectorizer on MITRE ATT&CK phase keyword corpora at init.
    At inference, transforms a finding's text and finds the most similar phase
    via cosine similarity.
    """

    def __init__(self) -> None:
        self._phases = list(MITRE_PHASES.keys())
        corpus = [_phase_document(MITRE_PHASES[p]) for p in self._phases]

        self._vectorizer = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
        self._phase_matrix = self._vectorizer.fit_transform(corpus)

    def _text_for_finding(self, finding: NormalizedFinding) -> str:
        return (
            f"{finding.title} {finding.description} "
            + " ".join(finding.entities.get("cves", []))
            + " " + " ".join(finding.entities.get("ips", []))
            + " " + finding.source_tool
        )

    def map_finding(self, finding: NormalizedFinding) -> tuple[str, float]:
        """
        Returns (phase_name, confidence_score).
        Confidence is the cosine similarity to the best-matching phase (0–1).
        """
        return self._map_text(self._text_for_finding(finding))

    def map_text(self, text: str) -> tuple[str, float]:
        """Map an arbitrary text string to a MITRE phase."""
        return self._map_text(text)

    def _map_text(self, text: str) -> tuple[str, float]:
        if not text.strip():
            return _DEFAULT_PHASE, 0.0
        try:
            vec = self._vectorizer.transform([text])
            sims = cosine_similarity(vec, self._phase_matrix)[0]
            best_idx = int(np.argmax(sims))
            confidence = float(sims[best_idx])
            phase = self._phases[best_idx]
            if confidence < _MIN_CONFIDENCE:
                return _DEFAULT_PHASE, confidence
            return phase, confidence
        except Exception:
            return _DEFAULT_PHASE, 0.0
