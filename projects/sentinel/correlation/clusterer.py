"""
TF-IDF + DBSCAN campaign clustering.
Groups related findings across tools into attack "campaigns".
"""

from __future__ import annotations

from core.models import NormalizedFinding

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import normalize
except ImportError as exc:
    raise ImportError("scikit-learn is required: pip install scikit-learn") from exc


def _finding_document(f: NormalizedFinding) -> str:
    """Build a text document representing a finding for TF-IDF."""
    entity_strs = (
        " ".join(f.entities.get("ips", []))
        + " " + " ".join(f.entities.get("cves", []))
        + " " + " ".join(f.entities.get("domains", []))
        + " " + " ".join(f.entities.get("ports", []))
    )
    return f"{f.title} {f.description} {entity_strs} {f.source_tool}"


class CampaignClusterer:
    """
    Unsupervised DBSCAN clustering on TF-IDF finding vectors.

    Parameters
    ----------
    eps : float
        DBSCAN neighbourhood radius in cosine space (0–1).
        Lower → tighter clusters; higher → more permissive.
    min_samples : int
        Minimum findings to form a core cluster.
    """

    def __init__(self, eps: float = 0.4, min_samples: int = 2) -> None:
        self.eps = eps
        self.min_samples = min_samples

    def cluster(self, findings: list[NormalizedFinding]) -> dict[int, list[str]]:
        """
        Returns {cluster_label: [finding_id, ...]}.
        Noise points (DBSCAN label -1) each become a separate singleton cluster
        with IDs starting from max_cluster + 1.
        """
        if not findings:
            return {}

        # Degenerate: too few for meaningful clustering
        if len(findings) < self.min_samples:
            return {0: [f.finding_id for f in findings]}

        # Build TF-IDF matrix
        docs = [_finding_document(f) for f in findings]
        vectorizer = TfidfVectorizer(
            max_features=500,
            ngram_range=(1, 2),
            sublinear_tf=True,
            min_df=1,
        )
        tfidf = vectorizer.fit_transform(docs)
        # Normalise for cosine metric
        tfidf_norm = normalize(tfidf, norm="l2")

        # DBSCAN
        db = DBSCAN(eps=self.eps, min_samples=self.min_samples, metric="cosine", algorithm="brute")
        labels = db.fit_predict(tfidf_norm)

        # Build result dict (convert numpy ints → Python ints for JSON serialisation)
        clusters: dict[int, list[str]] = {}
        noise_counter = int(max(labels)) + 1

        for finding, label in zip(findings, labels):
            if int(label) == -1:
                # Noise → singleton cluster
                clusters[noise_counter] = [finding.finding_id]
                noise_counter += 1
            else:
                clusters.setdefault(int(label), []).append(finding.finding_id)

        return clusters
