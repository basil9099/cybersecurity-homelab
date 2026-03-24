"""
Attack path detection using NetworkX PageRank and path enumeration.
"""

from __future__ import annotations

import uuid
from typing import Any

try:
    import networkx as nx
except ImportError as exc:
    raise ImportError("networkx is required: pip install networkx") from exc

from core.models import AttackPath
from core.constants import PHASE_MULTIPLIERS, PHASE_ORDER

# Phase ordering index for determining "earlier" vs "later" in kill chain
_PHASE_IDX = {p: i for i, p in enumerate(PHASE_ORDER)}

# Entity categories considered "source" (early phase) vs "target" (late phase)
_EARLY_TYPES = {"ips", "domains", "ports"}
_LATE_TYPES = {"cves"}   # CVEs often indicate exploitation


class PathDetector:
    """
    Identifies attack paths in the correlation graph by:
    1. PageRank → high-influence pivot entities
    2. all_simple_paths between high-influence nodes
    3. Path scoring based on edge weights
    """

    def __init__(self, graph: nx.Graph, finding_phases: dict[str, str]) -> None:
        """
        Parameters
        ----------
        graph : nx.Graph
            CorrelationGraph.G
        finding_phases : dict
            {finding_id_prefix: phase_name}
        """
        self.G = graph
        self.finding_phases = finding_phases

    def detect(self, max_paths: int = 10, cutoff: int = 5) -> list[AttackPath]:
        """Detect and return top *max_paths* attack paths sorted by path score."""
        if len(self.G) < 3:
            return []

        try:
            pagerank = nx.pagerank(self.G, weight="weight")
        except Exception:
            return []

        # Select entity nodes (non-finding) sorted by PageRank descending
        entity_nodes = [
            n for n, d in self.G.nodes(data=True)
            if d.get("node_type") not in ("finding", None) and not n.startswith("finding:")
        ]
        if len(entity_nodes) < 2:
            return []

        entity_nodes_ranked = sorted(entity_nodes, key=lambda n: pagerank.get(n, 0), reverse=True)

        # Take top-K as candidate endpoints
        top_k = min(6, len(entity_nodes_ranked))
        sources = entity_nodes_ranked[:top_k]
        targets = entity_nodes_ranked[:top_k]

        paths: list[AttackPath] = []
        seen: set[tuple] = set()

        for src in sources:
            for tgt in targets:
                if src == tgt:
                    continue
                try:
                    for path_nodes in nx.all_simple_paths(self.G, src, tgt, cutoff=cutoff):
                        if len(path_nodes) < 2:
                            continue
                        key = tuple(sorted(path_nodes))
                        if key in seen:
                            continue
                        seen.add(key)

                        edges = [(path_nodes[i], path_nodes[i + 1],
                                  self.G[path_nodes[i]][path_nodes[i + 1]].get("weight", 1))
                                 for i in range(len(path_nodes) - 1)]

                        total_weight = sum(e[2] for e in edges)
                        path_score = total_weight / len(edges) if edges else 0
                        sev = _score_to_severity(path_score)

                        entity_only = [n for n in path_nodes if not n.startswith("finding:")]
                        paths.append(AttackPath(
                            path_id=uuid.uuid4().hex[:8],
                            nodes=list(path_nodes),
                            edges=edges,
                            severity=sev,
                            description=f"Path: {' → '.join(_short(n) for n in entity_only) or ' → '.join(_short(n) for n in path_nodes)}",
                        ))

                        if len(paths) >= max_paths * 3:
                            break
                except nx.NetworkXNoPath:
                    continue
                except Exception:
                    continue

        # Sort by number of hops × edge weight (longer, heavier paths = more interesting)
        paths.sort(key=lambda p: len(p.nodes) + sum(e[2] for e in p.edges), reverse=True)
        return paths[:max_paths]


def _score_to_severity(score: float) -> str:
    if score >= 4:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def _short(node: str) -> str:
    """Return readable label — strip type prefix."""
    if ":" in node:
        return node.split(":", 1)[1]
    return node
