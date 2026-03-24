"""
NetworkX correlation graph — nodes are entity strings, edges are co-occurrence weights.
"""

from __future__ import annotations

from itertools import combinations
from typing import Any

try:
    import networkx as nx
except ImportError as exc:
    raise ImportError("networkx is required: pip install networkx") from exc

from core.models import NormalizedFinding


class CorrelationGraph:
    """
    Bipartite-like graph where:
      - Finding nodes (type="finding") connect to entity nodes (type=entity category)
      - Entity–entity edges gain weight for every co-occurring finding
    """

    def __init__(self) -> None:
        self.G: nx.Graph = nx.Graph()

    # ------------------------------------------------------------------
    def add_finding(self, finding: NormalizedFinding) -> None:
        """Add a finding and all its entities to the graph."""
        fid = f"finding:{finding.finding_id[:8]}"
        self.G.add_node(fid, node_type="finding", severity=finding.severity,
                        source_tool=finding.source_tool, title=finding.title)

        entity_nodes = []
        for category, values in finding.entities.items():
            for val in values:
                if not val:
                    continue
                nid = f"{category}:{val}"
                if nid not in self.G:
                    self.G.add_node(nid, node_type=category, value=val)
                # finding → entity edge
                if self.G.has_edge(fid, nid):
                    self.G[fid][nid]["weight"] += 1
                else:
                    self.G.add_edge(fid, nid, weight=1)
                entity_nodes.append(nid)

        # Entity–entity co-occurrence edges
        for a, b in combinations(entity_nodes, 2):
            if self.G.has_edge(a, b):
                self.G[a][b]["weight"] += 1
            else:
                self.G.add_edge(a, b, weight=1)

    # ------------------------------------------------------------------
    def get_entity_subgraph(self) -> nx.Graph:
        """Return a subgraph containing only entity nodes (no finding nodes)."""
        entity_nodes = [n for n, d in self.G.nodes(data=True)
                        if d.get("node_type") != "finding"]
        return self.G.subgraph(entity_nodes).copy()

    def compute_centrality(self) -> dict[str, float]:
        """Degree centrality for all nodes — useful for pivot entity identification."""
        if len(self.G) == 0:
            return {}
        return nx.degree_centrality(self.G)

    def compute_betweenness(self) -> dict[str, float]:
        """Betweenness centrality (chokepoints in the attack graph)."""
        if len(self.G) < 3:
            return {}
        try:
            return nx.betweenness_centrality(self.G, normalized=True, weight="weight")
        except Exception:
            return {}

    def compute_pagerank(self) -> dict[str, float]:
        """PageRank to find high-influence entity nodes."""
        if len(self.G) < 2:
            return {}
        try:
            return nx.pagerank(self.G, weight="weight")
        except Exception:
            return {}
