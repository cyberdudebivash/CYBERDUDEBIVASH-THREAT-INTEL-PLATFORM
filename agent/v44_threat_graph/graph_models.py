from dataclasses import dataclass
from typing import List, Dict


@dataclass
class ThreatNode:
    id: str
    type: str
    attributes: Dict


@dataclass
class ThreatEdge:
    source: str
    target: str
    relationship: str


class ThreatGraph:

    def __init__(self):
        self.nodes: Dict[str, ThreatNode] = {}
        self.edges: List[ThreatEdge] = []

    def add_node(self, node_id: str, node_type: str, attributes: Dict):

        if node_id not in self.nodes:
            self.nodes[node_id] = ThreatNode(node_id, node_type, attributes)

    def add_edge(self, source: str, target: str, relationship: str):

        self.edges.append(
            ThreatEdge(source, target, relationship)
        )

    def summary(self):

        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges)
        }