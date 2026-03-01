"""
CYBERDUDEBIVASH® SENTINEL APEX v29.0 — Graph Database Integration
====================================================================
Enterprise graph database integration for threat relationship analysis.

Supported Backends:
- Neo4j (production recommended)
- NetworkX (in-memory fallback)

Features:
- Threat actor relationship mapping
- Campaign correlation
- Attack path analysis
- IOC relationship graphs
- MITRE ATT&CK technique chains

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Node:
    """Graph node"""
    id: str
    label: str  # threat_actor, campaign, ioc, technique, etc.
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "label": self.label,
            "properties": self.properties,
        }


@dataclass
class Edge:
    """Graph edge/relationship"""
    source_id: str
    target_id: str
    relationship: str  # USES, TARGETS, ATTRIBUTED_TO, etc.
    properties: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "source": self.source_id,
            "target": self.target_id,
            "relationship": self.relationship,
            "properties": self.properties,
        }


@dataclass
class PathResult:
    """Path query result"""
    nodes: List[Node]
    edges: List[Edge]
    length: int


# ══════════════════════════════════════════════════════════════════════════════
# GRAPH INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

class GraphInterface(ABC):
    """Abstract graph database interface"""
    
    @abstractmethod
    def add_node(self, node: Node) -> bool:
        pass
    
    @abstractmethod
    def add_edge(self, edge: Edge) -> bool:
        pass
    
    @abstractmethod
    def get_node(self, node_id: str) -> Optional[Node]:
        pass
    
    @abstractmethod
    def get_neighbors(self, node_id: str, relationship: Optional[str] = None) -> List[Node]:
        pass
    
    @abstractmethod
    def find_path(self, source_id: str, target_id: str, max_depth: int = 5) -> Optional[PathResult]:
        pass
    
    @abstractmethod
    def query(self, cypher: str, parameters: Dict = None) -> List[Dict]:
        pass
    
    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# NETWORKX BACKEND (IN-MEMORY FALLBACK)
# ══════════════════════════════════════════════════════════════════════════════

class NetworkXBackend(GraphInterface):
    """
    In-memory graph using NetworkX.
    Suitable for development and small-scale deployments.
    """
    
    def __init__(self):
        self._graph = None
        self._nodes: Dict[str, Node] = {}
        self._init_graph()
    
    def _init_graph(self):
        """Initialize NetworkX graph"""
        try:
            import networkx as nx
            self._graph = nx.MultiDiGraph()
        except ImportError:
            logger.warning("NetworkX not installed. Using dict fallback.")
            self._graph = None
    
    def add_node(self, node: Node) -> bool:
        """Add node to graph"""
        self._nodes[node.id] = node
        
        if self._graph is not None:
            self._graph.add_node(node.id, label=node.label, **node.properties)
        
        return True
    
    def add_edge(self, edge: Edge) -> bool:
        """Add edge to graph"""
        if self._graph is not None:
            self._graph.add_edge(
                edge.source_id,
                edge.target_id,
                relationship=edge.relationship,
                **edge.properties
            )
        return True
    
    def get_node(self, node_id: str) -> Optional[Node]:
        """Get node by ID"""
        return self._nodes.get(node_id)
    
    def get_neighbors(self, node_id: str, relationship: Optional[str] = None) -> List[Node]:
        """Get neighboring nodes"""
        if self._graph is None:
            return []
        
        neighbors = []
        for _, neighbor_id, data in self._graph.edges(node_id, data=True):
            if relationship is None or data.get("relationship") == relationship:
                if neighbor_id in self._nodes:
                    neighbors.append(self._nodes[neighbor_id])
        
        return neighbors
    
    def find_path(self, source_id: str, target_id: str, max_depth: int = 5) -> Optional[PathResult]:
        """Find shortest path between nodes"""
        if self._graph is None:
            return None
        
        try:
            import networkx as nx
            path = nx.shortest_path(self._graph, source_id, target_id)
            
            nodes = [self._nodes[n] for n in path if n in self._nodes]
            edges = []
            
            for i in range(len(path) - 1):
                edge_data = self._graph.get_edge_data(path[i], path[i + 1])
                if edge_data:
                    for key, data in edge_data.items():
                        edges.append(Edge(
                            source_id=path[i],
                            target_id=path[i + 1],
                            relationship=data.get("relationship", "RELATED"),
                            properties={k: v for k, v in data.items() if k != "relationship"}
                        ))
            
            return PathResult(nodes=nodes, edges=edges, length=len(path) - 1)
        except:
            return None
    
    def query(self, cypher: str, parameters: Dict = None) -> List[Dict]:
        """Execute Cypher-like query (limited support)"""
        logger.warning("Cypher queries not fully supported in NetworkX backend")
        return []
    
    def health_check(self) -> Dict[str, Any]:
        """Check graph health"""
        if self._graph is None:
            return {"backend": "networkx", "status": "unavailable"}
        
        return {
            "backend": "networkx",
            "status": "healthy",
            "nodes": self._graph.number_of_nodes(),
            "edges": self._graph.number_of_edges(),
            "warning": "In-memory graph - data not persisted",
        }


# ══════════════════════════════════════════════════════════════════════════════
# NEO4J BACKEND (PRODUCTION)
# ══════════════════════════════════════════════════════════════════════════════

class Neo4jBackend(GraphInterface):
    """
    Neo4j graph database backend for production.
    Requires: pip install neo4j
    """
    
    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD", "password")
        self._driver = None
        self._fallback = NetworkXBackend()
    
    def _get_driver(self):
        """Lazy load Neo4j driver"""
        if self._driver is None:
            try:
                from neo4j import GraphDatabase
                self._driver = GraphDatabase.driver(
                    self.uri,
                    auth=(self.user, self.password)
                )
            except ImportError:
                logger.warning("Neo4j driver not installed. Using NetworkX fallback.")
                return None
            except Exception as e:
                logger.error(f"Failed to connect to Neo4j: {e}")
                return None
        return self._driver
    
    def add_node(self, node: Node) -> bool:
        """Add node to Neo4j"""
        driver = self._get_driver()
        if driver is None:
            return self._fallback.add_node(node)
        
        try:
            with driver.session() as session:
                props = {**node.properties, "id": node.id}
                props_str = ", ".join(f"{k}: ${k}" for k in props.keys())
                
                session.run(
                    f"MERGE (n:{node.label} {{id: $id}}) SET n = {{{props_str}}}",
                    **props
                )
            return True
        except Exception as e:
            logger.error(f"Failed to add node: {e}")
            return False
    
    def add_edge(self, edge: Edge) -> bool:
        """Add edge to Neo4j"""
        driver = self._get_driver()
        if driver is None:
            return self._fallback.add_edge(edge)
        
        try:
            with driver.session() as session:
                props = edge.properties
                props_str = ", ".join(f"{k}: ${k}" for k in props.keys()) if props else ""
                
                query = f"""
                    MATCH (a {{id: $source_id}})
                    MATCH (b {{id: $target_id}})
                    MERGE (a)-[r:{edge.relationship}]->(b)
                    {f'SET r = {{{props_str}}}' if props else ''}
                """
                
                session.run(
                    query,
                    source_id=edge.source_id,
                    target_id=edge.target_id,
                    **props
                )
            return True
        except Exception as e:
            logger.error(f"Failed to add edge: {e}")
            return False
    
    def get_node(self, node_id: str) -> Optional[Node]:
        """Get node from Neo4j"""
        driver = self._get_driver()
        if driver is None:
            return self._fallback.get_node(node_id)
        
        try:
            with driver.session() as session:
                result = session.run(
                    "MATCH (n {id: $id}) RETURN n, labels(n) as labels",
                    id=node_id
                )
                record = result.single()
                
                if record:
                    node_data = dict(record["n"])
                    labels = record["labels"]
                    return Node(
                        id=node_id,
                        label=labels[0] if labels else "Unknown",
                        properties={k: v for k, v in node_data.items() if k != "id"}
                    )
        except Exception as e:
            logger.error(f"Failed to get node: {e}")
        
        return None
    
    def get_neighbors(self, node_id: str, relationship: Optional[str] = None) -> List[Node]:
        """Get neighboring nodes from Neo4j"""
        driver = self._get_driver()
        if driver is None:
            return self._fallback.get_neighbors(node_id, relationship)
        
        try:
            with driver.session() as session:
                rel_pattern = f":{relationship}" if relationship else ""
                result = session.run(
                    f"MATCH (a {{id: $id}})-[{rel_pattern}]->(b) RETURN b, labels(b) as labels",
                    id=node_id
                )
                
                neighbors = []
                for record in result:
                    node_data = dict(record["b"])
                    labels = record["labels"]
                    neighbors.append(Node(
                        id=node_data.get("id", ""),
                        label=labels[0] if labels else "Unknown",
                        properties={k: v for k, v in node_data.items() if k != "id"}
                    ))
                
                return neighbors
        except Exception as e:
            logger.error(f"Failed to get neighbors: {e}")
        
        return []
    
    def find_path(self, source_id: str, target_id: str, max_depth: int = 5) -> Optional[PathResult]:
        """Find path in Neo4j"""
        driver = self._get_driver()
        if driver is None:
            return self._fallback.find_path(source_id, target_id, max_depth)
        
        try:
            with driver.session() as session:
                result = session.run(
                    f"""
                    MATCH path = shortestPath(
                        (a {{id: $source}})-[*..{max_depth}]-(b {{id: $target}})
                    )
                    RETURN path, length(path) as length
                    """,
                    source=source_id,
                    target=target_id
                )
                
                record = result.single()
                if record:
                    path = record["path"]
                    nodes = []
                    edges = []
                    
                    for node in path.nodes:
                        node_data = dict(node)
                        nodes.append(Node(
                            id=node_data.get("id", ""),
                            label=list(node.labels)[0] if node.labels else "Unknown",
                            properties={k: v for k, v in node_data.items() if k != "id"}
                        ))
                    
                    for rel in path.relationships:
                        edges.append(Edge(
                            source_id=dict(rel.start_node).get("id", ""),
                            target_id=dict(rel.end_node).get("id", ""),
                            relationship=rel.type,
                            properties=dict(rel)
                        ))
                    
                    return PathResult(nodes=nodes, edges=edges, length=record["length"])
        except Exception as e:
            logger.error(f"Failed to find path: {e}")
        
        return None
    
    def query(self, cypher: str, parameters: Dict = None) -> List[Dict]:
        """Execute Cypher query"""
        driver = self._get_driver()
        if driver is None:
            return []
        
        try:
            with driver.session() as session:
                result = session.run(cypher, **(parameters or {}))
                return [dict(record) for record in result]
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return []
    
    def health_check(self) -> Dict[str, Any]:
        """Check Neo4j health"""
        driver = self._get_driver()
        if driver is None:
            return {"backend": "neo4j", "status": "fallback_to_networkx"}
        
        try:
            with driver.session() as session:
                result = session.run("CALL dbms.components() YIELD versions RETURN versions[0] as version")
                record = result.single()
                
                # Get counts
                stats = session.run(
                    "MATCH (n) RETURN count(n) as nodes UNION ALL MATCH ()-[r]->() RETURN count(r) as edges"
                )
                
                return {
                    "backend": "neo4j",
                    "status": "healthy",
                    "version": record["version"] if record else "unknown",
                    "uri": self.uri,
                }
        except Exception as e:
            return {"backend": "neo4j", "status": "unhealthy", "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# THREAT GRAPH OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

class ThreatGraph:
    """
    High-level threat intelligence graph operations.
    Abstracts graph database operations for threat analysis.
    """
    
    def __init__(self, backend: Optional[GraphInterface] = None):
        self.backend = backend or get_client()._backend
    
    def add_threat_actor(self, actor_id: str, name: str, **properties) -> bool:
        """Add threat actor node"""
        return self.backend.add_node(Node(
            id=actor_id,
            label="ThreatActor",
            properties={"name": name, **properties}
        ))
    
    def add_campaign(self, campaign_id: str, name: str, **properties) -> bool:
        """Add campaign node"""
        return self.backend.add_node(Node(
            id=campaign_id,
            label="Campaign",
            properties={"name": name, **properties}
        ))
    
    def add_ioc(self, ioc_type: str, value: str, **properties) -> bool:
        """Add IOC node"""
        ioc_id = f"ioc--{ioc_type}--{value}"
        return self.backend.add_node(Node(
            id=ioc_id,
            label="IOC",
            properties={"type": ioc_type, "value": value, **properties}
        ))
    
    def add_technique(self, technique_id: str, name: str, tactic: str, **properties) -> bool:
        """Add MITRE ATT&CK technique node"""
        return self.backend.add_node(Node(
            id=technique_id,
            label="Technique",
            properties={"name": name, "tactic": tactic, **properties}
        ))
    
    def link_actor_to_campaign(self, actor_id: str, campaign_id: str) -> bool:
        """Link threat actor to campaign"""
        return self.backend.add_edge(Edge(
            source_id=actor_id,
            target_id=campaign_id,
            relationship="ATTRIBUTED_TO"
        ))
    
    def link_campaign_to_ioc(self, campaign_id: str, ioc_id: str) -> bool:
        """Link campaign to IOC"""
        return self.backend.add_edge(Edge(
            source_id=campaign_id,
            target_id=ioc_id,
            relationship="USES"
        ))
    
    def link_campaign_to_technique(self, campaign_id: str, technique_id: str) -> bool:
        """Link campaign to technique"""
        return self.backend.add_edge(Edge(
            source_id=campaign_id,
            target_id=technique_id,
            relationship="EMPLOYS"
        ))
    
    def get_actor_campaigns(self, actor_id: str) -> List[Node]:
        """Get all campaigns by threat actor"""
        return self.backend.get_neighbors(actor_id, "ATTRIBUTED_TO")
    
    def get_campaign_iocs(self, campaign_id: str) -> List[Node]:
        """Get all IOCs used in campaign"""
        return self.backend.get_neighbors(campaign_id, "USES")
    
    def find_attack_path(self, source_ioc: str, target_system: str) -> Optional[PathResult]:
        """Find potential attack path from IOC to target"""
        return self.backend.find_path(source_ioc, target_system)


# ══════════════════════════════════════════════════════════════════════════════
# GRAPH CLIENT FACTORY
# ══════════════════════════════════════════════════════════════════════════════

class GraphClient:
    """Unified graph client"""
    
    def __init__(self, backend_type: Optional[str] = None):
        backend_type = backend_type or os.getenv("SENTINEL_GRAPH", "networkx")
        
        if backend_type == "neo4j":
            self._backend = Neo4jBackend()
        else:
            self._backend = NetworkXBackend()
        
        self._type = backend_type
        self.threat_graph = ThreatGraph(self._backend)
    
    def add_node(self, node: Node) -> bool:
        return self._backend.add_node(node)
    
    def add_edge(self, edge: Edge) -> bool:
        return self._backend.add_edge(edge)
    
    def get_node(self, node_id: str) -> Optional[Node]:
        return self._backend.get_node(node_id)
    
    def get_neighbors(self, node_id: str, relationship: Optional[str] = None) -> List[Node]:
        return self._backend.get_neighbors(node_id, relationship)
    
    def find_path(self, source_id: str, target_id: str, max_depth: int = 5) -> Optional[PathResult]:
        return self._backend.find_path(source_id, target_id, max_depth)
    
    def query(self, cypher: str, parameters: Dict = None) -> List[Dict]:
        return self._backend.query(cypher, parameters)
    
    def health_check(self) -> Dict[str, Any]:
        return self._backend.health_check()
    
    @property
    def backend_type(self) -> str:
        return self._type


# ══════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

_client_instance: Optional[GraphClient] = None


def get_client(backend_type: Optional[str] = None) -> GraphClient:
    """Get graph client singleton"""
    global _client_instance
    
    requested_type = backend_type or os.getenv("SENTINEL_GRAPH", "networkx")
    
    if _client_instance is None or _client_instance.backend_type != requested_type:
        _client_instance = GraphClient(requested_type)
    
    return _client_instance


__all__ = [
    "Node",
    "Edge",
    "PathResult",
    "GraphInterface",
    "NetworkXBackend",
    "Neo4jBackend",
    "ThreatGraph",
    "GraphClient",
    "get_client",
]
