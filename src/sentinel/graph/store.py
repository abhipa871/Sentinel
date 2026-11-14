import networkx as nx


class GraphStore:
    def __init__(self, graph):
        self.graph = graph
        self.network = nx.MultiDiGraph()
        for node in graph.nodes:
            self.network.add_node(node.id, node=node)
        for edge in graph.edges:
            self.network.add_edge(edge.source, edge.target, key=edge.id, edge=edge)

    def neighborhood(self, node_ids, depth=2, max_nodes=80):
        if not 0 <= depth <= 3 or len(node_ids) > 20:
            raise ValueError("Graph retrieval bounds exceeded")
        if not set(node_ids) <= set(self.network):
            raise ValueError("Unknown graph node")
        selected, frontier = set(node_ids), set(node_ids)
        for _ in range(depth):
            adjacent = set()
            for node in sorted(frontier):
                adjacent.update(self.network.successors(node))
                adjacent.update(self.network.predecessors(node))
            frontier = set(sorted(adjacent - selected)[: max(0, max_nodes - len(selected))])
            selected.update(frontier)
        nodes = [n.model_dump() for n in self.graph.nodes if n.id in selected]
        edges = [e.model_dump() for e in self.graph.edges if e.source in selected and e.target in selected]
        evidence_ids = sorted(
            {i for n in nodes for i in n["evidence_ids"]} | {i for e in edges for i in e["evidence_ids"]}
        )
        return {
            "nodes": nodes,
            "edges": edges,
            "evidence_ids": evidence_ids,
            "depth": depth,
            "max_nodes": max_nodes,
            "bounded": True,
        }
