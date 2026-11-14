from sentinel.graph.store import GraphStore
from sentinel.verification.agent_tool_checks import inspect_agent_tools
from sentinel.verification.auth_checks import inspect_authorization

from .sandbox import verify_fixture


def inspect_source(context, inputs):
    nodes = [n for n in context.graph.nodes if n.id in inputs["node_ids"]]
    return {
        "symbols": [{"id": n.id, "name": n.name, "type": n.type} for n in nodes],
        "evidence_ids": sorted({i for n in nodes for i in n.evidence_ids}),
        "status": "static_supported",
        "source_executed": False,
    }


def retrieve_graph(context, inputs):
    result = GraphStore(context.graph).neighborhood(**inputs)
    # Cache snapshot-independent provenance. Current commit is attached by the reporter.
    for edge in result["edges"]:
        edge.pop("source_commit", None)
    return result


REGISTRY = {
    "inspect_source": inspect_source,
    "inspect_auth": inspect_authorization,
    "inspect_agent_tools": inspect_agent_tools,
    "retrieve_graph": retrieve_graph,
    "mock_verify": lambda context, inputs: verify_fixture(inputs["fixture_id"]),
}
