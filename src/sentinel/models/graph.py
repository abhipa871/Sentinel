from typing import Literal

from pydantic import Field, model_validator

from .base import Model
from .evidence import Evidence, Status

NodeType = Literal[
    "FILE",
    "MODULE",
    "PACKAGE",
    "APPLICATION",
    "FUNCTION",
    "API_ENDPOINT",
    "IDENTITY",
    "DATASTORE",
    "DATA_ASSET",
    "AI_AGENT",
    "TOOL",
    "DEPENDENCY",
    "CONFIG",
    "SECURITY_CONTROL",
    "BUSINESS_FUNCTION",
    "SECURITY_STATE",
    "EVIDENCE",
]
EdgeType = Literal[
    "CALLS",
    "IMPORTS",
    "EXPOSES",
    "READS",
    "WRITES",
    "RUNS_AS",
    "CAN_INVOKE",
    "HAS_PERMISSION",
    "DEPENDS_ON",
    "COMMUNICATES_WITH",
    "PROTECTS",
    "GOVERNED_BY",
    "SUPPORTS",
    "MAY_ENABLE",
    "SUPPORTED_BY_EVIDENCE",
]


class Node(Model):
    id: str
    type: NodeType
    name: str
    path: str | None = None
    symbol: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    attributes: dict = Field(default_factory=dict)


class Edge(Model):
    id: str
    source: str
    target: str
    type: EdgeType
    epistemic_status: Status = "observed"
    confidence: float | None = Field(default=None, ge=0, le=1)
    evidence_ids: list[str] = Field(default_factory=list)
    source_commit: str
    attributes: dict = Field(default_factory=dict)


class OrganizationGraph(Model):
    nodes: list[Node] = Field(default_factory=list)
    edges: list[Edge] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)

    @model_validator(mode="after")
    def references(self):
        nodes = {n.id for n in self.nodes}
        evidence = {e.id for e in self.evidence}
        if len(nodes) != len(self.nodes) or len(evidence) != len(self.evidence):
            raise ValueError("Duplicate graph or evidence ID")
        for node in self.nodes:
            if not set(node.evidence_ids) <= evidence:
                raise ValueError("Unknown node evidence")
        for edge in self.edges:
            if edge.source not in nodes or edge.target not in nodes:
                raise ValueError("Dangling graph edge")
            if not set(edge.evidence_ids) <= evidence:
                raise ValueError("Unknown edge evidence")
        return self
