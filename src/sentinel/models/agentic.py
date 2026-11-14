from typing import Literal

from pydantic import Field, model_validator

from .base import Model
from .graph import EdgeType, NodeType


class ProposedNode(Model):
    key: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9_.:/-]+$")
    type: NodeType
    name: str = Field(min_length=1, max_length=200)
    path: str | None = None
    symbol: str | None = Field(default=None, max_length=300)
    evidence_ids: list[str] = Field(min_length=1, max_length=20)
    attributes: dict = Field(default_factory=dict)


class ProposedEdge(Model):
    source: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=200)
    type: EdgeType
    epistemic_status: Literal["observed", "inferred"] = "inferred"
    evidence_ids: list[str] = Field(min_length=1, max_length=20)
    attributes: dict = Field(default_factory=dict)


class GraphDelta(Model):
    nodes: list[ProposedNode] = Field(default_factory=list, max_length=80)
    edges: list[ProposedEdge] = Field(default_factory=list, max_length=160)

    @model_validator(mode="after")
    def unique_keys(self):
        keys = [node.key for node in self.nodes]
        if len(keys) != len(set(keys)):
            raise ValueError("Graph proposal node keys must be unique")
        return self


class FindingInput(Model):
    cwe: str = Field(pattern=r"^CWE-[0-9]+$")
    title: str = Field(min_length=1, max_length=240)
    symbol: str = Field(default="<module>", max_length=300)
    sink_start_line: int = Field(ge=1)
    sink_end_line: int = Field(ge=1)
    source_evidence_ids: list[str] = Field(min_length=1, max_length=20)
    sink_evidence_ids: list[str] = Field(min_length=1, max_length=20)
    confidence: Literal["medium", "high"] = "medium"
    assumptions: list[str] = Field(default_factory=list, max_length=12)
    unknowns: list[str] = Field(default_factory=list, max_length=12)
    interruption_points: list[str] = Field(min_length=1, max_length=12)

    @model_validator(mode="after")
    def ordered_sink(self):
        if self.sink_end_line < self.sink_start_line:
            raise ValueError("Finding sink span is reversed")
        return self


class FindingProposal(FindingInput):
    path: str


class SecurityReviewInput(Model):
    status: Literal["finding_proposed", "no_finding", "inconclusive"]
    evidence_ids: list[str] = Field(min_length=1, max_length=40)
    counterevidence_ids: list[str] = Field(default_factory=list, max_length=40)
    rationale: str = Field(min_length=1, max_length=1200)


class SecurityReview(SecurityReviewInput):
    path: str


class OutcomeMappingProposal(Model):
    finding_id: str
    outcome_id: Literal["unauthorized_refund", "sensitive_data_exposure", "unauthorized_agent_tool_action"]
    evidence_ids: list[str] = Field(min_length=1, max_length=40)
    rationale: str = Field(min_length=1, max_length=1200)


class AgentRunManifest(Model):
    mode: Literal["agent_analysis", "structure_only"]
    provider: str | None = None
    model: str | None = None
    snapshot: str
    skills: list[str]
    graph_proposal_count: int = 0
    finding_proposal_count: int = 0
    security_review_count: int = 0
    outcome_mapping_count: int = 0
    labels_available_to_agent: bool = False
    source_executed: bool = False
