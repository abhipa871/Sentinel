from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


KnowledgeEntityType = Literal[
    "CWE",
    "CVE",
    "CAPEC",
    "ATLAS_TACTIC",
    "ATLAS_TECHNIQUE",
    "ATLAS_SUBTECHNIQUE",
    "ATLAS_CASE",
    "MITIGATION",
    "PRODUCT",
    "PACKAGE",
    "DEFENSIVE_TECHNIQUE",
]


class AssetType(StrEnum):
    SOURCE_FILE = "SOURCE_FILE"
    SQL_FILE = "SQL_FILE"
    DATABASE_FILE = "DATABASE_FILE"
    CONFIG_FILE = "CONFIG_FILE"
    MANIFEST_FILE = "MANIFEST_FILE"
    INFRA_FILE = "INFRA_FILE"
    WORKFLOW_FILE = "WORKFLOW_FILE"
    MODEL_ARTIFACT = "MODEL_ARTIFACT"
    NOTEBOOK_FILE = "NOTEBOOK_FILE"
    DATA_FILE = "DATA_FILE"
    BINARY_ASSET = "BINARY_ASSET"
    DOCUMENTATION_FILE = "DOCUMENTATION_FILE"
    OTHER_FILE = "OTHER_FILE"


class EdgeType(StrEnum):
    IMPORTS = "IMPORTS"
    CALLS_IN = "CALLS_IN"
    READS = "READS"
    WRITES = "WRITES"
    LOADS_CONFIG = "LOADS_CONFIG"
    INVOKES_TOOL = "INVOKES_TOOL"
    ROUTES_TO = "ROUTES_TO"
    EXECUTES = "EXECUTES"
    DEPENDS_ON_MANIFEST = "DEPENDS_ON_MANIFEST"
    REFERENCES = "REFERENCES"


class CoverageState(StrEnum):
    SUPPORTED_FULL = "supported_full"
    SUPPORTED_PARTIAL = "supported_partial"
    METADATA_ONLY = "metadata_only"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class EvidenceRef(FrozenModel):
    evidence_id: str
    producer: str
    source_path: str
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    content_sha256: str
    assertion_origin: Literal["observed", "official", "derived_rule", "agent_inference"]
    summary: str


class RepositorySnapshot(FrozenModel):
    snapshot_id: UUID = Field(default_factory=uuid4)
    repo_id: UUID = Field(default_factory=uuid4)
    source: str
    commit_sha: str
    acquisition_mode: Literal["LOCAL_READ_ONLY", "API_ONLY", "PINNED_CLONE", "METADATA_ONLY"]
    graph_schema_version: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    partial: bool = False
    warnings: tuple[str, ...] = ()


class Asset(FrozenModel):
    snapshot_id: UUID
    asset_id: str
    logical_asset_key: str
    path: str
    node_type: AssetType
    language: str | None = None
    content_sha256: str
    size_bytes: int = Field(ge=0)
    line_count: int | None = Field(default=None, ge=0)
    is_generated: bool = False
    is_vendor: bool = False
    is_binary: bool = False
    parser_status: CoverageState
    features: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: tuple[str, ...] = ()

    @field_validator("path")
    @classmethod
    def safe_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or value.startswith(("/", "\\")):
            raise ValueError("asset path must be repository-relative")
        return path.as_posix()


class AssetEdge(FrozenModel):
    snapshot_id: UUID
    edge_id: str
    source_asset_id: str
    target_asset_id: str
    edge_type: EdgeType
    confidence: Literal["high", "medium", "low"]
    resolution_method: str
    source_location: str
    target_location: str | None = None
    evidence_refs: tuple[str, ...]
    is_dynamic_unknown: bool = False


class UnresolvedReference(FrozenModel):
    snapshot_id: UUID
    source_asset_id: str
    reference: str
    kind: str
    location: str
    reason: str


class RepositoryAssetGraph(FrozenModel):
    snapshot: RepositorySnapshot
    assets: tuple[Asset, ...]
    edges: tuple[AssetEdge, ...]
    unresolved: tuple[UnresolvedReference, ...] = ()
    evidence: tuple[EvidenceRef, ...] = ()
    digest: str

    @model_validator(mode="after")
    def validate_graph(self) -> RepositoryAssetGraph:
        ids = {a.asset_id for a in self.assets}
        if len(ids) != len(self.assets):
            raise ValueError("asset IDs must be unique")
        if len({a.path for a in self.assets}) != len(self.assets):
            raise ValueError("asset paths must be unique")
        for edge in self.edges:
            if edge.source_asset_id not in ids or edge.target_asset_id not in ids:
                raise ValueError("edge endpoints must exist in this snapshot")
            if edge.snapshot_id != self.snapshot.snapshot_id:
                raise ValueError("edge snapshot mismatch")
        return self


class RepositoryGraphAssetAnnotation(FrozenModel):
    asset_id: str
    file_role: str
    node_priority: float = Field(ge=0, le=1)
    security_relevance: str
    evidence_refs: tuple[str, ...]


class RepositoryGraphEdgeProposal(FrozenModel):
    source_asset_id: str
    target_asset_id: str
    edge_type: EdgeType
    confidence: Literal["high", "medium", "low"]
    resolution_basis: str
    source_location: str | None = None
    target_location: str | None = None
    evidence_refs: tuple[str, ...]
    is_dynamic_unknown: bool = False


class RepositoryGraphUnresolvedProposal(FrozenModel):
    source_asset_id: str
    reference: str
    kind: str
    location: str
    reason: str


class RepositoryGraphSpecialistReview(FrozenModel):
    specialist: Literal["repository-scan", "dependency-graph-building", "graph-review"]
    conclusions: tuple[str, ...]
    supporting_evidence_refs: tuple[str, ...]
    asset_ids: tuple[str, ...]
    unknown_conditions: tuple[str, ...]


class RepositoryGraphAgentOutput(FrozenModel):
    asset_annotations: tuple[RepositoryGraphAssetAnnotation, ...]
    edges: tuple[RepositoryGraphEdgeProposal, ...]
    unresolved: tuple[RepositoryGraphUnresolvedProposal, ...]
    analyzed_asset_ids: tuple[str, ...]
    coverage_warnings: tuple[str, ...]
    summary: str
    specialist_reviews: tuple[str, ...]


class CriticalitySignal(FrozenModel):
    vulnerability_id: str
    catalog_severity: str | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = None
    cvss_base_score: float | None = Field(default=None, ge=0, le=10)
    epss_probability: float | None = Field(default=None, ge=0, le=1)
    in_cisa_kev: bool | None = None
    source_refs: tuple[str, ...] = ()


class ApplicabilityRule(FrozenModel):
    rule_id: str
    vulnerability_id: str
    vulnerability_name: str
    rule_version: int = Field(ge=1)
    applicable_asset_types: tuple[AssetType, ...]
    language_tags: tuple[str, ...] = ()
    required_features: dict[str, Any]
    excluded_features: dict[str, Any] = Field(default_factory=dict)
    necessary_preconditions: tuple[str, ...] = ()
    derivation_kind: Literal["catalog_direct", "catalog_normalized", "curated_derived"]
    source_refs: tuple[str, ...]
    weight: float = Field(default=1, ge=0, le=1)


class KnowledgeSnapshot(FrozenModel):
    kb_snapshot_id: UUID = Field(default_factory=uuid4)
    version: str
    rules: tuple[ApplicabilityRule, ...]
    criticality: tuple[CriticalitySignal, ...] = ()
    source_manifest: dict[str, str]
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class KnowledgeEntity(FrozenModel):
    entity_id: str
    entity_type: KnowledgeEntityType
    name: str
    description: str | None = None
    raw_id: str | None = None
    status: str | None = None
    aliases: tuple[str, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_system: str
    source_version: str
    assertion_origin: Literal["official", "derived_rule", "agent_inference"] = "official"


class KnowledgeRelation(FrozenModel):
    source_id: str
    relation_type: str
    target_id: str
    source_ref: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_system: str
    source_version: str
    assertion_origin: Literal["official", "derived_rule", "agent_inference"] = "official"


class KnowledgeGraphSnapshot(FrozenModel):
    kb_snapshot_id: UUID = Field(default_factory=uuid4)
    version: str
    graph_schema_version: int = Field(default=1, ge=1)
    parser_version: str = "sentinel-gv-etl-v1"
    entities: tuple[KnowledgeEntity, ...]
    relations: tuple[KnowledgeRelation, ...]
    source_manifest: dict[str, str]
    statistics: dict[str, int] = Field(default_factory=dict)
    digest: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def validate_knowledge_graph(self) -> KnowledgeGraphSnapshot:
        entity_ids = {entity.entity_id for entity in self.entities}
        if len(entity_ids) != len(self.entities):
            raise ValueError("knowledge entity IDs must be unique")
        for relation in self.relations:
            if relation.source_id not in entity_ids or relation.target_id not in entity_ids:
                raise ValueError("knowledge relation endpoints must exist in this snapshot")
            if relation.source_id.startswith("CVE-") and relation.target_id.startswith("CVE-"):
                raise ValueError("CVE-to-CVE relations are forbidden in G_V")
        return self


class RelatedAsset(FrozenModel):
    asset_id: str
    path: str
    edge_types: tuple[str, ...]
    graph_distance: int = Field(ge=0)
    evidence_refs: tuple[str, ...]
    role: str | None = None


class PotentialVulnerabilityRow(FrozenModel):
    candidate_id: str
    snapshot_id: UUID
    kb_snapshot_id: UUID
    asset_id: str
    node: str
    asset_type: AssetType
    vulnerability_id: str
    vulnerability_name: str
    hypothesis: str
    catalog_severity: str | None
    catalog_cvss: float | None
    investigation_priority: float = Field(ge=0, le=1)
    priority_features: dict[str, float | None]
    related_nodes: tuple[RelatedAsset, ...]
    rule_ids: tuple[str, ...]
    observed_evidence_refs: tuple[str, ...]
    untested_preconditions: tuple[str, ...]
    derivation_kind: str
    knowledge_context: dict[str, Any] = Field(default_factory=dict)
    candidate_status: Literal["potential"] = "potential"
    coverage_warnings: tuple[str, ...] = ()


class ModuleOneCandidateProposal(FrozenModel):
    primary_asset_id: str
    vulnerability_id: str
    vulnerability_name: str
    hypothesis: str
    investigation_priority: float = Field(ge=0, le=1)
    observed_evidence_refs: tuple[str, ...]
    related_asset_ids: tuple[str, ...] = ()
    untested_preconditions: tuple[str, ...]
    discovery_basis: str
    coverage_warnings: tuple[str, ...] = ()


class ModuleOneSpecialistReview(FrozenModel):
    specialist: Literal["repository-mapping", "candidate-discovery", "candidate-review"]
    conclusions: tuple[str, ...]
    supporting_evidence_refs: tuple[str, ...]
    asset_ids: tuple[str, ...]
    unknown_conditions: tuple[str, ...]


class ModuleOneAgentOutput(FrozenModel):
    candidates: tuple[ModuleOneCandidateProposal, ...]
    analyzed_asset_ids: tuple[str, ...]
    coverage_warnings: tuple[str, ...]
    summary: str
    specialist_reviews: tuple[str, ...]


class VerificationStatus(StrEnum):
    CONFIRMED = "confirmed"
    STRONGLY_SUPPORTED = "strongly_supported"
    INCONCLUSIVE = "inconclusive"
    REFUTED = "refuted"
    NOT_ANALYZED = "not_analyzed"


class SpecialistReview(FrozenModel):
    specialist: Literal[
        "traversal",
        "code-analysis",
        "dependency-config",
        "ai-security",
        "evidence-review",
    ]
    conclusions: tuple[str, ...]
    supporting_evidence_refs: tuple[str, ...]
    contradictory_evidence_refs: tuple[str, ...]
    unknown_conditions: tuple[str, ...]
    requested_followup: tuple[str, ...] = ()


class SecurityReviewProposal(FrozenModel):
    candidate_id: str
    primary_asset_id: str
    vulnerability_id: str
    status: VerificationStatus
    supporting_evidence_refs: tuple[str, ...]
    contradictory_evidence_refs: tuple[str, ...]
    related_nodes: tuple[RelatedAsset, ...]
    criticality: Literal["critical", "high", "medium", "low", "unknown"]
    criticality_basis: str
    relationship_explanation: str
    assumptions: tuple[str, ...]
    analyst_summary: str
    specialist_reviews: tuple[str, ...]


class DetectedVulnerabilityRow(FrozenModel):
    finding_id: UUID = Field(default_factory=uuid4)
    snapshot_id: UUID
    candidate_id: str
    primary_asset_id: str
    node: str
    detected_vulnerability: str
    verification_status: VerificationStatus
    criticality: Literal["critical", "high", "medium", "low", "unknown"]
    criticality_basis: str
    related_nodes: tuple[RelatedAsset, ...]
    relationship_explanation: str
    source_sink_evidence_refs: tuple[str, ...]
    contradictory_evidence_refs: tuple[str, ...]
    assumptions: tuple[str, ...]
    analyst_summary: str


class AttackPath(FrozenModel):
    path_id: str
    finding_ids: tuple[UUID, ...]
    asset_ids: tuple[str, ...]
    edge_refs: tuple[str, ...]
    prerequisites: tuple[str, ...]
    prerequisite_evidence_refs: tuple[str, ...]
    exposure_status: Literal["supported", "conditional", "hypothesized"]
    impact_weight: int = Field(ge=1, le=10)


class ProposalDecision(StrEnum):
    PENDING = "pending"
    ACCEPT = "accept"
    REJECT = "reject"
    MODIFY = "modify"
    DEFER = "defer"


class RemediationProposal(FrozenModel):
    proposal_id: UUID = Field(default_factory=uuid4)
    version: int = Field(default=1, ge=1)
    snapshot_id: UUID
    finding_ids: tuple[UUID, ...]
    affected_asset_ids: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    title: str
    problem_summary: str
    proposed_change_natural_language: str
    detailed_technical_spec: str
    alternatives: tuple[str, ...]
    security_invariant: str
    mitigation_mechanism: str
    expected_path_ids_blocked: tuple[str, ...]
    prerequisites: tuple[str, ...]
    conflicts_with: tuple[UUID, ...] = ()
    depends_on: tuple[UUID, ...] = ()
    functional_invariants: tuple[str, ...] = ()
    planned_tests: tuple[str, ...] = ()
    cost_points: int = Field(default=1, ge=1, le=100)
    disruption_points: int = Field(default=1, ge=0, le=100)
    operational_side_effects: tuple[str, ...] = ()
    rollback_plan: str
    risk_reduction_assumptions: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    human_decision: ProposalDecision = ProposalDecision.PENDING

    @field_validator("allowed_paths")
    @classmethod
    def safe_paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            path = PurePosixPath(value)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("proposal path escapes repository")
        return values


class GovernanceProposal(FrozenModel):
    control_id: UUID = Field(default_factory=uuid4)
    version: int = 1
    title: str
    risk_or_finding_ids: tuple[UUID, ...]
    framework_refs: tuple[str, ...]
    policy_text_natural_language: str
    concrete_enforcement: tuple[str, ...]
    affected_asset_ids: tuple[str, ...]
    accountable_role: str | None = None
    role_assignment_status: Literal["derived", "needs_confirmation", "assigned"]
    evidence_of_operation: tuple[str, ...]
    review_cadence: str | None = None
    exception_process: str
    implementation_type: Literal["repo_policy", "CI_control", "procedural", "platform_setting"]
    approval_authority_role: str
    decision: ProposalDecision = ProposalDecision.PENDING


class PlanningSpecialistReview(FrozenModel):
    specialist: Literal[
        "graph-impact",
        "remediation",
        "functional-constraint",
        "governance",
        "plan-review",
    ]
    conclusions: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    assumptions: tuple[str, ...]
    constraints_or_issues: tuple[str, ...]


class PlanningProposal(FrozenModel):
    attack_paths: tuple[AttackPath, ...]
    remediations: tuple[RemediationProposal, ...]
    governance: tuple[GovernanceProposal, ...]
    review_summary: str
    assumptions: tuple[str, ...]


class OptimizationResult(FrozenModel):
    solver_status: Literal["sat", "unsat", "unknown", "timeout"]
    selected_proposal_ids: tuple[UUID, ...]
    exposed_path_ids: tuple[str, ...]
    residual_exposure: int
    total_cost: int
    total_disruption: int
    explanation: str
    input_sha256: str


class ApprovalScope(FrozenModel):
    repository_id: str
    base_commit_sha: str
    paths: tuple[str, ...]
    permitted_operations: tuple[Literal["patch_files", "run_tests", "open_draft_pr"], ...]
    expires_at: datetime


class ApprovalEvent(FrozenModel):
    event_id: UUID = Field(default_factory=uuid4)
    proposal_id: UUID
    proposal_version: int
    proposal_sha256: str
    actor_id: UUID
    actor_role: str
    decision: ProposalDecision
    scope: ApprovalScope | None = None
    reason: str | None = None
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanBundle(FrozenModel):
    graph: RepositoryAssetGraph
    candidates: tuple[PotentialVulnerabilityRow, ...]
    findings: tuple[DetectedVulnerabilityRow, ...] = ()
    planning: PlanningProposal | None = None
    optimization: OptimizationResult | None = None


class FindingReverification(FrozenModel):
    original_finding_id: UUID
    original_snapshot_id: UUID
    new_snapshot_id: UUID
    fingerprint: str
    result: Literal["resolved_in_patch", "still_present", "regressed", "not_verifiable"]
    new_finding_id: UUID | None = None
    evidence_refs: tuple[str, ...]
    explanation: str


class PostRemediationAssessment(FrozenModel):
    before_snapshot_id: UUID
    after_snapshot_id: UUID
    comparisons: tuple[FindingReverification, ...]
    graph_changed: bool
    coverage_warnings: tuple[str, ...]
    deployed_resolved: bool = False
