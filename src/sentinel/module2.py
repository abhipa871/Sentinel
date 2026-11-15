from __future__ import annotations

from collections.abc import Mapping
from uuid import UUID, uuid5

from sentinel.agents.runtime import SemanticRuntime
from sentinel.contracts import (
    DetectedVulnerabilityRow,
    EvidenceRef,
    PotentialVulnerabilityRow,
    RepositoryAssetGraph,
    SecurityReviewProposal,
    VerificationStatus,
)
from sentinel.phase0 import NAMESPACE
from sentinel.profiles import ScanProfile
from sentinel.secrets import redact_secrets
from sentinel.telemetry import parallel_map


class InvalidAgentProposal(ValueError):
    pass


# A positive verdict must point at specific lines, not a whole-file read.
MAX_CITED_SPAN_LINES = 60


def validate_security_review(
    proposal: SecurityReviewProposal,
    candidate: PotentialVulnerabilityRow,
    graph: RepositoryAssetGraph,
    extra_evidence: Mapping[str, EvidenceRef] | None = None,
) -> None:
    """`extra_evidence` holds hash-verified source spans read during reviews."""
    if proposal.candidate_id != candidate.candidate_id:
        raise InvalidAgentProposal("candidate binding mismatch")
    if proposal.primary_asset_id != candidate.asset_id:
        raise InvalidAgentProposal("primary asset is coordinator-bound")
    if proposal.vulnerability_id != candidate.vulnerability_id:
        raise InvalidAgentProposal("vulnerability ID mismatch")
    assets = {asset.asset_id for asset in graph.assets}
    records = {item.evidence_id: item for item in graph.evidence}
    records.update(extra_evidence or {})
    evidence = set(records)
    referenced = set(proposal.supporting_evidence_refs) | set(proposal.contradictory_evidence_refs)
    if not referenced <= evidence:
        raise InvalidAgentProposal("proposal references unknown evidence")
    if any(item.asset_id not in assets for item in proposal.related_nodes):
        raise InvalidAgentProposal("proposal references unknown asset")
    if proposal.status in {
        VerificationStatus.CONFIRMED,
        VerificationStatus.STRONGLY_SUPPORTED,
    }:
        if not proposal.supporting_evidence_refs:
            raise InvalidAgentProposal("positive verdict requires real evidence")
        if "evidence-review" not in proposal.specialist_reviews:
            raise InvalidAgentProposal("positive verdict requires independent evidence review")
        spans = [
            records[item]
            for item in proposal.supporting_evidence_refs
            if records[item].start_line is not None
        ]
        if not spans:
            # File inventory records only show that a file exists.
            raise InvalidAgentProposal("positive verdict requires line-level source evidence")
        if not any(
            span.source_path == candidate.node
            and (span.end_line or span.start_line or 0) - (span.start_line or 0)
            < MAX_CITED_SPAN_LINES
            for span in spans
        ):
            raise InvalidAgentProposal(
                "positive verdict requires a cited source span of at most "
                f"{MAX_CITED_SPAN_LINES} lines in the primary file {candidate.node}; whole-file "
                "reads and spans only in other files do not show the weakness there"
            )
    if (
        proposal.status is VerificationStatus.CONFIRMED
        and len(set(proposal.specialist_reviews)) < 2
    ):
        raise InvalidAgentProposal("confirmed verdict requires specialist and independent review")
    if proposal.status is VerificationStatus.REFUTED and not proposal.contradictory_evidence_refs:
        raise InvalidAgentProposal("refutation requires counterevidence")


def finding_id(graph: RepositoryAssetGraph, candidate: PotentialVulnerabilityRow) -> UUID:
    """A finding is one review of one candidate in one snapshot; its ID is stable across reruns
    so cached reviews and plans keep referring to the same findings."""
    return uuid5(NAMESPACE, f"finding:{graph.snapshot.snapshot_id}:{candidate.candidate_id}")


class ModuleTwo:
    def __init__(self, runtime: SemanticRuntime) -> None:
        if not runtime.is_deepagents:
            raise TypeError("Module II requires a LangChain Deep Agents semantic runtime")
        self.runtime = runtime
        self.cited_evidence: tuple[EvidenceRef, ...] = ()

    def run(
        self,
        candidates: tuple[PotentialVulnerabilityRow, ...],
        graph: RepositoryAssetGraph,
        *,
        profile: ScanProfile | None = None,
    ) -> tuple[DetectedVulnerabilityRow, ...]:
        by_id = {asset.asset_id: asset for asset in graph.assets}
        observed: Mapping[str, EvidenceRef] = getattr(self.runtime, "observed_evidence", {})

        def review(candidate: PotentialVulnerabilityRow) -> DetectedVulnerabilityRow:
            try:
                proposal = self.runtime.review_candidate(candidate, graph, profile=profile)
                validate_security_review(proposal, candidate, graph, observed)
                return DetectedVulnerabilityRow(
                    finding_id=finding_id(graph, candidate),
                    snapshot_id=graph.snapshot.snapshot_id,
                    candidate_id=candidate.candidate_id,
                    primary_asset_id=candidate.asset_id,
                    node=by_id[candidate.asset_id].path,
                    detected_vulnerability=(
                        f"{candidate.vulnerability_id}: {candidate.vulnerability_name}"
                    ),
                    verification_status=proposal.status,
                    criticality=proposal.criticality,
                    criticality_basis=proposal.criticality_basis,
                    related_nodes=proposal.related_nodes,
                    relationship_explanation=proposal.relationship_explanation,
                    source_sink_evidence_refs=proposal.supporting_evidence_refs,
                    contradictory_evidence_refs=proposal.contradictory_evidence_refs,
                    assumptions=proposal.assumptions,
                    analyst_summary=proposal.analyst_summary,
                )
            except Exception as exc:
                return DetectedVulnerabilityRow(
                    finding_id=finding_id(graph, candidate),
                    snapshot_id=graph.snapshot.snapshot_id,
                    candidate_id=candidate.candidate_id,
                    primary_asset_id=candidate.asset_id,
                    node=candidate.node,
                    detected_vulnerability=(
                        f"{candidate.vulnerability_id}: {candidate.vulnerability_name}"
                    ),
                    verification_status=VerificationStatus.NOT_ANALYZED,
                    criticality="unknown",
                    criticality_basis="Agent transaction failed closed",
                    related_nodes=(),
                    relationship_explanation="No semantic relationship accepted",
                    source_sink_evidence_refs=(),
                    contradictory_evidence_refs=(),
                    assumptions=(
                        f"provider_failure:{type(exc).__name__}",
                        f"failure_detail:{redact_secrets(str(exc), limit=500)}",
                    ),
                    analyst_summary="No verdict was accepted because the typed review failed.",
                )

        # Reviews are isolated transactions; run them concurrently and keep candidate order.
        workers = profile.review_concurrency if profile else 1
        findings = tuple(parallel_map(review, candidates, workers))
        known = {item.evidence_id for item in graph.evidence}
        cited = dict.fromkeys(
            reference
            for finding in findings
            for reference in (
                *finding.source_sink_evidence_refs,
                *finding.contradictory_evidence_refs,
            )
            if reference not in known and reference in observed
        )
        # Source spans cited by accepted findings; the pipeline adds them to the graph evidence.
        self.cited_evidence = tuple(observed[reference] for reference in cited)
        return findings
