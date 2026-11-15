from __future__ import annotations

from sentinel.agents.runtime import SemanticRuntime
from sentinel.contracts import (
    DetectedVulnerabilityRow,
    PotentialVulnerabilityRow,
    RepositoryAssetGraph,
    SecurityReviewProposal,
    VerificationStatus,
)
from sentinel.secrets import redact_secrets


class InvalidAgentProposal(ValueError):
    pass


def validate_security_review(
    proposal: SecurityReviewProposal,
    candidate: PotentialVulnerabilityRow,
    graph: RepositoryAssetGraph,
) -> None:
    if proposal.candidate_id != candidate.candidate_id:
        raise InvalidAgentProposal("candidate binding mismatch")
    if proposal.primary_asset_id != candidate.asset_id:
        raise InvalidAgentProposal("primary asset is coordinator-bound")
    if proposal.vulnerability_id != candidate.vulnerability_id:
        raise InvalidAgentProposal("vulnerability ID mismatch")
    assets = {asset.asset_id for asset in graph.assets}
    evidence = {item.evidence_id for item in graph.evidence}
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
    if (
        proposal.status is VerificationStatus.CONFIRMED
        and len(set(proposal.specialist_reviews)) < 2
    ):
        raise InvalidAgentProposal("confirmed verdict requires specialist and independent review")
    if proposal.status is VerificationStatus.REFUTED and not proposal.contradictory_evidence_refs:
        raise InvalidAgentProposal("refutation requires counterevidence")


class ModuleTwo:
    def __init__(self, runtime: SemanticRuntime) -> None:
        if not runtime.is_deepagents:
            raise TypeError("Module II requires a LangChain Deep Agents semantic runtime")
        self.runtime = runtime

    def run(
        self,
        candidates: tuple[PotentialVulnerabilityRow, ...],
        graph: RepositoryAssetGraph,
    ) -> tuple[DetectedVulnerabilityRow, ...]:
        by_id = {asset.asset_id: asset for asset in graph.assets}
        findings: list[DetectedVulnerabilityRow] = []
        for candidate in candidates:
            try:
                proposal = self.runtime.review_candidate(candidate, graph)
                validate_security_review(proposal, candidate, graph)
                findings.append(
                    DetectedVulnerabilityRow(
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
                )
            except Exception as exc:
                findings.append(
                    DetectedVulnerabilityRow(
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
                )
        return tuple(findings)
