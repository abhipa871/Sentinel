from __future__ import annotations

import hashlib
from typing import Literal

from sentinel.contracts import (
    DetectedVulnerabilityRow,
    FindingReverification,
    PostRemediationAssessment,
    RepositoryAssetGraph,
    VerificationStatus,
)


def finding_fingerprint(finding: DetectedVulnerabilityRow) -> str:
    weakness = finding.detected_vulnerability.split(":", 1)[0]
    material = f"{finding.node}:{weakness}"
    return hashlib.sha256(material.encode()).hexdigest()


def assess_post_remediation(
    before_graph: RepositoryAssetGraph,
    after_graph: RepositoryAssetGraph,
    original_findings: tuple[DetectedVulnerabilityRow, ...],
    rerun_findings: tuple[DetectedVulnerabilityRow, ...],
) -> PostRemediationAssessment:
    """Compare two independent Module II runs without declaring deployed resolution."""

    rerun = {finding_fingerprint(item): item for item in rerun_findings}
    comparisons: list[FindingReverification] = []
    for original in original_findings:
        fingerprint = finding_fingerprint(original)
        current = rerun.get(fingerprint)
        result: Literal["resolved_in_patch", "still_present", "regressed", "not_verifiable"]
        if current is None:
            result = "not_verifiable"
            evidence: tuple[str, ...] = ()
            explanation = "The new Module II run produced no matching, reviewable hypothesis."
            new_id = None
        elif current.verification_status is VerificationStatus.REFUTED:
            result = "resolved_in_patch"
            evidence = current.contradictory_evidence_refs
            explanation = "The post-patch Deep Agents review refuted the original hypothesis."
            new_id = current.finding_id
        elif current.verification_status in {
            VerificationStatus.CONFIRMED,
            VerificationStatus.STRONGLY_SUPPORTED,
        }:
            result = "still_present"
            evidence = current.source_sink_evidence_refs
            explanation = (
                "The post-patch Deep Agents review still supports the original hypothesis."
            )
            new_id = current.finding_id
        else:
            result = "not_verifiable"
            evidence = current.source_sink_evidence_refs + current.contradictory_evidence_refs
            explanation = "The post-patch Deep Agents review was inconclusive or not analyzed."
            new_id = current.finding_id
        comparisons.append(
            FindingReverification(
                original_finding_id=original.finding_id,
                original_snapshot_id=before_graph.snapshot.snapshot_id,
                new_snapshot_id=after_graph.snapshot.snapshot_id,
                fingerprint=fingerprint,
                result=result,
                new_finding_id=new_id,
                evidence_refs=evidence,
                explanation=explanation,
            )
        )
    return PostRemediationAssessment(
        before_snapshot_id=before_graph.snapshot.snapshot_id,
        after_snapshot_id=after_graph.snapshot.snapshot_id,
        comparisons=tuple(comparisons),
        graph_changed=before_graph.digest != after_graph.digest,
        coverage_warnings=after_graph.snapshot.warnings,
        deployed_resolved=False,
    )
