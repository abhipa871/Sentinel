from uuid import uuid4

from sentinel.contracts import (
    AttackPath,
    DetectedVulnerabilityRow,
    GovernanceProposal,
    PlanningProposal,
    ProposalDecision,
    RemediationProposal,
    VerificationStatus,
)
from sentinel.module3 import RemediationOptimizer, validate_planning_proposal


def _finding(graph):
    asset = next(item for item in graph.assets if item.path == "services/loader.py")
    evidence = asset.evidence_refs[0]
    return DetectedVulnerabilityRow(
        snapshot_id=graph.snapshot.snapshot_id,
        candidate_id="candidate:test",
        primary_asset_id=asset.asset_id,
        node=asset.path,
        detected_vulnerability="CWE-502: Deserialization of Untrusted Data",
        verification_status=VerificationStatus.CONFIRMED,
        criticality="high",
        criticality_basis="test",
        related_nodes=(),
        relationship_explanation="isolated fixture",
        source_sink_evidence_refs=(evidence,),
        contradictory_evidence_refs=(),
        assumptions=(),
        analyst_summary="fixture",
    )


def _plan(graph):
    finding = _finding(graph)
    asset = next(item for item in graph.assets if item.path == finding.node)
    evidence = asset.evidence_refs[0]
    path = AttackPath(
        path_id="path-1",
        finding_ids=(finding.finding_id,),
        asset_ids=(asset.asset_id,),
        edge_refs=(),
        prerequisites=("untrusted input reaches loader",),
        prerequisite_evidence_refs=(evidence,),
        exposure_status="supported",
        impact_weight=7,
    )
    shared = RemediationProposal(
        snapshot_id=graph.snapshot.snapshot_id,
        finding_ids=(finding.finding_id,),
        affected_asset_ids=(asset.asset_id,),
        allowed_paths=(asset.path,),
        title="Replace unsafe deserialization",
        problem_summary="Unsafe loader accepted untrusted data.",
        proposed_change_natural_language="Use a safe typed format and reject serialized objects.",
        detailed_technical_spec="Replace pickle.loads with a strict JSON schema decoder.",
        alternatives=("Restrict input to a trusted signed channel.",),
        security_invariant="Untrusted bytes cannot instantiate objects.",
        mitigation_mechanism="safe parser",
        expected_path_ids_blocked=("path-1",),
        prerequisites=(),
        planned_tests=("reject serialized object fixture",),
        cost_points=3,
        disruption_points=2,
        rollback_plan="Revert branch patch.",
        risk_reduction_assumptions=("all calls use this loader",),
        evidence_refs=(evidence,),
    )
    local = shared.model_copy(
        update={
            "proposal_id": uuid4(),
            "title": "Disable upload route",
            "cost_points": 6,
            "disruption_points": 8,
        }
    )
    governance = GovernanceProposal(
        title="Require deserialization security review",
        risk_or_finding_ids=(finding.finding_id,),
        framework_refs=("NIST SSDF PW.7",),
        policy_text_natural_language="Changes to object parsing require security review.",
        concrete_enforcement=("CODEOWNERS review and regression test",),
        affected_asset_ids=(asset.asset_id,),
        role_assignment_status="needs_confirmation",
        evidence_of_operation=("required CI check",),
        exception_process="Document and time-bound exceptions.",
        implementation_type="CI_control",
        approval_authority_role="GovernanceApprover",
    )
    return finding, PlanningProposal(
        attack_paths=(path,),
        remediations=(shared, local),
        governance=(governance,),
        review_summary="Independent review found both alternatives bounded.",
        assumptions=("predicted blockers require post-patch verification",),
    )


def test_optimizer_prefers_lower_cost_supported_blocker(sample_graph):
    finding, planning = _plan(sample_graph)
    validate_planning_proposal(planning, (finding,), sample_graph)
    result = RemediationOptimizer().optimize(planning)
    assert result.solver_status == "sat"
    assert result.selected_proposal_ids == (planning.remediations[0].proposal_id,)
    assert result.exposed_path_ids == ()


def test_rejection_constrains_optimizer(sample_graph):
    _, planning = _plan(sample_graph)
    result = RemediationOptimizer().optimize(
        planning,
        decisions={planning.remediations[0].proposal_id: ProposalDecision.REJECT},
    )
    assert planning.remediations[0].proposal_id not in result.selected_proposal_ids
    assert planning.remediations[1].proposal_id in result.selected_proposal_ids
