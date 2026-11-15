from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Literal
from uuid import UUID

from z3 import Bool, If, Implies, IntVal, Not, Optimize, Or, Sum, is_true, sat

from sentinel.agents.runtime import SemanticRuntime
from sentinel.contracts import (
    DetectedVulnerabilityRow,
    OptimizationResult,
    PlanningProposal,
    ProposalDecision,
    RepositoryAssetGraph,
    VerificationStatus,
)


class InvalidPlanningProposal(ValueError):
    pass


def validate_planning_proposal(
    planning: PlanningProposal,
    findings: tuple[DetectedVulnerabilityRow, ...],
    graph: RepositoryAssetGraph,
) -> None:
    eligible = {
        finding.finding_id
        for finding in findings
        if finding.verification_status
        in {VerificationStatus.CONFIRMED, VerificationStatus.STRONGLY_SUPPORTED}
    }
    assets = {asset.asset_id: asset for asset in graph.assets}
    evidence = {item.evidence_id for item in graph.evidence}
    path_ids = {path.path_id for path in planning.attack_paths}
    if len(path_ids) != len(planning.attack_paths):
        raise InvalidPlanningProposal("attack path IDs must be unique")
    for path in planning.attack_paths:
        if not set(path.finding_ids) <= eligible:
            raise InvalidPlanningProposal("attack path includes an ineligible finding")
        if not set(path.asset_ids) <= set(assets):
            raise InvalidPlanningProposal("attack path includes an unknown asset")
        if not set(path.prerequisite_evidence_refs) <= evidence:
            raise InvalidPlanningProposal("attack path includes unknown evidence")
    proposal_ids = {item.proposal_id for item in planning.remediations}
    if len(proposal_ids) != len(planning.remediations):
        raise InvalidPlanningProposal("proposal IDs must be unique")
    known_paths = {asset.path for asset in graph.assets}
    for proposal in planning.remediations:
        if not set(proposal.finding_ids) <= eligible:
            raise InvalidPlanningProposal("remediation includes an ineligible finding")
        if not set(proposal.affected_asset_ids) <= set(assets):
            raise InvalidPlanningProposal("remediation includes an unknown asset")
        if not set(proposal.allowed_paths) <= known_paths:
            raise InvalidPlanningProposal("remediation allowlist includes an unknown path")
        if not set(proposal.expected_path_ids_blocked) <= path_ids:
            raise InvalidPlanningProposal("remediation references an unknown attack path")
        if not set(proposal.evidence_refs) <= evidence:
            raise InvalidPlanningProposal("remediation references unknown evidence")
        if not set(proposal.conflicts_with) <= proposal_ids:
            raise InvalidPlanningProposal("remediation conflict references unknown proposal")
        if not set(proposal.depends_on) <= proposal_ids:
            raise InvalidPlanningProposal("remediation dependency references unknown proposal")
    for control in planning.governance:
        if not set(control.risk_or_finding_ids) <= eligible:
            raise InvalidPlanningProposal("governance control includes an ineligible finding")
        if not set(control.affected_asset_ids) <= set(assets):
            raise InvalidPlanningProposal("governance control includes an unknown asset")


def _objective(terms: list[Any]) -> Any:
    # z3.Sum([]) returns the Python int 0, which Optimize.minimize rejects.
    return Sum(terms) if terms else IntVal(0)


class RemediationOptimizer:
    def optimize(
        self,
        planning: PlanningProposal,
        *,
        decisions: Mapping[UUID, ProposalDecision] | None = None,
        timeout_ms: int = 60_000,
    ) -> OptimizationResult:
        decisions = decisions or {}
        payload = {
            "planning": planning.model_dump(mode="json"),
            "decisions": {str(key): value.value for key, value in decisions.items()},
            "timeout_ms": timeout_ms,
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        opt = Optimize()
        opt.set(priority="lex")
        opt.set(timeout=timeout_ms)
        actions = {
            proposal.proposal_id: Bool(f"action_{proposal.proposal_id.hex}")
            for proposal in planning.remediations
        }
        exposed = {
            path.path_id: Bool(f"path_{hashlib.sha256(path.path_id.encode()).hexdigest()[:16]}")
            for path in planning.attack_paths
        }
        proposals = {proposal.proposal_id: proposal for proposal in planning.remediations}

        for path in planning.attack_paths:
            blockers = [
                actions[proposal.proposal_id]
                for proposal in planning.remediations
                if path.path_id in proposal.expected_path_ids_blocked
            ]
            # All blockers are predicted planning assumptions. A post-patch run is required before
            # any blocker can be relabeled observed.
            opt.add(exposed[path.path_id] == (Not(Or(*blockers)) if blockers else True))
        for proposal in planning.remediations:
            variable = actions[proposal.proposal_id]
            for required in proposal.depends_on:
                opt.add(Implies(variable, actions[required]))
            for conflict in proposal.conflicts_with:
                opt.add(Or(Not(variable), Not(actions[conflict])))
            decision = decisions.get(proposal.proposal_id, proposal.human_decision)
            if decision is ProposalDecision.ACCEPT:
                opt.add(variable)
            elif decision in {ProposalDecision.REJECT, ProposalDecision.DEFER}:
                opt.add(Not(variable))

        residual = _objective(
            [If(exposed[path.path_id], path.impact_weight, 0) for path in planning.attack_paths]
        )
        cost = _objective(
            [If(actions[item.proposal_id], item.cost_points, 0) for item in planning.remediations]
        )
        disruption = _objective(
            [
                If(actions[item.proposal_id], item.disruption_points, 0)
                for item in planning.remediations
            ]
        )
        opt.minimize(residual)
        opt.minimize(cost)
        opt.minimize(disruption)
        result = opt.check()
        if result != sat:
            status: Literal["unsat", "unknown", "timeout"] = (
                "unknown" if str(result) == "unknown" else "unsat"
            )
            reason = (
                opt.reason_unknown()
                if status == "unknown"
                else "human decisions or constraints conflict"
            )
            if status == "unknown" and "timeout" in reason.lower():
                status = "timeout"
            return OptimizationResult(
                solver_status=status,
                selected_proposal_ids=(),
                exposed_path_ids=tuple(path.path_id for path in planning.attack_paths),
                residual_exposure=sum(path.impact_weight for path in planning.attack_paths),
                total_cost=0,
                total_disruption=0,
                explanation=reason,
                input_sha256=digest,
            )
        model = opt.model()
        selected = tuple(
            proposal_id
            for proposal_id, variable in actions.items()
            if is_true(model.eval(variable, model_completion=True))
        )
        exposed_ids = tuple(
            path_id
            for path_id, variable in exposed.items()
            if is_true(model.eval(variable, model_completion=True))
        )
        return OptimizationResult(
            solver_status="sat",
            selected_proposal_ids=selected,
            exposed_path_ids=exposed_ids,
            residual_exposure=sum(
                path.impact_weight for path in planning.attack_paths if path.path_id in exposed_ids
            ),
            total_cost=sum(proposals[item].cost_points for item in selected),
            total_disruption=sum(proposals[item].disruption_points for item in selected),
            explanation=(
                "Lexicographic optimum over predicted blockers: residual exposure, then cost, "
                "then disruption. Re-verification is required."
            ),
            input_sha256=digest,
        )


class ModuleThree:
    def __init__(self, runtime: SemanticRuntime) -> None:
        if not runtime.is_deepagents:
            raise TypeError("Module III requires a LangChain Deep Agents semantic runtime")
        self.runtime = runtime
        self.optimizer = RemediationOptimizer()

    def run(
        self,
        findings: tuple[DetectedVulnerabilityRow, ...],
        graph: RepositoryAssetGraph,
        *,
        decisions: Mapping[UUID, ProposalDecision] | None = None,
    ) -> tuple[PlanningProposal, OptimizationResult]:
        eligible = [
            finding
            for finding in findings
            if finding.verification_status
            in {VerificationStatus.CONFIRMED, VerificationStatus.STRONGLY_SUPPORTED}
        ]
        if not eligible:
            # Nothing is eligible for planning, so no agent transaction runs and no proposal,
            # path, or control is created. This is an empty bundle, not a semantic claim.
            planning = PlanningProposal(
                attack_paths=(),
                remediations=(),
                governance=(),
                review_summary=(
                    "Module III planning was not run: no finding reached confirmed or "
                    "strongly_supported status in Module II."
                ),
                assumptions=(),
            )
            return planning, self.optimizer.optimize(planning, decisions=decisions)
        planning = self.runtime.synthesize_plan(findings, graph)
        validate_planning_proposal(planning, findings, graph)
        return planning, self.optimizer.optimize(planning, decisions=decisions)
