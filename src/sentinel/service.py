import re
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from uuid import uuid4

from sentinel.compiler.invalidation import AnalysisCache
from sentinel.compiler.planner import (
    compile_request,
    default_requests,
    specialize_remaining,
)
from sentinel.config import Limits, state_directory
from sentinel.extract.python_ast import FileFacts
from sentinel.graph.builder import build_graph, extract_files
from sentinel.ingest.repository import ingest
from sentinel.models.base import stable_id
from sentinel.models.evidence import Evidence
from sentinel.models.graph import Node
from sentinel.models.investigation import InvestigationQuestion, InvestigationRequest
from sentinel.reasoning.backward import backward_expand, suggest_outcomes
from sentinel.reasoning.counterfactual import simulate_compromise
from sentinel.reasoning.shared_dependencies import rank_shared_conditions
from sentinel.reporting.findings import attach_agent_findings, finding_attack_graph, finding_scenario
from sentinel.reporting.render import markdown_report, scenario_reports
from sentinel.reporting.serialize import read_json, write_json
from sentinel.runtime.executor import execute
from sentinel.runtime.policy import RunContext

ARTIFACTS = {
    "organization_graph",
    "attack_graph",
    "scenarios",
    "compiled_workflows",
    "verification_results",
    "counterfactuals",
    "shared_dependencies",
    "agent_trace",
    "incremental",
    "hypotheses",
    "findings",
    "source_analysis",
    "finding_attack_graphs",
    "syntax_index",
    "graph_proposals",
    "skills_manifest",
    "agent_run_manifest",
    "security_reviews",
    "outcome_mappings",
}


class SentinelService:
    def __init__(self, state_dir=None, allowed_root=None):
        self.state_dir = Path(state_dir or state_directory()).resolve()
        self.allowed_root = Path(allowed_root).resolve() if allowed_root else None
        self.cache = AnalysisCache(self.state_dir / "analysis.sqlite3")
        self.lock = RLock()

    def run_dir(self, run_id):
        if not re.fullmatch(r"[a-f0-9]{32}", run_id):
            raise ValueError("Invalid run ID")
        return self.state_dir / "runs" / run_id

    def get_run(self, run_id):
        return read_json(self.run_dir(run_id) / "run.json")

    def artifact(self, run_id, name):
        if name not in ARTIFACTS:
            raise ValueError("Unknown artifact")
        meta = self.get_run(run_id)
        return read_json(self.run_dir(run_id) / "revisions" / str(meta["revision"]) / (name + ".json"))

    def analyze(
        self,
        repo,
        outcome="unauthorized_refund",
        *,
        authorized=False,
        allow_mock=False,
        use_agents=True,
        analysis_targets=None,
    ):
        with self.lock:
            return self._analyze(
                repo,
                outcome,
                authorized,
                allow_mock,
                use_agents,
                analysis_targets=analysis_targets,
            )

    def _analyze(
        self,
        repo,
        outcome,
        authorized,
        allow_mock,
        use_agents,
        previous=None,
        changed_files=None,
        analysis_targets=None,
    ):
        snapshot = ingest(repo, authorized=authorized, allowed_root=self.allowed_root)
        run_id = previous["id"] if previous else uuid4().hex
        revision = previous["revision"] + 1 if previous else 1
        prior_hashes, previous_facts, before_graph, before_workflows = {}, {}, {}, []
        if previous:
            old_dir = self.run_dir(run_id) / "revisions" / str(previous["revision"])
            prior_hashes = read_json(old_dir / "hashes.json")
            previous_facts = {
                p: FileFacts.model_validate(f) for p, f in read_json(old_dir / "file_facts.json").items()
            }
            before_graph = read_json(old_dir / "organization_graph.json")
            before_workflows = read_json(old_dir / "compiled_workflows.json")
        changed = sorted(
            p
            for p in set(prior_hashes) | set(snapshot.hashes)
            if prior_hashes.get(p) != snapshot.hashes.get(p)
        )
        invalidated = self.cache.invalidate(snapshot.repository_id, changed) if previous else []
        facts, extracted = extract_files(snapshot, previous_facts, prior_hashes)
        graph = build_graph(snapshot, facts)
        limits = Limits()
        attack = backward_expand(outcome, graph, limits.max_depth, limits.max_paths)
        context = RunContext(snapshot, graph, attack, authorized=authorized, allow_mock=allow_mock)
        findings, source_coverage, graph_proposals = [], [], []
        requests = []
        agent_trace = [{"mode": "structure_only", "reason": "Semantic analysis was not requested"}]
        hypotheses, agent_state = [], None
        agent_manifest = {
            "mode": "structure_only",
            "provider": None,
            "model": None,
            "snapshot": snapshot.commit,
            "skills": [],
            "graph_proposal_count": 0,
            "finding_proposal_count": 0,
            "security_review_count": 0,
            "outcome_mapping_count": 0,
            "labels_available_to_agent": False,
            "source_executed": False,
        }
        if use_agents:
            from sentinel.agents.semantic import apply_graph_deltas, build_findings
            from sentinel.agents.supervisor import investigate

            outcome_result = (
                investigate(context)
                if analysis_targets is None
                else investigate(context, analysis_targets=analysis_targets)
            )
            if hasattr(outcome_result, "state"):
                request = outcome_result.request
                agent_trace = outcome_result.trace
                hypotheses = outcome_result.hypotheses
                agent_state = outcome_result.state
                agent_manifest = outcome_result.manifest
            else:
                # Compatibility for injected test/integration orchestrators using the original tuple.
                from sentinel.agents.context import AgentContext

                request, agent_trace, hypotheses = outcome_result
                agent_state = AgentContext(context)
                agent_manifest = {
                    **agent_manifest,
                    "mode": "agent_analysis",
                    "skills": [],
                }
            apply_graph_deltas(agent_state)
            graph_proposals = [proposal.model_dump() for proposal in agent_state.graph_deltas]
            attack = backward_expand(outcome, graph, limits.max_depth, limits.max_paths)
            context = RunContext(snapshot, graph, attack, authorized=authorized, allow_mock=allow_mock)
            findings = build_findings(agent_state)
            attach_agent_findings(context, findings, agent_state.source_evidence)
            source_coverage = [
                {
                    "analyzed_file": path,
                    "diagnostics": [],
                    "status": (
                        "agent_analysis_completed"
                        if path in agent_state.security_reviews
                        and agent_state.security_reviews[path].status in {"finding_proposed", "no_finding"}
                        else "inconclusive"
                    ),
                    "review_status": (
                        agent_state.security_reviews[path].status
                        if path in agent_state.security_reviews
                        else "not_reviewed"
                    ),
                    "review_rationale": (
                        agent_state.security_reviews[path].rationale
                        if path in agent_state.security_reviews
                        else "No dedicated security review was submitted"
                    ),
                    "review_evidence_ids": (
                        agent_state.security_reviews[path].evidence_ids
                        if path in agent_state.security_reviews
                        else []
                    ),
                    "counterevidence_ids": (
                        agent_state.security_reviews[path].counterevidence_ids
                        if path in agent_state.security_reviews
                        else []
                    ),
                    "supported_cwes": sorted({finding.cwe for finding in findings if finding.path == path}),
                    "limitations": ["Deep Agents static inference; runtime exploitability is unverified"],
                }
                for path in sorted(snapshot.files)
            ]
            requests = default_requests(context)
            if request.questions:
                requests.append(request)
        shared = rank_shared_conditions(attack.paths, attack.conditions, truncated=attack.bounds["truncated"])
        counterfactuals = []
        if use_agents:
            for component in sorted(
                {a for c in attack.conditions if c.id.endswith("_compromised") for a in c.asset_ids}
            ):
                counterfactuals.append(simulate_compromise(component, attack))
        if use_agents and allow_mock and outcome == "unauthorized_refund" and attack.applicable:
            requests.append(
                InvestigationRequest(
                    outcome_id=outcome,
                    questions=[
                        InvestigationQuestion(
                            hypothesis_id="synthetic_refund_comparison",
                            condition_id=attack.conditions[0].id,
                            analyzer="mock_verify",
                            fixture_id=fixture_id,
                            reason="Compare fixed synthetic authorization fixtures",
                        )
                        for fixture_id in ("refund_vulnerable", "refund_safeguarded")
                    ],
                )
            )
        workflow_records, verification, resolved = [], [], set()
        for request in requests:
            workflow = compile_request(request, context)
            results = execute(workflow, context, self.cache)
            # Only trusted deterministic evidence resolves conditions. Auth effectiveness stays unknown.
            for result in results:
                if result.kind == "inspect_agent_tools":
                    for item in result.data["declared_tools"]:
                        for condition in attack.conditions:
                            if (
                                condition.id == "condition:tool_callable"
                                and item["tool_id"] in condition.asset_ids
                                and item["status"] == "observed"
                            ):
                                condition.truth, condition.status = "true", "observed"
                                resolved.add(condition.id)
                if result.kind == "mock_verify":
                    result.data["evidence_id"] = stable_id(
                        "evidence", "fixture", result.data["fixture_id"], "v1"
                    )
                    verification.append(result.data)
            remaining = specialize_remaining(request, context, resolved)
            workflow_records.append(
                {
                    "workflow": workflow.model_dump(),
                    "results": [r.model_dump() for r in results],
                    "policy": "passed_at_compile_and_invocation",
                    "resolved_conditions": sorted(resolved),
                    "remaining_workflow": remaining.model_dump(),
                }
            )
        # Attach synthetic evidence with an explicit fixture scope; it cannot verify repository conditions.
        for result in verification:
            eid = result["evidence_id"]
            if any(e.id == eid for e in graph.evidence):
                continue
            graph.evidence.append(
                Evidence(
                    id=eid,
                    kind="mock_test",
                    path="fixture://" + result["fixture_id"],
                    start_line=1,
                    end_line=1,
                    commit="trusted-fixture:v1",
                    status="verified",
                    claim=result["status"],
                    scope="synthetic_fixture_only",
                )
            )
            nid = stable_id("evidence-node", eid)
            graph.nodes.append(
                Node(
                    id=nid,
                    type="EVIDENCE",
                    name=result["fixture_id"],
                    evidence_ids=[eid],
                    attributes={"status": result["status"], "scope": "synthetic_fixture_only"},
                )
            )
            result["evidence_id"] = eid
        reports = (
            scenario_reports(context, shared, verification)
            + [finding_scenario(f) for f in findings if f.dangerous_outcome]
            if use_agents
            else []
        )
        old_edges = {e["id"]: e for e in before_graph.get("edges", [])}
        new_edges = {e.id: e.model_dump() for e in graph.edges}
        reused = [r["task_id"] for w in workflow_records for r in w["results"] if r["cache_hit"]]
        incremental = {
            "changed_files": changed,
            "requested_changed_files": changed_files or [],
            "extracted_files": extracted,
            "invalidated_task_ids": invalidated,
            "reused_cached_task_ids": reused,
            "newly_executed_task_ids": [
                r["task_id"] for w in workflow_records for r in w["results"] if not r["cache_hit"]
            ],
            "added_edges": sorted(set(new_edges) - set(old_edges)),
            "removed_edges": sorted(set(old_edges) - set(new_edges)),
            "changed_edges": sorted(
                k
                for k in set(old_edges) & set(new_edges)
                if {a: b for a, b in old_edges[k].items() if a != "source_commit"}
                != {a: b for a, b in new_edges[k].items() if a != "source_commit"}
            ),
            "previous_workflow_ids": [w["workflow"]["id"] for w in before_workflows],
            "current_workflow_ids": [w["workflow"]["id"] for w in workflow_records],
        }
        revision_dir = self.run_dir(run_id) / "revisions" / str(revision)
        artifacts = {
            "organization_graph": graph.model_dump(),
            "attack_graph": attack.model_dump(),
            "scenarios": [r.model_dump() for r in reports],
            "compiled_workflows": workflow_records,
            "verification_results": verification,
            "counterfactuals": counterfactuals,
            "shared_dependencies": shared,
            "agent_trace": agent_trace,
            "incremental": incremental,
            "hypotheses": hypotheses,
            "hashes": snapshot.hashes,
            "file_facts": {p: f.model_dump() for p, f in facts.items()},
            "findings": [f.model_dump() for f in findings],
            "source_analysis": source_coverage,
            "finding_attack_graphs": [
                {"finding_id": f.id, "attack_graph": finding_attack_graph(f).model_dump()}
                for f in findings
                if f.dangerous_outcome
            ],
            "syntax_index": {p: f.model_dump() for p, f in facts.items()},
            "graph_proposals": graph_proposals,
            "skills_manifest": {"skills": agent_manifest["skills"], "source": "packaged_read_only"},
            "agent_run_manifest": agent_manifest,
            "security_reviews": (
                {path: review.model_dump() for path, review in agent_state.security_reviews.items()}
                if agent_state
                else {}
            ),
            "outcome_mappings": (
                {key: mapping.model_dump() for key, mapping in agent_state.outcome_mappings.items()}
                if agent_state
                else {}
            ),
        }
        for name, value in artifacts.items():
            write_json(revision_dir / (name + ".json"), value)
        (revision_dir / "report.md").write_text(markdown_report(reports), encoding="utf-8")
        meta = {
            "id": run_id,
            "revision": revision,
            "status": "completed",
            "repo": snapshot.source,
            "repository_id": snapshot.repository_id,
            "repository_commit": snapshot.commit,
            "outcome": outcome,
            "authorized": authorized,
            "allow_mock": allow_mock,
            "use_agents": use_agents,
            "analysis_mode": "agent_analysis" if use_agents else "structure_only",
            "analysis_targets": analysis_targets,
            "completed_at": datetime.now(UTC).isoformat(),
            "metrics": {
                "files": len(snapshot.files),
                "nodes": len(graph.nodes),
                "edges": len(graph.edges),
                "scenarios": len(reports),
                "static_findings": len(findings),
                "workflows": len(workflow_records),
                "cache_hits": len(reused),
                "tasks": sum(len(w["results"]) for w in workflow_records),
            },
            "suggested_outcomes": suggest_outcomes(graph),
            "warnings": snapshot.warnings + [warning for f in facts.values() for warning in f.warnings],
            "artifact_directory": str(revision_dir),
        }
        write_json(self.run_dir(run_id) / "run.json", meta)
        return meta

    def reanalyze(self, run_id, changed_files=None):
        with self.lock:
            previous = self.get_run(run_id)
            for path in changed_files or []:
                if Path(path).is_absolute() or ".." in Path(path).parts or "\\" in path or ":" in path:
                    raise ValueError("Changed files must be safe relative paths")
            return self._analyze(
                previous["repo"],
                previous["outcome"],
                previous["authorized"],
                previous["allow_mock"],
                previous["use_agents"],
                previous=previous,
                changed_files=changed_files,
                analysis_targets=previous.get("analysis_targets"),
            )
