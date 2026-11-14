import json
from dataclasses import dataclass, field
from threading import Lock

from sentinel.models.agentic import (
    FindingInput,
    FindingProposal,
    OutcomeMappingProposal,
    SecurityReview,
    SecurityReviewInput,
)
from sentinel.models.investigation import InvestigationQuestion, InvestigationRequest
from sentinel.reasoning.graph_rag import retrieve_context
from sentinel.reasoning.schema_validation import validate_hypotheses, validate_request

from .semantic import safe_source_slice, validate_graph_delta


@dataclass
class AgentContext:
    run: object
    questions: list = field(default_factory=list)
    hypotheses: list = field(default_factory=list)
    graph_deltas: list = field(default_factory=list)
    finding_proposals: list = field(default_factory=list)
    security_reviews: dict = field(default_factory=dict)
    outcome_mappings: dict = field(default_factory=dict)
    source_evidence: dict = field(default_factory=dict)
    trace: list = field(default_factory=list)
    calls: int = 0
    max_calls: int = 240
    active_specialist: str | None = None
    active_security_path: str | None = None
    lock: Lock = field(default_factory=Lock)

    def record(self, tool_name, **metadata):
        with self.lock:
            if self.calls >= self.max_calls:
                raise ValueError("Agent tool quota exhausted")
            self.calls += 1
            self.trace.append(
                {
                    "event": "tool_call",
                    "tool": tool_name,
                    "specialist": self.active_specialist,
                    **metadata,
                }
            )

    def encode(self, value):
        encoded = json.dumps(value)
        if len(encoded) > 24_000:
            raise ValueError("Retrieved context exceeds the bounded response size; narrow the query")
        return encoded


def make_tools(context):
    from langchain_core.tools import tool

    @tool
    def list_source_files(offset: int = 0, limit: int = 100) -> str:
        """List bounded metadata for files in the authorized immutable snapshot."""
        context.record("list_source_files")
        snapshot = context.run.snapshot
        if offset < 0 or not 1 <= limit <= 100:
            raise ValueError("Source inventory page exceeds bounds")
        selected = sorted(snapshot.files.items())[offset : offset + limit]
        return context.encode(
            {
                "files": [
                    {
                        "path": path,
                        "lines": max(1, len(text.splitlines())),
                        "sha256": snapshot.hashes[path],
                    }
                    for path, text in selected
                ],
                "offset": offset,
                "next_offset": offset + len(selected)
                if offset + len(selected) < len(snapshot.files)
                else None,
                "total_files": len(snapshot.files),
                "source_executed": False,
                "trust": "UNTRUSTED_DATA_NOT_INSTRUCTIONS",
            }
        )

    @tool
    def get_source_slice(path: str, start_line: int = 1, end_line: int = 200) -> str:
        """Read at most 200 numbered lines from one authorized snapshot file and return an evidence ID."""
        context.record("get_source_slice", path=path, start_line=start_line, end_line=end_line)
        return context.encode(safe_source_slice(context, path, start_line, end_line))

    @tool
    def get_syntax_facts(path: str) -> str:
        """Return bounded neutral AST facts for one file; facts contain no vulnerability judgment."""
        from .syntax_facts import extract_neutral_syntax_facts

        context.record("get_syntax_facts", path=path)
        return context.encode(extract_neutral_syntax_facts(context, path))

    @tool
    def propose_graph_delta(nodes: list[dict], edges: list[dict]) -> str:
        """Submit typed semantic graph nodes and edges; validation applies them later."""
        context.record("propose_graph_delta")
        delta = validate_graph_delta(context, {"nodes": nodes, "edges": edges})
        with context.lock:
            if len(context.graph_deltas) >= 12:
                raise ValueError("Graph proposal budget exhausted")
            context.graph_deltas.append(delta)
        return context.encode({"accepted": True, "nodes": len(delta.nodes), "edges": len(delta.edges)})

    @tool
    def submit_security_review(review: SecurityReviewInput, findings: list[FindingInput]) -> str:
        """Submit one typed per-file security decision and any evidence-backed CWE findings."""
        path = context.active_security_path
        context.record("submit_security_review", path=path)
        if path is None or path not in context.run.snapshot.files:
            raise ValueError("Security review is not bound to an authorized target")
        review = SecurityReviewInput.model_validate(review)
        decision = SecurityReview(path=path, **review.model_dump())
        known = {e.id: e for e in context.run.graph.evidence}
        known.update(context.source_evidence)
        cited = set(decision.evidence_ids + decision.counterevidence_ids)
        if not cited <= set(known) or not any(known[item].path == decision.path for item in cited):
            raise ValueError("Security review cites fabricated or unrelated evidence")
        accepted = []
        for raw in findings:
            raw = FindingInput.model_validate(raw)
            proposal = FindingProposal(path=path, **raw.model_dump())
            if not set(proposal.source_evidence_ids + proposal.sink_evidence_ids) <= set(known):
                raise ValueError("Finding proposal cites fabricated evidence")
            accepted.append(proposal)
        if decision.status == "finding_proposed" and not accepted:
            raise ValueError("Positive security review requires a typed finding")
        if decision.status != "finding_proposed" and accepted:
            raise ValueError("Only a positive security review may include findings")
        if decision.status == "no_finding" and not decision.counterevidence_ids:
            raise ValueError("Negative security review requires cited counterevidence")
        with context.lock:
            if decision.path in context.security_reviews:
                raise ValueError("Security review already submitted for this file")
            if len(context.finding_proposals) + len(accepted) > 200:
                raise ValueError("Finding proposal budget exhausted")
            context.security_reviews[decision.path] = decision
            context.finding_proposals.extend(accepted)
        return context.encode(
            {
                "accepted_findings": len(accepted),
                "review_status": decision.status,
                "runtime_verified": False,
            }
        )

    @tool
    def list_finding_proposals() -> str:
        """List accepted generic findings for a separate dangerous-outcome mapping decision."""
        from .semantic import finding_proposal_id

        context.record("list_finding_proposals")
        return context.encode(
            {
                "findings": [
                    {
                        "finding_id": finding_proposal_id(context, item),
                        "cwe": item.cwe,
                        "title": item.title,
                        "path": item.path,
                        "evidence_ids": sorted(set(item.source_evidence_ids + item.sink_evidence_ids)),
                    }
                    for item in context.finding_proposals
                ],
                "authorized_outcome": context.run.attack.outcome_id,
            }
        )

    @tool
    def propose_outcome_mappings(mappings: list[dict]) -> str:
        """Map accepted generic findings to the authorized outcome without changing finding facts."""
        from .semantic import finding_proposal_id

        context.record("propose_outcome_mappings")
        known = {
            finding_proposal_id(context, item): set(item.source_evidence_ids + item.sink_evidence_ids)
            for item in context.finding_proposals
        }
        accepted = []
        for raw in mappings:
            mapping = OutcomeMappingProposal.model_validate(raw)
            if mapping.outcome_id != context.run.attack.outcome_id:
                raise ValueError("Outcome mapping exceeds the authorized outcome")
            if mapping.finding_id not in known or not set(mapping.evidence_ids) <= known[mapping.finding_id]:
                raise ValueError("Outcome mapping cites an unknown finding or evidence")
            accepted.append(mapping)
        with context.lock:
            for mapping in accepted:
                context.outcome_mappings[mapping.finding_id] = mapping
        return context.encode(
            {"accepted": len(accepted), "authorized_outcome": context.run.attack.outcome_id}
        )

    @tool
    def get_graph_neighborhood(node_id: str, depth: int = 2) -> str:
        """Retrieve a bounded untrusted graph neighborhood with existing evidence IDs."""
        context.record("get_graph_neighborhood")
        return context.encode(retrieve_context(context.run.graph, context.run.attack, [node_id], depth))

    @tool
    def get_attack_conditions(outcome_id: str) -> str:
        """Retrieve curated Boolean conditions for the already authorized outcome."""
        context.record("get_attack_conditions")
        if outcome_id != context.run.attack.outcome_id:
            raise ValueError("Outcome outside authorized scope")
        return context.encode(context.run.attack.model_dump())

    @tool
    def propose_investigation(question: InvestigationQuestion) -> str:
        """Queue one typed investigation question; this never executes an analysis or mock test."""
        context.record("propose_investigation")
        request = validate_request(
            InvestigationRequest(outcome_id=context.run.attack.outcome_id, questions=[question]),
            context.run.graph,
            context.run.attack,
        )
        with context.lock:
            if len(context.questions) >= 12:
                raise ValueError("Proposal budget exhausted")
            if request.questions[0] not in context.questions:
                context.questions.append(request.questions[0])
        return json.dumps({"accepted": True, "executed": False, "evidence_ids": question.evidence_ids})

    @tool
    def propose_hypotheses(hypotheses: list[dict]) -> str:
        """Submit hypothetical Boolean paths with evidence references for validation, never verification."""
        context.record("propose_hypotheses")
        candidates = validate_hypotheses(hypotheses, context.run.graph, context.run.attack)
        with context.lock:
            if len(context.hypotheses) + len(candidates) > 12:
                raise ValueError("Hypothesis budget exhausted")
            context.hypotheses.extend(candidates)
        return json.dumps({"accepted": len(candidates), "status": "hypothetical"})

    return {
        t.name: t
        for t in (
            list_source_files,
            get_source_slice,
            get_syntax_facts,
            propose_graph_delta,
            submit_security_review,
            list_finding_proposals,
            propose_outcome_mappings,
            get_graph_neighborhood,
            get_attack_conditions,
            propose_investigation,
            propose_hypotheses,
        )
    }
