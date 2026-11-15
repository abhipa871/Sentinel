from sentinel.contracts import SecurityReviewProposal, VerificationStatus
from sentinel.knowledge import curated_mvp_knowledge
from sentinel.module1 import ModuleOne
from sentinel.module2 import ModuleTwo


class FakeDeepRuntime:
    runtime_name = "langchain-deepagents-test-double"
    is_deepagents = True

    def __init__(self, invalid_evidence: bool = False) -> None:
        self.invalid_evidence = invalid_evidence
        self.observed_evidence: dict = {}

    def review_candidate(self, candidate, graph, **_):
        from sentinel.agents.runtime import EvidenceToolbox

        # A narrow, hash-verified span in the candidate's own file, as a real review would cite.
        toolbox = EvidenceToolbox(graph, mint_span_evidence=True)
        toolbox.read_source_span(candidate.node, 1, 3)
        span = next(iter(toolbox.span_evidence.values()))
        self.observed_evidence[span.evidence_id] = span
        evidence = "ev:missing" if self.invalid_evidence else span.evidence_id
        return SecurityReviewProposal(
            candidate_id=candidate.candidate_id,
            primary_asset_id=candidate.asset_id,
            vulnerability_id=candidate.vulnerability_id,
            status=VerificationStatus.CONFIRMED,
            supporting_evidence_refs=(evidence,),
            contradictory_evidence_refs=(),
            related_nodes=candidate.related_nodes[:1],
            criticality="high",
            criticality_basis="Application-specific agent assessment",
            relationship_explanation="The linked file supplies an evidenced static import corridor.",
            assumptions=("runtime deployment remains unknown",),
            analyst_summary="Typed test-double review for contract testing.",
            specialist_reviews=("code-analysis", "evidence-review"),
        )

    def synthesize_plan(self, findings, graph, **_):
        raise NotImplementedError


def test_valid_agent_review_becomes_finding(sample_graph):
    candidate = next(
        row
        for row in ModuleOne().run(sample_graph, curated_mvp_knowledge())
        if row.vulnerability_id == "CWE-502"
    )
    findings = ModuleTwo(FakeDeepRuntime()).run((candidate,), sample_graph)
    assert findings[0].verification_status is VerificationStatus.CONFIRMED
    assert findings[0].source_sink_evidence_refs


def test_unknown_evidence_fails_closed(sample_graph):
    candidate = ModuleOne().run(sample_graph, curated_mvp_knowledge())[0]
    findings = ModuleTwo(FakeDeepRuntime(invalid_evidence=True)).run((candidate,), sample_graph)
    assert findings[0].verification_status is VerificationStatus.NOT_ANALYZED
    assert findings[0].source_sink_evidence_refs == ()


def test_non_deep_runtime_is_rejected():
    class WrongRuntime:
        is_deepagents = False

    try:
        ModuleTwo(WrongRuntime())
    except TypeError as exc:
        assert "Deep Agents" in str(exc)
    else:
        raise AssertionError("non-DeepAgents runtime was accepted")


def test_positive_verdict_requires_line_level_source_evidence(sample_graph):
    candidate = ModuleOne().run(sample_graph, curated_mvp_knowledge())[0]

    class InventoryOnly(FakeDeepRuntime):
        def review_candidate(self, candidate, graph, **_):
            proposal = super().review_candidate(candidate, graph)
            return proposal.model_copy(
                update={"supporting_evidence_refs": candidate.observed_evidence_refs[:1]}
            )

    findings = ModuleTwo(InventoryOnly()).run((candidate,), sample_graph)
    assert findings[0].verification_status is VerificationStatus.NOT_ANALYZED
    assert any("line-level source evidence" in item for item in findings[0].assumptions)


def test_source_spans_read_in_review_become_citable_evidence(sample_graph):
    from sentinel.agents.runtime import EvidenceToolbox

    plain = EvidenceToolbox(sample_graph).read_source_span("services/loader.py", 1, 3)
    assert "evidence_ref" not in plain
    toolbox = EvidenceToolbox(sample_graph, mint_span_evidence=True)
    first = toolbox.read_source_span("services/loader.py", 1, 3)
    again = toolbox.read_source_span("services/loader.py", 1, 3)
    other = toolbox.read_source_span("services/loader.py", 2, 3)
    assert first["evidence_ref"] == again["evidence_ref"] == "S000001"
    assert other["evidence_ref"] == "S000002"
    evidence_id = toolbox.resolve_evidence_reference("S000001")
    record = toolbox.span_evidence[evidence_id]
    assert (record.source_path, record.start_line, record.end_line) == ("services/loader.py", 1, 3)
    assert record.assertion_origin == "observed"
    assert toolbox.read_evidence("S000001")["start_line"] == 1


def test_cited_spans_validate_and_are_published_with_findings(sample_graph):
    from sentinel.agents.runtime import EvidenceToolbox

    candidate = ModuleOne().run(sample_graph, curated_mvp_knowledge())[0]
    toolbox = EvidenceToolbox(sample_graph, mint_span_evidence=True)
    toolbox.read_source_span(candidate.node, 1, 3)
    span = next(iter(toolbox.span_evidence.values()))

    class SpanRuntime(FakeDeepRuntime):
        def __init__(self) -> None:
            super().__init__()
            self.observed_evidence = {span.evidence_id: span}

        def review_candidate(self, candidate, graph, **_):
            proposal = super().review_candidate(candidate, graph)
            return proposal.model_copy(update={"supporting_evidence_refs": (span.evidence_id,)})

    module_two = ModuleTwo(SpanRuntime())
    findings = module_two.run((candidate,), sample_graph)
    assert findings[0].verification_status is VerificationStatus.CONFIRMED
    assert module_two.cited_evidence == (span,)


def test_positive_verdict_needs_a_narrow_span_in_the_primary_file(sample_graph):
    from sentinel.agents.runtime import EvidenceToolbox
    from sentinel.module2 import InvalidAgentProposal, validate_security_review

    candidate = next(
        row
        for row in ModuleOne().run(sample_graph, curated_mvp_knowledge())
        if row.node == "services/loader.py"
    )
    toolbox = EvidenceToolbox(sample_graph, mint_span_evidence=True)
    toolbox.read_source_span("api/routes.py", 1, 3)
    elsewhere = next(iter(toolbox.span_evidence.values()))
    proposal = FakeDeepRuntime().review_candidate(candidate, sample_graph)
    other_file = proposal.model_copy(update={"supporting_evidence_refs": (elsewhere.evidence_id,)})
    try:
        validate_security_review(
            other_file, candidate, sample_graph, {elsewhere.evidence_id: elsewhere}
        )
    except InvalidAgentProposal as exc:
        assert "in the primary file services/loader.py" in str(exc)
    else:
        raise AssertionError("a span only in another file must not support a positive verdict")
    whole_file = elsewhere.model_copy(
        update={"source_path": "services/loader.py", "start_line": 1, "end_line": 400}
    )
    try:
        validate_security_review(
            other_file, candidate, sample_graph, {elsewhere.evidence_id: whole_file}
        )
    except InvalidAgentProposal as exc:
        assert "at most 60 lines" in str(exc)
    else:
        raise AssertionError("a whole-file read must not support a positive verdict")
