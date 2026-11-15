from sentinel.contracts import SecurityReviewProposal, VerificationStatus
from sentinel.knowledge import curated_mvp_knowledge
from sentinel.module1 import ModuleOne
from sentinel.module2 import ModuleTwo


class FakeDeepRuntime:
    runtime_name = "langchain-deepagents-test-double"
    is_deepagents = True

    def __init__(self, invalid_evidence: bool = False) -> None:
        self.invalid_evidence = invalid_evidence

    def review_candidate(self, candidate, graph):
        evidence = "ev:missing" if self.invalid_evidence else candidate.observed_evidence_refs[0]
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

    def synthesize_plan(self, findings, graph):
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
