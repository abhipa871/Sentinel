from sentinel.contracts import VerificationStatus
from sentinel.remediation import assess_post_remediation
from tests.test_module3 import _finding


def test_post_remediation_requires_new_module_two_result(sample_graph):
    original = _finding(sample_graph)
    refuted = original.model_copy(
        update={
            "verification_status": VerificationStatus.REFUTED,
            "source_sink_evidence_refs": (),
            "contradictory_evidence_refs": (original.source_sink_evidence_refs[0],),
        }
    )
    assessment = assess_post_remediation(
        sample_graph,
        sample_graph,
        (original,),
        (refuted,),
    )
    assert assessment.comparisons[0].result == "resolved_in_patch"
    assert not assessment.deployed_resolved
