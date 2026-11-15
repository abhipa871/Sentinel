from sentinel.contracts import DetectedVulnerabilityRow, VerificationStatus
from sentinel.evaluation import GroundTruth, score_findings
from tests.test_module3 import _finding


def test_scorecard_counts_abstentions_as_false_negatives(sample_graph):
    positive = _finding(sample_graph)
    abstention = DetectedVulnerabilityRow(
        **{
            **positive.model_dump(),
            "finding_id": positive.finding_id,
            "candidate_id": "candidate:2",
            "node": "api/routes.py",
            "verification_status": VerificationStatus.INCONCLUSIVE,
        }
    )
    truth = (
        GroundTruth("A", "CWE-502", positive.node, True),
        GroundTruth("B", "CWE-862", "api/routes.py", True),
    )
    score = score_findings((positive, abstention), truth)
    assert score.true_positives == 1
    assert score.false_negatives == 1
    assert score.abstentions == 1
    assert score.recall == 0.5
