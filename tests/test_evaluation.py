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


def test_challenge_coverage_matches_service_and_official_owasp_links():
    from pathlib import Path

    from sentinel.evaluation import ChallengeTruth, load_challenge_truth, score_challenge_coverage
    from sentinel.knowledge_graph import KnowledgeGraphIndex, load_predefined_graph

    index = KnowledgeGraphIndex(load_predefined_graph())
    truth = (
        ChallengeTruth("bola", "BOLA", "services/identity/", ("OWASP-API:API1:2023",)),
        ChallengeTruth("nosql", "NoSQL", "services/community/", ("CWE-943",)),
        ChallengeTruth("any", "Unauthenticated", None, ("CWE-306",)),
    )
    rows = [
        # CWE-639 is officially referenced by API1:2023, so it covers the BOLA challenge.
        ("services/identity/src/VehicleController.java", "CWE-639"),
        # Right weakness, wrong service: does not count.
        ("services/workshop/crapi/shop/views.py", "CWE-943"),
    ]
    score = score_challenge_coverage(rows, truth, index)
    assert set(score.covered) == {"bola"}
    assert score.missed == ("nosql", "any")
    assert score.recall == 1 / 3
    packaged = load_challenge_truth(Path("benchmarks/crapi/challenges.json"))
    assert len(packaged) == 18
    assert all(index.entity(item) for challenge in packaged for item in challenge.expected_ids)


def test_scoring_keeps_entity_ids_that_contain_colons(sample_graph):
    finding = _finding(sample_graph).model_copy(
        update={"detected_vulnerability": "OWASP-API:API1:2023: Broken Object Level Authorization"}
    )
    truth = (GroundTruth("A", "OWASP-API:API1:2023", finding.node, True),)
    assert score_findings((finding,), truth).true_positives == 1
