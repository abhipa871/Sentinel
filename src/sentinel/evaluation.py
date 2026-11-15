from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from sentinel.contracts import DetectedVulnerabilityRow, VerificationStatus
from sentinel.knowledge_graph import KnowledgeGraphIndex


@dataclass(frozen=True)
class GroundTruth:
    case_id: str
    weakness_id: str
    primary_asset_path: str
    vulnerable: bool


@dataclass(frozen=True)
class Scorecard:
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    abstentions: int
    precision: float
    recall: float
    f1: float


def score_findings(
    findings: tuple[DetectedVulnerabilityRow, ...],
    truth: tuple[GroundTruth, ...],
) -> Scorecard:
    # detected_vulnerability is "<entity_id>: <name>"; entity IDs may themselves contain ":"
    # (ATLAS:AML.T0051, OWASP-API:API1:2023), so split on the ": " separator.
    predictions = {
        (row.node, row.detected_vulnerability.split(": ", 1)[0]): row.verification_status
        for row in findings
    }
    tp = fp = fn = tn = abstain = 0
    positive = {VerificationStatus.CONFIRMED, VerificationStatus.STRONGLY_SUPPORTED}
    for item in truth:
        status = predictions.get((item.primary_asset_path, item.weakness_id))
        if status is None or status in {
            VerificationStatus.INCONCLUSIVE,
            VerificationStatus.NOT_ANALYZED,
        }:
            abstain += 1
            if item.vulnerable:
                fn += 1
            continue
        predicted = status in positive
        if item.vulnerable and predicted:
            tp += 1
        elif item.vulnerable:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return Scorecard(tp, fp, fn, tn, abstain, precision, recall, f1)


@dataclass(frozen=True)
class ChallengeTruth:
    challenge_id: str
    title: str
    service_prefix: str | None
    expected_ids: tuple[str, ...]


@dataclass(frozen=True)
class ChallengeCoverage:
    covered: dict[str, tuple[tuple[str, str], ...]]
    missed: tuple[str, ...]
    recall: float


def load_challenge_truth(path: Path) -> tuple[ChallengeTruth, ...]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return tuple(
        ChallengeTruth(
            challenge_id=item["challenge_id"],
            title=item["title"],
            service_prefix=item["service_prefix"],
            expected_ids=tuple(item["expected_ids"]),
        )
        for item in data["challenges"]
    )


def _related_ids(vulnerability_id: str, index: KnowledgeGraphIndex) -> set[str]:
    """The ID itself plus the OWASP API risks it is officially linked to, in either direction."""
    related = {vulnerability_id}
    related.update(risk.entity_id for risk in index.owasp_api_risks(vulnerability_id))
    related.update(
        relation.target_id
        for relation in index.outgoing.get(vulnerability_id, [])
        if relation.relation_type == "REFERENCES_WEAKNESS"
    )
    return related


def score_challenge_coverage(
    rows: Iterable[tuple[str, str]],
    truth: tuple[ChallengeTruth, ...],
    index: KnowledgeGraphIndex,
) -> ChallengeCoverage:
    """Category-level recall: rows are (asset path, vulnerability ID) pairs.

    A challenge is covered when a row lies under its service prefix and the row's ID equals, or is
    REFERENCES_WEAKNESS-linked to, an expected ID. This is coarser than endpoint-level matching
    and is meant for comparing runs, not for claiming a vulnerability was found.
    """
    materialized = [(path, vulnerability_id) for path, vulnerability_id in rows]
    covered: dict[str, tuple[tuple[str, str], ...]] = {}
    for challenge in truth:
        expected = set(challenge.expected_ids)
        matches = tuple(
            sorted(
                {
                    (path, vulnerability_id)
                    for path, vulnerability_id in materialized
                    if (
                        challenge.service_prefix is None
                        or path.startswith(challenge.service_prefix)
                    )
                    and _related_ids(vulnerability_id, index) & expected
                }
            )
        )
        if matches:
            covered[challenge.challenge_id] = matches
    missed = tuple(item.challenge_id for item in truth if item.challenge_id not in covered)
    return ChallengeCoverage(covered, missed, len(covered) / len(truth) if truth else 0.0)
