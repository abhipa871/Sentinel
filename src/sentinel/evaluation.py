from __future__ import annotations

from dataclasses import dataclass

from sentinel.contracts import DetectedVulnerabilityRow, VerificationStatus


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
    predictions = {
        (row.node, row.detected_vulnerability.split(":", 1)[0]): row.verification_status
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
