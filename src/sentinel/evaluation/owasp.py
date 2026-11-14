import csv
import re
from collections import defaultdict
from pathlib import Path, PurePosixPath


def load_labels(path):
    rows = []
    seen = set()
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.reader(line for line in handle if line.strip() and not line.lstrip().startswith("#")):
            if (
                len(row) != 4
                or not re.fullmatch(r"BenchmarkTest\d{5}", row[0])
                or row[2] not in {"true", "false"}
                or not row[3].isdigit()
            ):
                raise ValueError("Invalid OWASP ground-truth row")
            if row[0] in seen:
                raise ValueError("Duplicate benchmark case")
            seen.add(row[0])
            rows.append(
                {
                    "case_id": row[0],
                    "category": row[1],
                    "vulnerable": row[2] == "true",
                    "cwe": "CWE-" + row[3],
                }
            )
    if not rows:
        raise ValueError("No benchmark labels")
    return rows


def metrics(rows):
    tp = sum(r["expected_vulnerable"] and r["predicted_vulnerable"] for r in rows)
    fp = sum(not r["expected_vulnerable"] and r["predicted_vulnerable"] for r in rows)
    fn = sum(r["expected_vulnerable"] and not r["predicted_vulnerable"] for r in rows)
    tn = sum(not r["expected_vulnerable"] and not r["predicted_vulnerable"] for r in rows)
    return {
        "cases": len(rows),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "recall": tp / (tp + fn) if tp + fn else None,
        "precision": tp / (tp + fp) if tp + fp else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "abstentions": sum(r["abstained"] for r in rows),
    }


def score(labels, predictions):
    """Exact case/CWE matching. Abstentions count as nondetections, never proof of safety."""
    ids = {r["case_id"] for r in labels}
    if set(predictions) != ids:
        raise ValueError("Prediction coverage must exactly match the ground-truth case IDs")
    details = []
    for label in labels:
        prediction = predictions[label["case_id"]]
        predicted = label["cwe"] in prediction["reported_cwes"]
        details.append(
            {
                **label,
                "expected_vulnerable": label["vulnerable"],
                "predicted_vulnerable": predicted,
                "abstained": prediction["abstained"],
                "reported_cwes": prediction["reported_cwes"],
                "reason": prediction["reason"],
                "outcome": ("TP" if predicted else "FN")
                if label["vulnerable"]
                else ("FP" if predicted else "TN"),
            }
        )
    groups = defaultdict(list)
    for row in details:
        groups[(row["category"], row["cwe"])].append(row)
    return {
        "overall": metrics(details),
        "by_category": [
            {"category": category, "cwe": cwe, **metrics(rows)}
            for (category, cwe), rows in sorted(groups.items())
        ],
        "cases": details,
        "false_negatives": [r for r in details if r["outcome"] == "FN"],
        "false_positives": [r for r in details if r["outcome"] == "FP"],
        "extra_cwe_predictions": sum(len(set(r["reported_cwes"]) - {r["cwe"]}) for r in details),
        "scoring_policy": "Exact testcase/CWE detections. Abstentions count as nondetections; precision is null with no positive predictions.",
        "interpretation": "Bounded static candidate detection on a public regression suite, not runtime verification or standalone model accuracy.",
    }


def native_predictions(case_ids, reports, findings=None, coverage=None):
    """Match only typed, evidence-backed static findings; never promote hypotheses."""
    from sentinel.models.finding import StaticFinding

    if any(
        r.get("status") not in {"hypothetical", "refuted_within_model", "static_supported"} for r in reports
    ):
        raise ValueError("Report schema changed; review the native prediction adapter before scoring")
    ids = set(case_ids)
    covered = {}
    for item in coverage or []:
        case = PurePosixPath(item["analyzed_file"]).stem
        if case in ids:
            covered[case] = item
    predictions = {
        case: {
            "reported_cwes": [],
            "finding_ids": [],
            "evidence_ids": [],
            "abstained": case not in covered or covered[case].get("status") != "agent_analysis_completed",
            "reason": (
                "No supported CWE finding after a completed Deep Agents review; this is not proof of safety"
                if case in covered and covered[case].get("status") == "agent_analysis_completed"
                else "Dedicated Deep Agents security review was missing or inconclusive"
            ),
        }
        for case in sorted(ids)
    }
    for raw in findings or []:
        finding = StaticFinding.model_validate(raw)
        cases = {PurePosixPath(location.path).stem for location in finding.trace} & ids
        for case in cases:
            prediction = predictions[case]
            prediction["reported_cwes"] = sorted(set(prediction["reported_cwes"]) | {finding.cwe})
            prediction["finding_ids"] = sorted(set(prediction["finding_ids"]) | {finding.id})
            prediction["evidence_ids"] = sorted(set(prediction["evidence_ids"]) | set(finding.evidence_ids))
            prediction["abstained"] = False
            prediction["reason"] = (
                "Evidence-backed static candidate; runtime exploitability remains unverified"
            )
    return predictions
