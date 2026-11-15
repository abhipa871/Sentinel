"""Score a SENTINEL scan bundle against a documented-challenge benchmark (e.g. crAPI).

Usage: python scripts/score_challenge_coverage.py artifacts/crapi-full.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel.evaluation import load_challenge_truth, score_challenge_coverage
from sentinel.knowledge_graph import KnowledgeGraphIndex, load_predefined_graph

POSITIVE = {"confirmed", "strongly_supported"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="scan bundle JSON written by `sentinel scan`")
    parser.add_argument("--truth", type=Path, default=Path("benchmarks/crapi/challenges.json"))
    parser.add_argument("--json", action="store_true", help="emit machine-readable output")
    args = parser.parse_args()

    bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    truth = load_challenge_truth(args.truth)
    index = KnowledgeGraphIndex(load_predefined_graph())
    findings = bundle.get("findings", [])
    levels = {
        "module1_candidates": [
            (row["node"], row["vulnerability_id"]) for row in bundle.get("candidates", [])
        ],
        "module2_reviewed": [
            (row["node"], row["detected_vulnerability"].split(": ", 1)[0])
            for row in findings
            if row["verification_status"] != "not_analyzed"
        ],
        "module2_positive": [
            (row["node"], row["detected_vulnerability"].split(": ", 1)[0])
            for row in findings
            if row["verification_status"] in POSITIVE
        ],
    }
    report = {}
    for level, rows in levels.items():
        score = score_challenge_coverage(rows, truth, index)
        report[level] = {
            "rows": len(rows),
            "covered": len(score.covered),
            "total": len(truth),
            "recall": round(score.recall, 3),
            "covered_challenges": {
                key: [list(item) for item in value] for key, value in score.covered.items()
            },
            "missed_challenges": list(score.missed),
        }
    if args.json:
        print(json.dumps(report, indent=2))
        return
    titles = {item.challenge_id: item.title for item in truth}
    for level, result in report.items():
        print(
            f"{level}: {result['covered']}/{result['total']} challenges "
            f"(recall {result['recall']:.0%}) from {result['rows']} rows"
        )
        for challenge_id, matches in result["covered_challenges"].items():
            shown = ", ".join(
                f"{vid} @ {path.removeprefix('services/')}" for path, vid in matches[:2]
            )
            print(f"   + {challenge_id} {titles[challenge_id]}: {shown}")
        print(f"   - missed: {', '.join(result['missed_challenges']) or 'none'}")


if __name__ == "__main__":
    main()
