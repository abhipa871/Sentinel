"""Build website/assets-data.js from a saved SENTINEL scan bundle.

Usage: python scripts/build_website_data.py artifacts/crapi-full-v7.json

The website replays saved results only. Every verdict, summary, cited source span, and fix shown
there is copied from the bundle unchanged; nothing is relabeled.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from sentinel.evaluation import load_challenge_truth, score_challenge_coverage
from sentinel.knowledge_graph import KnowledgeGraphIndex, load_predefined_graph

POSITIVE = {"confirmed", "strongly_supported"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--output", type=Path, default=Path("website/assets-data.js"))
    parser.add_argument("--truth", type=Path, default=Path("benchmarks/crapi/challenges.json"))
    args = parser.parse_args()

    bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    graph = bundle["graph"]
    assets = {asset["asset_id"]: asset for asset in graph["assets"]}
    evidence = {item["evidence_id"]: item for item in graph["evidence"]}
    findings = {item["candidate_id"]: item for item in bundle.get("findings", [])}
    planning = bundle.get("planning") or {"remediations": [], "attack_paths": [], "governance": []}
    selected = set((bundle.get("optimization") or {}).get("selected_proposal_ids", []))
    fixes_by_finding: dict[str, list[dict[str, object]]] = {}
    for proposal in planning["remediations"]:
        fix = {
            "title": proposal["title"],
            "change": proposal["proposed_change_natural_language"],
            "tests": proposal["planned_tests"],
            "rollback": proposal["rollback_plan"],
            "selected": proposal["proposal_id"] in selected,
        }
        for finding_id in proposal["finding_ids"]:
            fixes_by_finding.setdefault(finding_id, []).append(fix)

    rows = []
    for candidate in bundle["candidates"]:
        asset = assets[candidate["asset_id"]]
        finding = findings.get(candidate["candidate_id"])
        agent = asset["features"].get("agent_graph", {})
        spans = []
        for reference in (finding or {}).get("source_sink_evidence_refs", []):
            record = evidence.get(reference)
            if record and record.get("start_line"):
                spans.append(
                    {
                        "path": record["source_path"],
                        "start": record["start_line"],
                        "end": record["end_line"] or record["start_line"],
                    }
                )
        rows.append(
            {
                "path": candidate["node"],
                "language": asset.get("language") or "unknown",
                "role": agent.get("file_role") or asset["features"].get("file_role", "file"),
                "id": candidate["candidate_id"],
                "cwe": candidate["vulnerability_id"],
                "name": candidate["vulnerability_name"],
                "hypothesis": candidate["hypothesis"],
                "priority": candidate["investigation_priority"],
                "owasp": [
                    risk["raw_id"]
                    for risk in candidate.get("knowledge_context", {}).get("owasp_api_risks", [])
                ],
                "preconditions": candidate["untested_preconditions"],
                "status": finding["verification_status"] if finding else "not_reviewed",
                "criticality": finding["criticality"] if finding else "unknown",
                "summary": finding["analyst_summary"] if finding else "",
                "assumptions": [
                    item
                    for item in (finding or {}).get("assumptions", [])
                    if not item.startswith(("provider_failure:", "failure_detail:"))
                ],
                "spans": spans,
                "fixes": fixes_by_finding.get((finding or {}).get("finding_id", ""), []),
            }
        )

    index = KnowledgeGraphIndex(load_predefined_graph())
    truth = load_challenge_truth(args.truth)
    reviewed = [(row["path"], row["cwe"]) for row in rows]
    positive = [(row["path"], row["cwe"]) for row in rows if row["status"] in POSITIVE]
    metrics = bundle.get("run_metrics", [])
    summary = {
        "repository": "OWASP crAPI",
        "commit": graph["snapshot"]["commit_sha"],
        "profile": bundle.get("scan_profile"),
        "files": len(graph["assets"]),
        "graph_edges": len(graph["edges"]),
        "candidates": len(rows),
        "statuses": dict(Counter(row["status"] for row in rows)),
        "benchmark_total": len(truth),
        "benchmark_candidates": len(score_challenge_coverage(reviewed, truth, index).covered),
        "benchmark_positive": len(score_challenge_coverage(positive, truth, index).covered),
        "attack_paths": len(planning["attack_paths"]),
        "fixes": len(planning["remediations"]),
        "governance": len(planning["governance"]),
        "input_tokens": sum(item["input_tokens"] for item in metrics),
        "stage_seconds": round(sum(item["duration_seconds"] for item in metrics)),
        "coverage": dict(Counter(item["status"] for item in bundle.get("module1_coverage", []))),
    }
    args.output.write_text(
        "const scanSummary = "
        + json.dumps(summary, sort_keys=True)
        + ";\nconst assetFindings = "
        + json.dumps(rows, ensure_ascii=False)
        + ";\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
