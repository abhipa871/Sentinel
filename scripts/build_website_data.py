"""Build the immutable website datasets from one completed SENTINEL scan bundle."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

HIGH_EVIDENCE_STATUS = "strongly_supported"


def _asset_metadata(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {asset["asset_id"]: asset for asset in bundle["graph"]["assets"]}


def _finding_rows(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = {row["candidate_id"]: row for row in bundle["candidates"]}
    assets = _asset_metadata(bundle)
    rows: list[dict[str, Any]] = []
    for finding in bundle["findings"]:
        if finding["verification_status"] != HIGH_EVIDENCE_STATUS:
            continue
        candidate = candidates[finding["candidate_id"]]
        asset = assets[candidate["asset_id"]]
        agent_graph = asset.get("features", {}).get("agent_graph", {})
        rows.append(
            {
                "path": candidate["node"],
                "language": asset.get("language") or "asset",
                "role": agent_graph.get("file_role") or asset["node_type"].lower(),
                "id": candidate["candidate_id"],
                "finding_id": finding["finding_id"],
                "cwe": candidate["vulnerability_id"],
                "name": candidate["vulnerability_name"],
                "hypothesis": candidate["hypothesis"],
                "status": finding["verification_status"],
                "summary": finding["analyst_summary"],
                "preconditions": candidate["untested_preconditions"],
                "priority": candidate["investigation_priority"],
                "evidence_count": len(finding["source_sink_evidence_refs"]),
                "criticality": finding["criticality"],
            }
        )
    return sorted(rows, key=lambda row: (-row["priority"], row["path"], row["cwe"]))


def _module_one_rows(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    findings = {row["candidate_id"]: row for row in bundle["findings"]}
    assets = _asset_metadata(bundle)
    rows: list[dict[str, Any]] = []
    for candidate in bundle["candidates"]:
        asset = assets[candidate["asset_id"]]
        finding = findings.get(candidate["candidate_id"])
        agent_graph = asset.get("features", {}).get("agent_graph", {})
        rows.append(
            {
                "id": candidate["candidate_id"],
                "path": candidate["node"],
                "service": (
                    candidate["node"].split("/")[1]
                    if candidate["node"].startswith("services/")
                    else "Repository"
                ),
                "language": asset.get("language") or "asset",
                "role": agent_graph.get("file_role") or asset["node_type"].lower(),
                "cwe": candidate["vulnerability_id"],
                "name": candidate["vulnerability_name"],
                "hypothesis": candidate["hypothesis"],
                "priority": candidate["investigation_priority"],
                "candidate_status": candidate["candidate_status"],
                "verification_status": (
                    finding["verification_status"] if finding else "not_analyzed"
                ),
                "high_evidence": bool(
                    finding and finding["verification_status"] == HIGH_EVIDENCE_STATUS
                ),
                "observed_evidence_count": len(candidate["observed_evidence_refs"]),
                "source_sink_evidence_count": (
                    len(finding["source_sink_evidence_refs"]) if finding else 0
                ),
                "preconditions": candidate["untested_preconditions"],
                "coverage_warnings": candidate["coverage_warnings"],
                "summary": finding["analyst_summary"] if finding else "Not reviewed by Module II.",
            }
        )
    return sorted(rows, key=lambda row: (-row["priority"], row["path"], row["cwe"]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--assets", type=Path, default=Path("website/assets-data.js"))
    parser.add_argument("--module-one", type=Path, default=Path("website/module1-data.js"))
    parser.add_argument("--expected-high-evidence", type=int, default=24)
    args = parser.parse_args()

    bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    finding_rows = _finding_rows(bundle)
    module_rows = _module_one_rows(bundle)
    if len(finding_rows) != args.expected_high_evidence:
        raise SystemExit(
            f"expected {args.expected_high_evidence} high-evidence findings, "
            f"found {len(finding_rows)}"
        )

    status_counts = Counter(row["verification_status"] for row in module_rows)
    summary = {
        "source_artifact": args.bundle.name,
        "snapshot_id": bundle["graph"]["snapshot"]["snapshot_id"],
        "commit_sha": bundle["graph"]["snapshot"]["commit_sha"],
        "module_one_candidates": len(module_rows),
        "high_evidence_findings": len(finding_rows),
        "repository_assets": len(bundle["graph"]["assets"]),
        "repository_edges": len(bundle["graph"]["edges"]),
        "verification_statuses": dict(sorted(status_counts.items())),
    }
    args.assets.write_text(
        "const assetFindings = "
        + json.dumps(finding_rows, sort_keys=True, separators=(",", ":"))
        + ";\n",
        encoding="utf-8",
    )
    args.module_one.write_text(
        "const scanSummary = "
        + json.dumps(summary, sort_keys=True, separators=(",", ":"))
        + ";\nconst moduleOneRows = "
        + json.dumps(module_rows, sort_keys=True, separators=(",", ":"))
        + ";\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
