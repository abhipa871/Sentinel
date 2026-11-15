from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _javascript_value(path: Path, declaration: str):
    raw = path.read_text(encoding="utf-8").strip()
    prefix = f"const {declaration} = "
    assert raw.startswith(prefix)
    return json.loads(raw.removeprefix(prefix).removesuffix(";"))


def test_website_findings_are_exactly_the_24_high_evidence_results():
    displayed = _javascript_value(ROOT / "website/assets-data.js", "assetFindings")

    assert len(displayed) == 24
    assert len({row["id"] for row in displayed}) == 24
    assert {row["status"] for row in displayed} == {"strongly_supported"}
    artifact = ROOT / "artifacts/crapi-full-v7.json"
    if artifact.exists():
        bundle = json.loads(artifact.read_text(encoding="utf-8"))
        expected = {
            finding["candidate_id"]
            for finding in bundle["findings"]
            if finding["verification_status"] == "strongly_supported"
        }
        assert {row["id"] for row in displayed} == expected


def test_module_one_table_uses_the_same_complete_scan_bundle():
    raw = (ROOT / "website/module1-data.js").read_text(encoding="utf-8").strip()
    summary_raw, rows_raw = raw.split(";\nconst moduleOneRows = ", maxsplit=1)
    summary = json.loads(summary_raw.removeprefix("const scanSummary = "))
    rows = json.loads(rows_raw.removesuffix(";"))

    assert summary["source_artifact"] == "crapi-full-v7.json"
    assert summary["module_one_candidates"] == 58
    assert summary["high_evidence_findings"] == 24
    assert len(rows) == 58
    assert sum(row["high_evidence"] for row in rows) == 24
    artifact = ROOT / "artifacts/crapi-full-v7.json"
    if artifact.exists():
        bundle = json.loads(artifact.read_text(encoding="utf-8"))
        assert summary["snapshot_id"] == bundle["graph"]["snapshot"]["snapshot_id"]
        assert {row["id"] for row in rows} == {
            candidate["candidate_id"] for candidate in bundle["candidates"]
        }


def test_website_includes_both_requested_graph_datasets():
    raw = (ROOT / "website/graphs-data.js").read_text(encoding="utf-8").strip()
    repo_raw, vuln_raw = raw.split(";\nconst vulnGraph = ", maxsplit=1)
    repo = json.loads(repo_raw.removeprefix("const repoGraph = "))
    vulnerability = json.loads(vuln_raw.removesuffix(";"))

    assert repo
    assert all(data["nodes"] and data["edges"] for data in repo.values())
    repo_edge_types = {edge["type"] for data in repo.values() for edge in data["edges"]}
    assert repo_edge_types > {"IMPORTS", "ROUTES_TO"}
    assert {"CALLS_IN", "DEPENDS_ON_MANIFEST", "READS"} <= repo_edge_types
    assert vulnerability["nodes"]
    assert vulnerability["edges"]
    assert {node["role"] for node in vulnerability["nodes"]} >= {
        "finding",
        "parent",
        "owasp",
        "attack",
    }


def test_website_uses_plain_language_for_its_primary_navigation():
    html = (ROOT / "website/index.html").read_text(encoding="utf-8")

    for label in (
        "Issues",
        "Review queue",
        "Code map",
        "Attack paths",
        "Security review queue",
        "High-confidence security issues",
        "Application area",
        "Vulnerability knowledge graph",
        "CWE weakness detected in this scan",
        "CAPEC attack pattern",
        "REFERENCES_WEAKNESS",
        "EXPLOITS_WEAKNESS",
    ):
        assert label in html

    for implementation_label in (
        ">Module I table<",
        ">Repo graph<",
        ">Vulnerability graph<",
        "Module II disposition",
    ):
        assert implementation_label not in html
