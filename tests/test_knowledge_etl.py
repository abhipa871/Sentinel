import hashlib
import json
from datetime import UTC, datetime

import pytest

from sentinel.knowledge_etl import CatalogArtifact, KnowledgeEtl, graph_digest
from sentinel.knowledge_graph import (
    KnowledgeGraphIndex,
    dump_predefined_graph,
    load_predefined_graph,
)
from sentinel.knowledge_overlay import extend_with_targeted_cves


def _artifact(catalog, content, version="test-v1"):
    raw = content.encode()
    return CatalogArtifact(
        catalog=catalog,
        version=version,
        source_url=f"https://example.invalid/{catalog}",
        content=raw,
        retrieved_at=datetime.now(UTC),
        expected_sha256=hashlib.sha256(raw).hexdigest(),
    )


def _owasp_risk(rank, name, cwes, *, links=None):
    labels = "".join(f"* [CWE-{cwe}: Weakness {cwe}][{i}]\n" for i, cwe in enumerate(cwes, 1))
    targets = cwes if links is None else links
    defs = "".join(
        f"[{i}]: https://cwe.mitre.org/data/definitions/{cwe}.html\n"
        for i, cwe in enumerate(targets, 1)
    )
    return (
        f"# API{rank}:2023 {name}\n\n"
        "| Threat agents/Attack vectors | Security Weakness | Impacts |\n"
        "| API Specific : Exploitability **Easy** | Prevalence **Common** : Detectability "
        "**Average** | Technical **Severe** : Business Specific |\n\n"
        f"## Is the API Vulnerable?\n\nRisk {rank} applies when\nchecks are missing.\n\n"
        "## How To Prevent\n\nDo the right thing.\n\n"
        f"## References\n\n### External\n\n{labels}\n{defs}"
    )


def _owasp_bundle(overrides=None):
    files = {
        f"0xa{rank:x}-risk-{rank}.md": _owasp_risk(rank, f"Risk {rank}", [100 + rank])
        for rank in range(1, 11)
    }
    files.update(overrides or {})
    return _artifact(
        "owasp_api",
        json.dumps({"commit": "0" * 40, "files": files}, sort_keys=True),
        version="2023",
    )


def test_cwe_and_capec_relations_preserve_direction():
    cwe = _artifact(
        "cwe",
        """
        <Weakness_Catalog>
          <Weaknesses>
            <Weakness ID="89" Name="SQL Injection" />
          </Weaknesses>
        </Weakness_Catalog>
        """,
    )
    capec = _artifact(
        "capec",
        """
        <Attack_Pattern_Catalog>
          <Attack_Patterns>
            <Attack_Pattern ID="66" Name="SQL Injection">
              <Related_Weaknesses><Related_Weakness CWE_ID="89"/></Related_Weaknesses>
            </Attack_Pattern>
          </Attack_Patterns>
        </Attack_Pattern_Catalog>
        """,
    )
    snapshot = KnowledgeEtl().promote((cwe, capec))
    assert any(
        relation.source_id == "CAPEC-66"
        and relation.relation_type == "EXPLOITS_WEAKNESS"
        and relation.target_id == "CWE-89"
        for relation in snapshot.relations
    )


def test_catalog_checksum_mismatch_fails_closed():
    artifact = CatalogArtifact(
        catalog="cwe",
        version="bad",
        source_url="https://example.invalid/cwe",
        content=b"<root/>",
        retrieved_at=datetime.now(UTC),
        expected_sha256="0" * 64,
    )
    with pytest.raises(ValueError, match="checksum"):
        KnowledgeEtl().promote((artifact,))


def test_predefined_graph_is_comprehensive_and_preserves_invariants():
    graph = load_predefined_graph()
    assert graph.statistics["entities_total"] >= 4_800
    assert graph.statistics["relations_total"] >= 9_300
    assert graph.statistics["entity:CWE"] >= 1_300
    assert graph.statistics["entity:CAPEC"] >= 700
    assert graph.statistics["entity:ATLAS_TECHNIQUE"] >= 120
    assert graph.statistics["entity:DEFENSIVE_TECHNIQUE"] >= 270
    assert graph.statistics["relation:EXPLOITS_WEAKNESS"] >= 1_200
    assert graph.statistics["relation:USES_TECHNIQUE"] >= 750
    assert not any(
        row.source_id.startswith("CVE-") and row.target_id.startswith("CVE-")
        for row in graph.relations
    )


def test_atlas_case_order_is_metadata_not_universal_causality():
    graph = load_predefined_graph()
    case_edges = [row for row in graph.relations if row.relation_type == "USES_TECHNIQUE"]
    assert case_edges
    assert any(row.metadata.get("step_id") for row in case_edges)
    assert not any(row.relation_type == "PREREQUISITE_OF" for row in graph.relations)


def test_targeted_cve_overlay_maps_weakness_and_product_without_cve_chain():
    base = load_predefined_graph()
    record = {
        "cveMetadata": {"cveId": "CVE-2026-12345", "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "title": "Example vulnerability",
                "descriptions": [{"lang": "en", "value": "Example only"}],
                "problemTypes": [{"descriptions": [{"lang": "en", "cweId": "CWE-89"}]}],
                "affected": [
                    {
                        "vendor": "Example",
                        "product": "Widget",
                        "versions": [{"version": "1.0", "status": "affected"}],
                    }
                ],
            }
        },
    }
    graph = extend_with_targeted_cves(
        base,
        [record],
        source_url="https://example.invalid/CVE-2026-12345.json",
        source_version="test",
    )
    assert any(
        row.source_id == "CVE-2026-12345"
        and row.relation_type == "MAPPED_TO_WEAKNESS"
        and row.target_id == "CWE-89"
        for row in graph.relations
    )
    assert any(
        row.source_id == "CVE-2026-12345" and row.relation_type == "AFFECTS_PRODUCT"
        for row in graph.relations
    )


def test_owasp_api_top10_references_become_typed_edges_without_inference():
    bundle = _owasp_bundle(
        {
            "0xa1-risk-1.md": _owasp_risk(1, "Broken Object Level Authorization", [285, 639]),
            "0xa6-risk-6.md": _owasp_risk(6, "Unrestricted Access to Sensitive Business Flows", []),
        }
    )
    snapshot = KnowledgeEtl().promote((bundle,))
    index = KnowledgeGraphIndex(snapshot)
    risk = index.entity("OWASP-API:API1:2023")
    assert risk is not None and risk.entity_type == "OWASP_API_RISK"
    assert risk.name == "Broken Object Level Authorization"
    assert risk.metadata["rank"] == 1 and risk.metadata["exploitability"] == "Easy"
    assert risk.description == "Risk 1 applies when checks are missing."
    assert {
        row.target_id
        for row in index.outgoing["OWASP-API:API1:2023"]
        if row.relation_type == "REFERENCES_WEAKNESS"
    } == {"CWE-285", "CWE-639"}
    assert "OWASP-API:API6:2023" not in index.outgoing
    # Cited CWEs absent from this build are kept as reference-only nodes, not dropped.
    assert index.entity("CWE-639").metadata["catalog_kind"] == "reference_only"
    assert snapshot.statistics["entity:OWASP_API_RISK"] == 10


def test_owasp_api_bundle_fails_closed_on_inconsistent_or_incomplete_source():
    mismatch = _owasp_bundle({"0xa1-risk-1.md": _owasp_risk(1, "Risk 1", [285], links=[639])})
    with pytest.raises(ValueError, match="disagree"):
        KnowledgeEtl().promote((mismatch,))
    incomplete = _owasp_bundle()
    files = json.loads(incomplete.content)["files"]
    files.pop("0xaa-risk-10.md")
    with pytest.raises(ValueError, match="ranks 1-10"):
        KnowledgeEtl().promote(
            (_artifact("owasp_api", json.dumps({"files": files}), version="2023"),)
        )


def test_cwe_groupings_are_named_nodes_with_view_scoped_membership():
    cwe = _artifact(
        "cwe",
        """
        <Weakness_Catalog>
          <Weaknesses><Weakness ID="22" Name="Path Traversal" /></Weaknesses>
          <Groupings>
            <Grouping ID="1345" Name="OWASP Top Ten 2021 Category A01:2021 - Broken Access Control">
              <Summary>Weaknesses related to A01.</Summary>
              <Relationships><Has_Member CWE_ID="22" View_ID="1344"/></Relationships>
            </Grouping>
          </Groupings>
        </Weakness_Catalog>
        """,
    )
    index = KnowledgeGraphIndex(KnowledgeEtl().promote((cwe,)))
    grouping = index.entity("CWE-1345")
    assert grouping.name.endswith("A01:2021 - Broken Access Control")
    assert grouping.metadata["catalog_kind"] == "grouping"
    assert grouping.description == "Weaknesses related to A01."
    member = next(row for row in index.incoming["CWE-1345"] if row.source_id == "CWE-22")
    assert member.relation_type == "MEMBER_OF" and member.metadata == {"view_id": "1344"}


def test_predefined_graph_includes_owasp_api_top10_and_named_cwe_groupings():
    index = KnowledgeGraphIndex(load_predefined_graph())
    risks = [entity for entity in index.entities.values() if entity.entity_type == "OWASP_API_RISK"]
    assert sorted(risk.metadata["rank"] for risk in risks) == list(range(1, 11))
    assert {row.target_id for row in index.outgoing["OWASP-API:API1:2023"]} == {
        "CWE-285",
        "CWE-639",
    }
    assert "OWASP-API:API6:2023" not in index.outgoing
    assert [risk.entity_id for risk in index.owasp_api_risks("CWE-285")] == [
        "OWASP-API:API1:2023",
        "OWASP-API:API5:2023",
    ]
    assert index.entity("CWE-1345").metadata["catalog_kind"] == "grouping"
    assert not any(
        entity.metadata.get("catalog_kind") == "reference_only"
        for entity in index.entities.values()
    )


def test_digest_verification_uses_the_parser_version_the_snapshot_records(tmp_path):
    snapshot = KnowledgeEtl().promote((_owasp_bundle(),))
    legacy_digest = graph_digest(
        snapshot.entities, snapshot.relations, snapshot.source_manifest, "sentinel-gv-etl-v2"
    )
    legacy = snapshot.model_copy(
        update={"parser_version": "sentinel-gv-etl-v2", "digest": legacy_digest}
    )
    path = tmp_path / "legacy.json.gz"
    dump_predefined_graph(legacy, path)
    assert load_predefined_graph(path).digest == legacy_digest
    dump_predefined_graph(legacy.model_copy(update={"digest": snapshot.digest}), path)
    with pytest.raises(ValueError, match="digest mismatch"):
        load_predefined_graph(path)
