import hashlib
from datetime import UTC, datetime

import pytest

from sentinel.knowledge_etl import CatalogArtifact, KnowledgeEtl
from sentinel.knowledge_graph import load_predefined_graph
from sentinel.knowledge_overlay import extend_with_targeted_cves


def _artifact(catalog, content):
    raw = content.encode()
    return CatalogArtifact(
        catalog=catalog,
        version="test-v1",
        source_url=f"https://example.invalid/{catalog}",
        content=raw,
        retrieved_at=datetime.now(UTC),
        expected_sha256=hashlib.sha256(raw).hexdigest(),
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
