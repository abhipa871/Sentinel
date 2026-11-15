from sentinel.contracts import ModuleOneAgentOutput, ModuleOneCandidateProposal
from sentinel.knowledge import curated_mvp_knowledge
from sentinel.knowledge_graph import load_predefined_graph
from sentinel.module1 import AgenticModuleOne, ModuleOne, evaluate_rule
from sentinel.phase0 import RepositoryExtractor


def test_java_delegation_requires_an_unscoped_lookup_in_the_matching_service(tmp_path):
    (tmp_path / "DocumentController.java").write_text(
        """package example.web;
import example.documents.DocumentService;
class DocumentController {
  DocumentService documents;
  @GetMapping
  public Document get(@PathVariable UUID id) {
    return documents.read(id);
  }
  @GetMapping
  public Document scoped(@PathVariable UUID id) {
    return documents.readOwned(id);
  }
}
""",
        encoding="utf-8",
    )
    (tmp_path / "DocumentServiceImpl.java").write_text(
        """package example.documents;
class DocumentServiceImpl implements DocumentService {
  public Document read(UUID id) {
    return repository.findById(id);
  }
  public Document readOwned(UUID id) {
    return repository.findByIdAndOwner(id, principal());
  }
}
""",
        encoding="utf-8",
    )
    graph = RepositoryExtractor().extract(tmp_path)
    (candidate,) = [
        row
        for row in ModuleOne().run(graph, curated_mvp_knowledge())
        if row.vulnerability_id == "CWE-639"
    ]
    refs = set(candidate.observed_evidence_refs)
    assert {
        (item.source_path, item.start_line) for item in graph.evidence if item.evidence_id in refs
    } == {
        ("DocumentController.java", 7),
        ("DocumentServiceImpl.java", 4),
    }


def test_module_one_emits_potential_candidates_only(sample_graph):
    rows = ModuleOne().run(sample_graph, curated_mvp_knowledge())
    assert rows
    assert all(row.candidate_status == "potential" for row in rows)
    assert any(row.vulnerability_id == "CWE-502" for row in rows)
    assert any(row.vulnerability_id == "CWE-862" for row in rows)
    deserialize = next(row for row in rows if row.vulnerability_id == "CWE-502")
    assert "serialized_input_is_untrusted" in deserialize.untested_preconditions
    assert deserialize.catalog_cvss is None


def test_rule_match_is_not_a_verdict(sample_graph):
    asset = next(item for item in sample_graph.assets if item.path == "services/loader.py")
    rule = next(
        item for item in curated_mvp_knowledge().rules if item.vulnerability_id == "CWE-502"
    )
    result = evaluate_rule(asset, rule)
    assert result.result == "match"
    assert not hasattr(result, "verification_status")


def test_module_one_enriches_from_predefined_graph(sample_graph):
    graph = load_predefined_graph()
    knowledge = curated_mvp_knowledge(graph)
    rows = ModuleOne().run(sample_graph, knowledge, vulnerability_graph=graph)
    assert rows
    assert all(row.kb_snapshot_id == graph.kb_snapshot_id for row in rows)
    assert all(row.knowledge_context.get("catalog_entity_found") for row in rows)


def test_agent_selects_final_module_one_candidates(sample_graph):
    graph = load_predefined_graph()
    knowledge = curated_mvp_knowledge(graph)
    leads = ModuleOne().run(sample_graph, knowledge, vulnerability_graph=graph)
    lead = leads[0]
    output = ModuleOneAgentOutput(
        candidates=(
            ModuleOneCandidateProposal(
                primary_asset_id=lead.asset_id,
                vulnerability_id=lead.vulnerability_id,
                vulnerability_name=lead.vulnerability_name,
                hypothesis=f"Potential {lead.vulnerability_name} requires investigation.",
                investigation_priority=0.84,
                observed_evidence_refs=lead.observed_evidence_refs,
                untested_preconditions=lead.untested_preconditions,
                discovery_basis="Observed source feature and official knowledge relationship.",
            ),
        ),
        analyzed_asset_ids=(lead.asset_id,),
        coverage_warnings=("Fixture-only analysis.",),
        summary="Agent-selected potential candidate.",
        specialist_reviews=(
            "repository-mapping",
            "candidate-discovery",
            "candidate-review",
        ),
    )
    rows = AgenticModuleOne._materialize(
        output, leads, sample_graph, knowledge, graph, max_candidates=10
    )
    assert len(rows) == 1
    assert rows[0].derivation_kind == "agent_inference"
    assert rows[0].candidate_status == "potential"
    assert "agent.module1.discovery.v1" in rows[0].rule_ids

    class FixtureRuntime:
        is_deepagents = True

        def discover_candidates(self, *_args, **_kwargs):
            return output

    merged = AgenticModuleOne(FixtureRuntime()).run(sample_graph, knowledge, graph)
    assert {row.candidate_id for row in merged} == {row.candidate_id for row in leads}
    retained = next(row for row in merged if row.candidate_id == lead.candidate_id)
    assert set(lead.observed_evidence_refs) <= set(retained.observed_evidence_refs)
    assert "agent.module1.discovery.v1" in retained.rule_ids


def test_polyglot_rules_emit_leads_from_syntax_facts_only(tmp_path):
    from sentinel.phase0 import RepositoryExtractor
    from tests.test_phase0 import POLYGLOT_REPO, _write

    _write(
        tmp_path,
        {
            **POLYGLOT_REPO,
            "svc/crapi/shop/serializers.py": "class S:\n    class Meta:\n        fields = '__all__'\n",
            "svc/crapi/shop/auth.py": (
                "import jwt\njwt.decode(t, options={'verify_signature': False})\n"
            ),
            "svc/crapi/empty.py": "",
        },
    )
    graph = RepositoryExtractor().extract(tmp_path)
    leads = ModuleOne().run(graph, curated_mvp_knowledge(), max_candidates=1_000)
    found = {(lead.node, lead.vulnerability_id) for lead in leads}
    assert ("id/src/main/java/com/x/Ctl.java", "CWE-639") in found  # {carId} route parameter
    assert ("id/src/main/java/com/x/Ctl.java", "CWE-862") in found
    assert ("id/src/main/java/com/x/Ctl.java", "CWE-918") in found  # getForObject
    assert ("go/api/router/routes.go", "CWE-943") in found  # bson.M query document
    assert ("go/api/router/routes.go", "CWE-295") in found  # InsecureSkipVerify
    assert ("svc/crapi/shop/serializers.py", "CWE-915") in found  # fields = "__all__"
    assert ("svc/crapi/shop/auth.py", "CWE-347") in found
    assert ("svc/crapi/shop/urls.py", "CWE-639") in found  # (?P<order_id>...)
    # Empty and feature-free files produce no leads, and no predicate is left "unknown".
    assert not any(lead.node == "svc/crapi/empty.py" for lead in leads)
    assert not any(
        "required feature evidence is incomplete" in lead.coverage_warnings for lead in leads
    )
    assert all(lead.candidate_status == "potential" for lead in leads)


def test_rule_dsl_nonempty_and_string_literal_predicates(sample_graph):
    from sentinel.contracts import ApplicabilityRule, AssetType

    asset = next(item for item in sample_graph.assets if item.path == "api/routes.py")

    def rule(required):
        return ApplicabilityRule(
            rule_id="rule.test.v1",
            vulnerability_id="CWE-639",
            vulnerability_name="test",
            rule_version=1,
            applicable_asset_types=(AssetType.SOURCE_FILE,),
            required_features=required,
            derivation_kind="curated_derived",
            source_refs=("test",),
        )

    assert evaluate_rule(asset, rule({"any_string_literals": ("/load",)})).result == "match"
    assert evaluate_rule(asset, rule({"any_string_literals": ("__all__",)})).result == "no_match"
    assert evaluate_rule(asset, rule({"nonempty": ("route_paths",)})).result == "match"
    assert evaluate_rule(asset, rule({"nonempty": ("route_params",)})).result == "no_match"
    assert evaluate_rule(asset, rule({"nonempty": ("never_extracted",)})).result == "unknown"


def test_candidate_enrichment_lists_owasp_api_risks_explicitly():
    from sentinel.knowledge_graph import KnowledgeGraphIndex
    from sentinel.module1 import _knowledge_context

    index = KnowledgeGraphIndex(load_predefined_graph())
    context = _knowledge_context("CWE-639", index)
    assert [risk["entity_id"] for risk in context["owasp_api_risks"]] == ["OWASP-API:API1:2023"]
    direct = _knowledge_context("OWASP-API:API6:2023", index)
    assert direct["entity_type"] == "OWASP_API_RISK"
    assert direct["owasp_api_risks"][0]["raw_id"] == "API6:2023"
