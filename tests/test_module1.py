from sentinel.contracts import ModuleOneAgentOutput, ModuleOneCandidateProposal
from sentinel.knowledge import curated_mvp_knowledge
from sentinel.knowledge_graph import load_predefined_graph
from sentinel.module1 import AgenticModuleOne, ModuleOne, evaluate_rule


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
