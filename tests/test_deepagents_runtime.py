import pytest

from sentinel.agents.runtime import DeepAgentsRuntime, EvidenceToolbox
from sentinel.contracts import (
    ModuleOneAgentOutput,
    ModuleOneCandidateProposal,
    RelatedAsset,
    SecurityReviewProposal,
    VerificationStatus,
)
from sentinel.knowledge_graph import load_predefined_graph
from sentinel.module3 import ModuleThree


def test_cwe_tools_search_definitions_and_return_mitigation_text(sample_graph):
    toolbox = EvidenceToolbox(sample_graph, load_predefined_graph())
    result = toolbox.search_weaknesses("CWE-89")
    assert result["matches"][0]["entity_id"] == "CWE-89"
    assert toolbox.search_weaknesses("sql injection")["total_matches"] > 0
    documentation = toolbox.knowledge_neighborhood("CWE-89", limit=50)
    assert documentation["source_url"] == "https://cwe.mitre.org/data/definitions/89.html"
    assert documentation["entity"]["description"]
    assert any(
        entity["entity_type"] == "MITIGATION" and entity["description"]
        for entity in documentation["related_entities"]
    )
    assert "error" in toolbox.knowledge_neighborhood("CWE-99999999")
    assert "error" in toolbox.search_weaknesses("")


@pytest.mark.parametrize("planning", [False, True])
def test_review_and_planning_specialists_receive_cwe_tools(sample_graph, monkeypatch, planning):
    captured = {}

    def capture_agent(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr("deepagents.create_deep_agent", capture_agent)
    runtime = DeepAgentsRuntime("google_genai:gemini-2.5-flash")
    runtime._agent(
        toolbox=EvidenceToolbox(sample_graph, runtime.vulnerability_graph),
        response_format=SecurityReviewProposal,
        planning=planning,
    )
    for specialist in captured["subagents"]:
        names = {tool.name for tool in specialist["tools"]}
        assert {"search_weaknesses", "knowledge_neighborhood"} <= names
        assert "MITRE CWE" in specialist["system_prompt"]


def test_openai_models_disable_reasoning_for_chat_completion_tools(monkeypatch):
    captured = {}

    def fake_init_chat_model(model_name, **kwargs):
        captured["model_name"] = model_name
        captured.update(kwargs)
        return object()

    monkeypatch.setenv("OPENAI_API_KEY", "test-only-not-a-real-secret")
    monkeypatch.setattr("langchain.chat_models.init_chat_model", fake_init_chat_model)
    runtime = object.__new__(DeepAgentsRuntime)
    runtime.max_provider_retries = 5
    runtime.provider_timeout_seconds = 120

    runtime._model_client("openai:gpt-5.6-luna")

    assert captured["model_name"] == "gpt-5.6-luna"
    assert captured["model_provider"] == "openai"
    assert captured["reasoning_effort"] == "none"
    assert "use_responses_api" not in captured


def test_deepagents_factory_builds_locked_compiled_graph(sample_graph):
    runtime = DeepAgentsRuntime("google_genai:gemini-2.5-flash")
    agent = runtime._agent(
        toolbox=EvidenceToolbox(sample_graph),
        response_format=SecurityReviewProposal,
        planning=False,
    )
    assert type(agent).__name__ == "CompiledStateGraph"
    module_one_agent = runtime._module_one_agent(EvidenceToolbox(sample_graph))
    graph_agent = runtime._repository_graph_agent(EvidenceToolbox(sample_graph))
    assert type(module_one_agent).__name__ == "CompiledStateGraph"
    assert type(graph_agent).__name__ == "CompiledStateGraph"
    assert len(runtime._skill_files()) == 12


def test_source_tool_rejects_drift_and_untracked_paths(sample_graph):
    toolbox = EvidenceToolbox(sample_graph)
    result = toolbox.read_source_span("../outside.py")
    assert "outside" in result["error"]


def test_agent_pagination_is_safely_clamped(sample_graph):
    toolbox = EvidenceToolbox(sample_graph)
    assets = toolbox.list_assets(limit=10_000)
    edges = toolbox.edge_hints(limit=10_000)
    search = toolbox.search_source("route", limit=10_000)
    assert assets["limit_clamped"] is True
    assert edges["limit_clamped"] is True
    assert search["limit_clamped"] is True


def test_edge_support_returns_canonical_endpoint_evidence(sample_graph):
    edge = sample_graph.edges[0]
    toolbox = EvidenceToolbox(sample_graph)
    support = toolbox.edge_support(edge.source_asset_id, edge.target_asset_id)
    assert support["source_path"] in edge.source_location
    assert support["target_path"] == edge.target_location
    assert support["parser_edge_hints"]


def test_asset_handles_resolve_exactly_to_canonical_ids(sample_graph):
    toolbox = EvidenceToolbox(sample_graph)
    handle, asset_id = next(iter(toolbox.asset_handles.items()))
    asset = toolbox.assets[asset_id]
    assert toolbox.resolve_asset_reference(handle) == asset_id
    assert toolbox.resolve_asset_reference(asset.path) == asset_id
    assert toolbox.resolve_asset_reference(asset_id) == asset_id


def test_agent_tool_schema_rejects_bad_arguments_without_aborting(sample_graph):
    runtime = DeepAgentsRuntime("google_genai:gemini-2.5-flash")
    toolbox = EvidenceToolbox(sample_graph)
    search_tool = runtime._tools([toolbox.search_source])[0]
    result = search_tool.invoke({"query": "route", "limit": 10_000})
    assert "ValidationError" in result
    assert "Correct the tool arguments" in result


def test_evidence_handles_resolve_exactly_and_never_fuzzy_match(sample_graph):
    toolbox = EvidenceToolbox(sample_graph)
    handle, evidence_id = next(iter(toolbox.evidence_handles.items()))
    assert handle.startswith("E") and len(handle) == 7
    assert toolbox.resolve_evidence_reference(handle) == evidence_id
    assert toolbox.resolve_evidence_reference(evidence_id) == evidence_id
    truncated = evidence_id[:-1]
    assert toolbox.resolve_evidence_reference(truncated) == truncated
    assert toolbox.resolve_evidence_reference("E999999") == "E999999"


def test_tool_results_present_handles_instead_of_digest_ids(sample_graph):
    toolbox = EvidenceToolbox(sample_graph)
    listing = toolbox.list_assets()
    rendered = str(listing) + str(toolbox.edge_hints()) + str(toolbox.search_source("load"))
    assert "ev:" not in rendered
    assert "asset:" not in rendered
    first = listing["assets"][0]
    assert first["asset_id"] in toolbox.asset_handles
    assert all(ref in toolbox.evidence_handles for ref in first["evidence_refs"])
    hint = toolbox.edge_hints()["edge_hints"][0]
    assert hint["evidence_summaries"]
    evidence = toolbox.read_evidence(hint["evidence_refs"][0])
    assert evidence["evidence_id"] == hint["evidence_refs"][0]
    assert "error" not in evidence


def test_asset_catalog_lists_every_asset_with_its_evidence_handles(sample_graph):
    toolbox = EvidenceToolbox(sample_graph)
    catalog = toolbox.asset_catalog()
    assert len(catalog) == len(sample_graph.assets)
    cited = {ref for entry in catalog.values() for ref in entry["evidence_refs"]}
    assert cited == set(toolbox.evidence_handles)


def test_security_review_is_canonicalized_and_provenance_is_observed(sample_graph):
    from langchain_core.messages import AIMessage, ToolMessage

    from sentinel.knowledge import curated_mvp_knowledge
    from sentinel.module1 import ModuleOne
    from sentinel.module2 import InvalidAgentProposal, validate_security_review

    candidate = ModuleOne().run(sample_graph, curated_mvp_knowledge())[0]
    toolbox = EvidenceToolbox(sample_graph)
    asset_handle = toolbox.handle_by_asset_id[candidate.asset_id]
    evidence_handle = toolbox.handle_by_evidence_id[candidate.observed_evidence_refs[0]]
    messages = [
        AIMessage(
            content="",
            tool_calls=[
                {"name": "task", "id": "t1", "args": {"subagent_type": "code-analysis"}},
                {"name": "task", "id": "t2", "args": {"subagent_type": "evidence-review"}},
                {"name": "task", "id": "t3", "args": {"subagent_type": "general-purpose"}},
            ],
        ),
        ToolMessage(content="{}", tool_call_id="t1"),
        ToolMessage(content="failed", tool_call_id="t2", status="error"),
        ToolMessage(content="{}", tool_call_id="t3"),
    ]
    executed = DeepAgentsRuntime._executed_subagents(
        messages, frozenset({"code-analysis", "evidence-review"})
    )
    assert executed == ("code-analysis",)
    proposal = SecurityReviewProposal(
        candidate_id="C000001",
        primary_asset_id=asset_handle,
        vulnerability_id=candidate.vulnerability_id,
        status=VerificationStatus.STRONGLY_SUPPORTED,
        supporting_evidence_refs=(evidence_handle,),
        contradictory_evidence_refs=(),
        related_nodes=(
            RelatedAsset(
                asset_id=asset_handle,
                path="model-supplied/path.py",
                edge_types=(),
                graph_distance=0,
                evidence_refs=(evidence_handle,),
            ),
        ),
        criticality="high",
        criticality_basis="test",
        relationship_explanation="test",
        assumptions=(),
        analyst_summary="test",
        specialist_reviews=("code-analysis", "evidence-review"),
    )
    canonical = DeepAgentsRuntime._canonicalize_security_review(
        proposal, toolbox, candidate, executed
    )
    assert canonical.candidate_id == candidate.candidate_id
    assert canonical.primary_asset_id == candidate.asset_id
    assert canonical.supporting_evidence_refs == candidate.observed_evidence_refs[:1]
    assert canonical.related_nodes[0].path == candidate.node
    # The supervisor claimed an evidence review whose delegation failed, so the positive
    # verdict must not pass validation on the strength of that claim.
    assert canonical.specialist_reviews == ("code-analysis",)
    with pytest.raises(InvalidAgentProposal, match="independent evidence review"):
        validate_security_review(canonical, candidate, sample_graph)


def test_module_one_contract_flags_verdict_wording_and_unrelated_assets(sample_graph):
    toolbox = EvidenceToolbox(sample_graph, load_predefined_graph())
    loader = next(asset for asset in sample_graph.assets if asset.path == "services/loader.py")
    unrelated = next(asset for asset in sample_graph.assets if asset.path == "pyproject.toml")
    output = ModuleOneAgentOutput(
        candidates=(
            ModuleOneCandidateProposal(
                primary_asset_id=loader.asset_id,
                vulnerability_id="CWE-502",
                vulnerability_name="Deserialization of Untrusted Data",
                hypothesis="Exploitability is not confirmed yet.",
                investigation_priority=0.5,
                observed_evidence_refs=loader.evidence_refs,
                related_asset_ids=(unrelated.asset_id,),
                untested_preconditions=("attacker controls data",),
                discovery_basis="pickle.loads observed",
            ),
        ),
        analyzed_asset_ids=(loader.asset_id,),
        coverage_warnings=(),
        summary="test",
        specialist_reviews=(),
    )
    errors = DeepAgentsRuntime._module_one_contract_errors(output, toolbox, max_candidates=5)
    assert any("verdict wording 'confirmed'" in error for error in errors)
    assert any("not connected to the primary asset" in error for error in errors)


def test_module_three_skips_planning_without_eligible_findings(sample_graph):
    class Runtime:
        is_deepagents = True

        def synthesize_plan(self, findings, graph):
            raise AssertionError("no agent transaction may run without eligible findings")

    planning, optimization = ModuleThree(Runtime()).run((), sample_graph)  # type: ignore[arg-type]
    assert planning.remediations == () and planning.attack_paths == ()
    assert optimization.solver_status == "sat"
    assert optimization.selected_proposal_ids == ()


def test_specialist_subagents_use_tool_strategy_with_error_feedback(sample_graph, monkeypatch):
    from langchain.agents.structured_output import ToolStrategy

    captured = {}

    def fake_create_deep_agent(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr("deepagents.create_deep_agent", fake_create_deep_agent)
    runtime = DeepAgentsRuntime("google_genai:gemini-2.5-flash")
    for planning in (False, True):
        runtime._agent(
            toolbox=EvidenceToolbox(sample_graph),
            response_format=SecurityReviewProposal,
            planning=planning,
        )
        strategies = [spec["response_format"] for spec in captured["subagents"]]
        strategies.append(captured["response_format"])
        assert all(isinstance(strategy, ToolStrategy) for strategy in strategies)
        assert all(callable(strategy.handle_errors) for strategy in strategies)
        message = strategies[0].handle_errors(ValueError("extra_forbidden: baseline_controls"))
        assert "baseline_controls" in message
