from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import BaseModel

from sentinel.agentic_graph import AgenticRepositoryGraphBuilder, InvalidRepositoryGraphAgentOutput
from sentinel.agents.runtime import DeepAgentsRuntime, EvidenceToolbox, ToolBudgetExceeded
from sentinel.contracts import (
    CoverageChecklistItem,
    ModuleOneAgentOutput,
    ModuleOneCandidateProposal,
    RepositoryGraphAgentOutput,
    RepositoryGraphHintRejection,
)
from sentinel.knowledge_graph import load_predefined_graph
from sentinel.module1 import AgenticModuleOne
from sentinel.partitions import SUPPORTING_PARTITION, partition_assets
from sentinel.phase0 import RepositoryExtractor
from sentinel.profiles import PROFILES, get_profile
from tests.test_phase0 import POLYGLOT_REPO, _write


@pytest.fixture
def polyglot_graph(tmp_path: Path):
    _write(
        tmp_path, {**POLYGLOT_REPO, "docs/guide.md": "# Guide\n", "deploy/compose.yml": "x: 1\n"}
    )
    return RepositoryExtractor().extract(tmp_path)


def _paths(graph, partition) -> set[str]:
    return {asset.path for asset in graph.assets if asset.asset_id in partition}


def test_partitions_follow_component_roots_and_pool_supporting_files(polyglot_graph):
    partitions = {item.partition_id: item for item in partition_assets(polyglot_graph)}
    assert set(partitions) == {"go", "id", "svc", "web", SUPPORTING_PARTITION}
    assert "go/api/router/routes.go" in _paths(polyglot_graph, partitions["go"])
    assert "id/src/main/java/com/x/Ctl.java" in _paths(polyglot_graph, partitions["id"])
    assert _paths(polyglot_graph, partitions[SUPPORTING_PARTITION]) == {
        "docs/guide.md",
        "deploy/compose.yml",
    }
    every = [asset for item in partitions.values() for asset in item.asset_ids]
    assert sorted(every) == sorted(asset.asset_id for asset in polyglot_graph.assets)


def test_oversized_components_split_by_path_and_pack_siblings_up_to_the_cap():
    from sentinel.partitions import _split

    paths = {
        "root": "svc/build.gradle",
        "a1": "svc/a/one.java",
        "a2": "svc/a/two.java",
        "b1": "svc/b/one.java",
        "c1": "svc/c/deep/x/one.java",
        "c2": "svc/c/deep/y/two.java",
    }
    hints = {"root": 1, "a1": 3, "a2": 3, "b1": 2, "c1": 4, "c2": 4}
    pieces = _split("svc", set(paths), paths, hints, max_hints=7)
    labels = [label for label, _ in pieces]
    assert labels == ["svc/{.,a}", "svc/{b,c/deep/x}", "svc/c/deep/y"]
    members = [asset for _, assets in pieces for asset in assets]
    assert sorted(members) == sorted(paths)
    assert all(sum(hints[item] for item in assets) <= 7 for _, assets in pieces)
    assert _split("svc", set(paths), paths, hints, max_hints=100) == [("svc", set(paths))]


def test_hint_cap_keeps_every_asset_in_exactly_one_partition(polyglot_graph):
    capped = partition_assets(polyglot_graph, max_hints=1)
    every = [asset for partition in capped for asset in partition.asset_ids]
    assert sorted(every) == sorted(asset.asset_id for asset in polyglot_graph.assets)
    assert len(capped) > len(partition_assets(polyglot_graph))


def test_focus_scopes_discovery_tools_but_not_point_lookups(polyglot_graph):
    go = next(item for item in partition_assets(polyglot_graph) if item.partition_id == "go")
    toolbox = EvidenceToolbox(polyglot_graph, focus=go.asset_ids)
    catalog_paths = {entry["path"] for entry in toolbox.asset_catalog().values()}
    assert catalog_paths == _paths(polyglot_graph, go)
    assert {row["path"] for row in toolbox.list_assets()["assets"]} <= catalog_paths
    assert all(row["source"].startswith("go/") for row in toolbox.hint_table())
    assert all(row["hint_ref"].startswith("H") for row in toolbox.edge_hints()["edge_hints"])
    assert "error" not in toolbox.read_source_span("svc/crapi/shop/views.py")


def _graph_output(graph, **updates) -> RepositoryGraphAgentOutput:
    base = RepositoryGraphAgentOutput(
        asset_annotations=(),
        edges=(),
        unresolved=(),
        analyzed_asset_ids=(),
        coverage_warnings=(),
        summary="test",
        specialist_reviews=("repository-scan", "dependency-graph-building", "graph-review"),
    )
    return base.model_copy(update=updates)


def test_accepted_hints_keep_observed_evidence_and_rejections_are_counted(polyglot_graph):
    imports = [edge for edge in polyglot_graph.edges if edge.edge_type.value == "IMPORTS"]
    accepted, rejected = imports[0], imports[1]
    proposal = _graph_output(
        polyglot_graph,
        accepted_hint_refs=(accepted.edge_id,),
        rejected_hints=(RepositoryGraphHintRejection(hint_ref=rejected.edge_id, reason="x"),),
    )
    graph = AgenticRepositoryGraphBuilder._materialize(proposal, polyglot_graph)
    assert len(graph.edges) == 1
    edge = graph.edges[0]
    assert edge.resolution_method == f"deepagents:accepted_parser_hint:{accepted.resolution_method}"
    assert edge.evidence_refs == accepted.evidence_refs
    assert edge.source_location == accepted.source_location
    assert any("accepted 1 and rejected 1" in item for item in graph.snapshot.warnings)
    both = _graph_output(
        polyglot_graph,
        accepted_hint_refs=(accepted.edge_id,),
        rejected_hints=(RepositoryGraphHintRejection(hint_ref=accepted.edge_id, reason="x"),),
    )
    with pytest.raises(InvalidRepositoryGraphAgentOutput, match="both accepted and rejected"):
        AgenticRepositoryGraphBuilder._materialize(both, polyglot_graph)


def test_partitioned_graph_run_merges_disjoint_proposals(polyglot_graph):
    seen: list[str] = []

    class Runtime:
        is_deepagents = True

        def build_repository_graph(self, observations, *, focus=None, profile=None):
            seen.append(focus.partition_id)
            accepted = tuple(
                edge.edge_id for edge in observations.edges if edge.source_asset_id in focus
            )
            return _graph_output(observations, accepted_hint_refs=accepted)

    partitions = partition_assets(polyglot_graph)
    graph = AgenticRepositoryGraphBuilder(Runtime()).run(  # type: ignore[arg-type]
        polyglot_graph, partitions=partitions, profile=PROFILES["balanced"]
    )
    # Partitions run concurrently, so completion order is not fixed.
    assert sorted(seen) == sorted(item.partition_id for item in partitions)
    assert len(graph.edges) == len(polyglot_graph.edges)


class _ScriptedModel(BaseChatModel):
    """Replays scripted AI messages; enough to drive a real agent loop offline."""

    script: list[AIMessage]

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any):
        return ChatResult(generations=[ChatGeneration(message=self.script.pop(0))])


class _Answer(BaseModel):
    value: int


def _call(name: str, index: int, **args: Any) -> AIMessage:
    return AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": f"c{index}"}])


def test_tool_budget_refuses_extra_calls_but_never_blocks_the_typed_response(sample_graph):
    runtime = DeepAgentsRuntime("google_genai:gemini-2.5-flash")
    toolbox = EvidenceToolbox(sample_graph)
    handle = next(iter(toolbox.evidence_handles))
    script = [_call("read_evidence", i, evidence_id=handle) for i in range(3)]
    script.append(_call("_Answer", 9, value=7))
    agent = runtime._typed_agent(
        model=_ScriptedModel(script=script),
        tools=runtime._tools([toolbox.read_evidence]),
        system_prompt="x",
        response_format=_Answer,
        tool_budget=2,
    )
    result = agent.invoke({"messages": [{"role": "user", "content": "go"}]})
    assert result["structured_response"].value == 7
    replies = [m for m in result["messages"] if isinstance(m, ToolMessage)]
    assert sum("Tool budget exhausted" in str(m.content) for m in replies) == 1


def test_one_parallel_batch_over_budget_is_refused_not_aborted(sample_graph):
    # Regression: a single turn requesting many tools in parallel exceeded the old per-call grace
    # and aborted before the model had seen any refusal.
    runtime = DeepAgentsRuntime("google_genai:gemini-2.5-flash")
    toolbox = EvidenceToolbox(sample_graph)
    handle = next(iter(toolbox.evidence_handles))
    batch = AIMessage(
        content="",
        tool_calls=[
            {"name": "read_evidence", "args": {"evidence_id": handle}, "id": f"p{i}"}
            for i in range(25)
        ],
    )
    agent = runtime._typed_agent(
        model=_ScriptedModel(script=[batch, _call("_Answer", 99, value=3)]),
        tools=runtime._tools([toolbox.read_evidence]),
        system_prompt="x",
        response_format=_Answer,
        tool_budget=18,
    )
    result = agent.invoke({"messages": [{"role": "user", "content": "go"}]})
    assert result["structured_response"].value == 3
    refused = [
        m
        for m in result["messages"]
        if isinstance(m, ToolMessage) and "Tool budget exhausted" in str(m.content)
    ]
    assert len(refused) == 7


def test_telemetry_records_stage_usage_and_budget_exhaustion(sample_graph):
    from sentinel.telemetry import RunTelemetry, collecting

    runtime = DeepAgentsRuntime("google_genai:gemini-2.5-flash")
    toolbox = EvidenceToolbox(sample_graph)
    handle = next(iter(toolbox.evidence_handles))
    usage = {"input_tokens": 100, "output_tokens": 7, "total_tokens": 107}
    script = [
        AIMessage(
            content="",
            usage_metadata=usage,
            tool_calls=[{"name": "read_evidence", "args": {"evidence_id": handle}, "id": f"t{i}"}],
        )
        for i in range(3)
    ]
    script.append(
        AIMessage(
            content="",
            usage_metadata=usage,
            tool_calls=[{"name": "_Answer", "args": {"value": 1}, "id": "done"}],
        )
    )
    agent = runtime._typed_agent(
        model=_ScriptedModel(script=script),
        tools=runtime._tools([toolbox.read_evidence]),
        system_prompt="x",
        response_format=_Answer,
        tool_budget=2,
        budget_label="probe",
    )
    lines: list[str] = []
    telemetry = RunTelemetry(progress=lines.append)
    with collecting(telemetry):
        runtime._invoke_stage(agent, {"messages": [{"role": "user", "content": "go"}]}, "probe")
    metrics, events = telemetry.snapshot()
    assert len(metrics) == 1 and metrics[0].outcome == "ok"
    assert metrics[0].model_calls == 4 and metrics[0].input_tokens == 400
    assert metrics[0].tool_calls >= 2
    budget = [event for event in events if event.kind == "budget_exhausted"]
    assert budget and budget[0].stage == "probe" and "1 further calls refused" in budget[0].detail
    assert any("stage_ok" in line for line in lines)


def test_tool_budget_aborts_a_model_that_ignores_refusals(sample_graph):
    runtime = DeepAgentsRuntime("google_genai:gemini-2.5-flash")
    toolbox = EvidenceToolbox(sample_graph)
    handle = next(iter(toolbox.evidence_handles))
    agent = runtime._typed_agent(
        model=_ScriptedModel(
            script=[_call("read_evidence", i, evidence_id=handle) for i in range(20)]
        ),
        tools=runtime._tools([toolbox.read_evidence]),
        system_prompt="x",
        response_format=_Answer,
        tool_budget=1,
    )
    with pytest.raises(ToolBudgetExceeded):
        agent.invoke({"messages": [{"role": "user", "content": "go"}]})


def _module_one_output(
    asset_id: str, evidence: tuple[str, ...], checklist=()
) -> ModuleOneAgentOutput:
    return ModuleOneAgentOutput(
        candidates=(
            ModuleOneCandidateProposal(
                primary_asset_id=asset_id,
                vulnerability_id="CWE-862",
                vulnerability_name="Missing Authorization",
                hypothesis="Route may lack an authorization check.",
                investigation_priority=0.6,
                observed_evidence_refs=evidence,
                untested_preconditions=("route reachable",),
                discovery_basis="route feature",
            ),
        ),
        analyzed_asset_ids=(asset_id,),
        coverage_warnings=("partial",),
        summary="s",
        specialist_reviews=("repository-mapping", "candidate-discovery", "candidate-review"),
        coverage_checklist=checklist,
    )


def test_partitioned_module_one_merges_outputs_and_exposes_coverage(polyglot_graph):
    vulnerability_graph = load_predefined_graph()
    partitions = partition_assets(polyglot_graph)
    by_path = {asset.path: asset for asset in polyglot_graph.assets}

    class Runtime:
        is_deepagents = True

        def discover_candidates(self, leads, graph, vg, *, max_candidates, focus, profile):
            source = next(
                (
                    by_path[p]
                    for p in sorted(by_path)
                    if by_path[p].asset_id in focus
                    and p.endswith((".py", ".java", ".go", ".ts", ".js"))
                ),
                None,
            )
            if source is None:
                return _module_one_output(next(iter(focus.asset_ids)), (), ()).model_copy(
                    update={"candidates": ()}
                )
            item = CoverageChecklistItem(
                entity_id="OWASP-API:API5:2023",
                status="examined_no_candidate",
                note="n",
                partition_id=focus.partition_id,
            )
            return _module_one_output(source.asset_id, source.evidence_refs, (item,))

    from sentinel.knowledge import curated_mvp_knowledge

    module_one = AgenticModuleOne(Runtime())  # type: ignore[arg-type]
    rows = module_one.run(
        polyglot_graph,
        curated_mvp_knowledge(vulnerability_graph),
        vulnerability_graph,
        max_candidates=2,
        partitions=partitions,
        profile=get_profile("balanced"),
    )
    assert len(rows) == 2  # four source partitions offered one each; the budget keeps two
    assert any("exceeded the 2-candidate budget" in w for w in rows[0].coverage_warnings)
    assert {item.partition_id for item in module_one.coverage_checklist} == {
        "go",
        "id",
        "svc",
        "web",
    }


def test_runtime_contract_requires_full_checklist_and_in_partition_primary(polyglot_graph):
    vulnerability_graph = load_predefined_graph()
    go = next(item for item in partition_assets(polyglot_graph) if item.partition_id == "go")
    outside = next(asset for asset in polyglot_graph.assets if asset.path.endswith("Ctl.java"))
    runtime = DeepAgentsRuntime("google_genai:gemini-2.5-flash")
    toolbox = EvidenceToolbox(polyglot_graph, vulnerability_graph, focus=go.asset_ids)
    risks = [risk["entity_id"] for risk in runtime._owasp_api_risks(toolbox)]
    assert len(risks) == 10
    errors = runtime._module_one_contract_errors(
        _module_one_output(outside.asset_id, outside.evidence_refs), toolbox, max_candidates=5
    )
    assert not errors  # the shared checks do not know about partitions...

    # ...the partition-scoped checks are applied inside discover_candidates; exercise them by
    # stubbing the synthesis so nothing reaches a model.
    captured: dict[str, Any] = {}

    def fake_synthesize(**kwargs):
        captured.update(kwargs)
        return kwargs["finalize"](_module_one_output(outside.asset_id, outside.evidence_refs))

    runtime._synthesize = fake_synthesize  # type: ignore[method-assign]
    from sentinel.contracts import ModuleOneSpecialistReview

    runtime._invoke_specialist = lambda **kwargs: ModuleOneSpecialistReview(  # type: ignore[method-assign]
        specialist=kwargs["name"],
        conclusions=(),
        supporting_evidence_refs=(),
        asset_ids=(),
        unknown_conditions=(),
    )
    runtime._stage_cache_path = lambda *_: Path("never-exists.json")  # type: ignore[method-assign]
    runtime.discover_candidates((), polyglot_graph, vulnerability_graph, max_candidates=5, focus=go)
    output = captured["finalize"](_module_one_output(outside.asset_id, outside.evidence_refs))
    errors = captured["contract_errors"](output)
    assert any("outside partition go" in error for error in errors)
    assert any("coverage_checklist must list each owasp_api_top10" in error for error in errors)


def _offline_runtime(tmp_path: Path, structured: Any) -> DeepAgentsRuntime:
    """A runtime whose model always returns `structured`; specialists and caches are stubbed."""
    from sentinel.contracts import ModuleOneSpecialistReview, RepositoryGraphSpecialistReview

    runtime = DeepAgentsRuntime("google_genai:gemini-2.5-flash", stage_cache_root=tmp_path)
    runtime._invoke_stage = lambda agent, payload, stage: {"structured_response": structured}  # type: ignore[method-assign]

    def specialist(**kwargs: Any) -> Any:
        schema = kwargs["response_format"]
        fields = {"conclusions": (), "supporting_evidence_refs": (), "asset_ids": ()}
        if schema is ModuleOneSpecialistReview or schema is RepositoryGraphSpecialistReview:
            return schema(specialist=kwargs["name"], unknown_conditions=(), **fields)
        raise AssertionError(schema)

    runtime._invoke_specialist = specialist  # type: ignore[method-assign]
    return runtime


def test_module_one_salvage_fails_closed_per_item_and_names_what_it_removed(
    polyglot_graph, tmp_path
):
    vulnerability_graph = load_predefined_graph()
    go = next(item for item in partition_assets(polyglot_graph) if item.partition_id == "go")
    assets = {asset.path: asset for asset in polyglot_graph.assets}
    routes, coupon = assets["go/api/router/routes.go"], assets["go/api/models/coupon.go"]
    unconnected = assets["go/api/models/coupon_test.go"]
    valid = ModuleOneCandidateProposal(
        primary_asset_id=routes.asset_id,
        vulnerability_id="CWE-943",
        vulnerability_name="NoSQL query logic",
        hypothesis="A query document may include client-controlled operators.",
        investigation_priority=0.8,
        observed_evidence_refs=routes.evidence_refs,
        related_asset_ids=(coupon.asset_id, unconnected.asset_id),
        untested_preconditions=("value is client controlled",),
        discovery_basis="bson.M query document",
    )
    invented = valid.model_copy(
        update={"vulnerability_id": "CWE-918", "observed_evidence_refs": ("E999999",)}
    )
    broken = ModuleOneAgentOutput(
        candidates=(valid, invented),
        analyzed_asset_ids=(routes.asset_id,),
        coverage_warnings=(),
        summary="s",
        specialist_reviews=(),
        coverage_checklist=(
            CoverageChecklistItem(
                entity_id="OWASP-API:API7:2023", status="examined_no_candidate", note="n"
            ),
        ),
    )
    runtime = _offline_runtime(tmp_path, broken)
    output = runtime.discover_candidates(
        (), polyglot_graph, vulnerability_graph, max_candidates=5, focus=go
    )
    assert [candidate.vulnerability_id for candidate in output.candidates] == ["CWE-943"]
    assert output.candidates[0].related_asset_ids == (coupon.asset_id,)
    notes = " ".join(output.coverage_warnings)
    assert "go/api/models/coupon_test.go" in notes
    assert "dropped a CWE-918 candidate on go/api/router/routes.go" in notes
    assert len(output.coverage_checklist) == 10
    assert sum(item.status == "not_examined" for item in output.coverage_checklist) == 9
    assert all(item.partition_id == "go" for item in output.coverage_checklist)
    assert list(tmp_path.glob("*/output.json")), "the salvaged, valid output is cached"


def test_graph_salvage_drops_unknown_hints_and_out_of_partition_annotations(
    polyglot_graph, tmp_path
):
    from sentinel.contracts import RepositoryGraphAssetAnnotation

    go = next(item for item in partition_assets(polyglot_graph) if item.partition_id == "go")
    assets = {asset.path: asset for asset in polyglot_graph.assets}
    routes, controller = (
        assets["go/api/router/routes.go"],
        assets["id/src/main/java/com/x/Ctl.java"],
    )
    hint = next(edge for edge in polyglot_graph.edges if edge.source_asset_id == routes.asset_id)

    def annotation(asset):
        return RepositoryGraphAssetAnnotation(
            asset_id=asset.asset_id,
            file_role="source",
            node_priority=0.5,
            security_relevance="r",
            evidence_refs=asset.evidence_refs,
        )

    broken = _graph_output(
        polyglot_graph,
        asset_annotations=(annotation(routes), annotation(controller)),
        accepted_hint_refs=(hint.edge_id, "H999999"),
    )
    output = _offline_runtime(tmp_path, broken).build_repository_graph(polyglot_graph, focus=go)
    assert output.accepted_hint_refs == (hint.edge_id,)
    assert [item.asset_id for item in output.asset_annotations] == [routes.asset_id]
    notes = " ".join(output.coverage_warnings)
    assert "id/src/main/java/com/x/Ctl.java" in notes and "H999999" in notes


def test_unrecoverable_partition_fails_closed_and_the_scan_continues(polyglot_graph):
    from sentinel.agents.runtime import ContractRepairFailed
    from sentinel.knowledge import curated_mvp_knowledge

    vulnerability_graph = load_predefined_graph()
    partitions = partition_assets(polyglot_graph)
    by_path = {asset.path: asset for asset in polyglot_graph.assets}

    class Runtime:
        is_deepagents = True

        def discover_candidates(self, leads, graph, vg, *, max_candidates, focus, profile):
            if focus.partition_id == "go":
                raise ContractRepairFailed("module1[go] failed contract repair: bad")
            source = next(
                (
                    by_path[p]
                    for p in sorted(by_path)
                    if by_path[p].asset_id in focus and p.endswith((".py", ".java", ".ts", ".js"))
                ),
                None,
            )
            if source is None:
                return _module_one_output(next(iter(focus.asset_ids)), ()).model_copy(
                    update={"candidates": ()}
                )
            return _module_one_output(source.asset_id, source.evidence_refs)

        def build_repository_graph(self, observations, *, focus=None, profile=None):
            if focus.partition_id == "go":
                raise ContractRepairFailed("graph[go] failed contract repair: bad")
            return _graph_output(observations)

    module_one = AgenticModuleOne(Runtime())  # type: ignore[arg-type]
    rows = module_one.run(
        polyglot_graph,
        curated_mvp_knowledge(vulnerability_graph),
        vulnerability_graph,
        max_candidates=10,
        partitions=partitions,
        profile=get_profile("balanced"),
    )
    assert rows and not any(row.node.startswith("go/") for row in rows)
    assert any("[go] partition not analyzed" in w for w in rows[0].coverage_warnings)
    go_items = [item for item in module_one.coverage_checklist if item.partition_id == "go"]
    assert len(go_items) == 10 and {item.status for item in go_items} == {"not_examined"}
    graph = AgenticRepositoryGraphBuilder(Runtime()).run(  # type: ignore[arg-type]
        polyglot_graph, partitions=partitions
    )
    assert any("[go] partition graph not built" in w for w in graph.snapshot.warnings)


def test_provider_errors_are_not_swallowed_by_fail_closed(polyglot_graph):
    from sentinel.knowledge import curated_mvp_knowledge

    vulnerability_graph = load_predefined_graph()

    class Runtime:
        is_deepagents = True

        def discover_candidates(self, *args, **kwargs):
            raise RuntimeError("module1 failed on attempt 2: 401 invalid api key")

    with pytest.raises(RuntimeError, match="401"):
        AgenticModuleOne(Runtime()).run(  # type: ignore[arg-type]
            polyglot_graph,
            curated_mvp_knowledge(vulnerability_graph),
            vulnerability_graph,
            partitions=partition_assets(polyglot_graph),
        )
