from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from sentinel.agents.runtime import DeepAgentsRuntime
from sentinel.contracts import SecurityReviewProposal, VerificationStatus
from sentinel.knowledge import curated_mvp_knowledge
from sentinel.module1 import ModuleOne
from sentinel.module2 import ModuleTwo
from sentinel.pipeline import SentinelPipeline
from sentinel.profiles import PROFILES


def _counting_runtime(tmp_path: Path, candidate) -> tuple[DeepAgentsRuntime, list[str]]:
    runtime = DeepAgentsRuntime("google_genai:gemini-2.5-flash", stage_cache_root=tmp_path)
    calls: list[str] = []

    def invoke(agent, payload, stage):
        calls.append(stage)
        return {
            "structured_response": SecurityReviewProposal(
                candidate_id="C000001",
                primary_asset_id=candidate.asset_id,
                vulnerability_id=candidate.vulnerability_id,
                status=VerificationStatus.INCONCLUSIVE,
                supporting_evidence_refs=(),
                contradictory_evidence_refs=(),
                related_nodes=(),
                criticality="unknown",
                criticality_basis="b",
                relationship_explanation="r",
                assumptions=(),
                analyst_summary="s",
                specialist_reviews=(),
            ),
            "messages": [],
        }

    runtime._invoke_stage = invoke  # type: ignore[method-assign]
    return runtime, calls


def test_validated_reviews_are_cached_per_candidate_graph_and_profile(sample_graph, tmp_path):
    candidate = ModuleOne().run(sample_graph, curated_mvp_knowledge())[0]
    runtime, calls = _counting_runtime(tmp_path, candidate)
    first = runtime.review_candidate(candidate, sample_graph, profile=PROFILES["balanced"])
    again = runtime.review_candidate(candidate, sample_graph, profile=PROFILES["balanced"])
    assert len(calls) == 1, "an identical rerun must not call the model"
    assert again == first
    smaller = dataclasses.replace(PROFILES["balanced"], subagent_tool_calls=10)
    runtime.review_candidate(candidate, sample_graph, profile=smaller)
    assert len(calls) == 2, "a different review budget is a different review"


def test_invalid_reviews_are_not_cached(sample_graph, tmp_path):
    candidate = ModuleOne().run(sample_graph, curated_mvp_knowledge())[0]
    runtime, calls = _counting_runtime(tmp_path, candidate)
    original = runtime._invoke_stage

    def invalid(agent, payload, stage):
        result = original(agent, payload, stage)
        bad = result["structured_response"].model_copy(update={"vulnerability_id": "CWE-79"})
        return {**result, "structured_response": bad}

    runtime._invoke_stage = invalid  # type: ignore[method-assign]
    runtime.review_candidate(candidate, sample_graph)
    runtime.review_candidate(candidate, sample_graph)
    assert len(calls) == 2
    assert not list(tmp_path.glob("*/output.json"))


def test_finding_ids_are_stable_across_reruns(sample_graph):
    candidate = ModuleOne().run(sample_graph, curated_mvp_knowledge())[0]

    class Runtime:
        is_deepagents = True

        def review_candidate(self, candidate, graph, **_):
            raise RuntimeError("provider down")

    first = ModuleTwo(Runtime()).run((candidate,), sample_graph)  # type: ignore[arg-type]
    second = ModuleTwo(Runtime()).run((candidate,), sample_graph)  # type: ignore[arg-type]
    assert first[0].finding_id == second[0].finding_id


def test_graph_checkpoint_key_tracks_the_full_profile_and_records_provenance(
    sample_graph, tmp_path
):
    class Runtime:
        model = "test:agent"
        is_deepagents = True

    pipeline = SentinelPipeline(runtime=Runtime(), agent_cache_root=tmp_path)  # type: ignore[arg-type]
    balanced = PROFILES["balanced"]
    smaller = dataclasses.replace(balanced, specialist_tool_calls=18)
    assert pipeline._agent_graph_checkpoint(sample_graph, balanced) != (
        pipeline._agent_graph_checkpoint(sample_graph, smaller)
    )
    pipeline._save_agent_graph_checkpoint(sample_graph, sample_graph, smaller)
    payload = json.loads(
        pipeline._agent_graph_checkpoint(sample_graph, smaller).read_text(encoding="utf-8")
    )
    assert payload["built_with_profile"]["specialist_tool_calls"] == 18
    assert pipeline._load_agent_graph_checkpoint(sample_graph, balanced) is None
    assert pipeline._load_agent_graph_checkpoint(sample_graph, smaller) is not None


def test_parallel_map_keeps_order_and_telemetry_context():
    import threading

    from sentinel.telemetry import RunTelemetry, collecting, emit, parallel_map

    telemetry = RunTelemetry()
    threads: set[int] = set()

    def work(item: int) -> int:
        threads.add(threading.get_ident())
        emit("validated", f"stage-{item}")
        return item * 2

    with collecting(telemetry):
        assert parallel_map(work, range(12), 6) == [item * 2 for item in range(12)]
    _, events = telemetry.snapshot()
    assert sorted(event.stage for event in events) == sorted(f"stage-{i}" for i in range(12))
    assert len(threads) > 1


def test_concurrency_and_review_budgets_do_not_invalidate_discovery_caches(sample_graph, tmp_path):
    balanced = PROFILES["balanced"]
    faster = dataclasses.replace(balanced, review_concurrency=1, partition_concurrency=1)
    assert faster.discovery_identity() == balanced.discovery_identity()
    assert faster.review_identity() == balanced.review_identity()
    deeper = dataclasses.replace(balanced, subagent_tool_calls=10)
    assert deeper.discovery_identity() == balanced.discovery_identity()
    assert deeper.review_identity() != balanced.review_identity()

    class Runtime:
        model = "test:agent"
        is_deepagents = True

    pipeline = SentinelPipeline(runtime=Runtime(), agent_cache_root=tmp_path)  # type: ignore[arg-type]
    assert pipeline._agent_graph_checkpoint(sample_graph, balanced) == (
        pipeline._agent_graph_checkpoint(sample_graph, deeper)
    )
