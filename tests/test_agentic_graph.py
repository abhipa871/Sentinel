import pytest

from sentinel.agentic_graph import (
    AgenticRepositoryGraphBuilder,
    InvalidRepositoryGraphAgentOutput,
)
from sentinel.contracts import (
    RepositoryGraphAgentOutput,
    RepositoryGraphAssetAnnotation,
    RepositoryGraphEdgeProposal,
)
from sentinel.pipeline import SentinelPipeline


def _proposal(sample_graph, *, evidence_refs=None):
    edge = sample_graph.edges[0]
    source = next(asset for asset in sample_graph.assets if asset.asset_id == edge.source_asset_id)
    target = next(asset for asset in sample_graph.assets if asset.asset_id == edge.target_asset_id)
    refs = evidence_refs if evidence_refs is not None else edge.evidence_refs
    return RepositoryGraphAgentOutput(
        asset_annotations=(
            RepositoryGraphAssetAnnotation(
                asset_id=source.asset_id,
                file_role="service source",
                node_priority=0.8,
                security_relevance="Contains an observed repository relationship.",
                evidence_refs=(source.evidence_refs[0],),
            ),
        ),
        edges=(
            RepositoryGraphEdgeProposal(
                source_asset_id=source.asset_id,
                target_asset_id=target.asset_id,
                edge_type=edge.edge_type,
                confidence="high",
                resolution_basis="agent reviewed parser hint against source evidence",
                source_location=edge.source_location,
                target_location=edge.target_location,
                evidence_refs=refs,
            ),
        ),
        unresolved=(),
        analyzed_asset_ids=(source.asset_id, target.asset_id),
        coverage_warnings=("Only a bounded fixture corridor was reviewed.",),
        summary="AI-reviewed fixture repository graph.",
        specialist_reviews=(
            "repository-scan",
            "dependency-graph-building",
            "graph-review",
        ),
    )


def test_agent_owns_materialized_repository_edges(sample_graph):
    graph = AgenticRepositoryGraphBuilder._materialize(_proposal(sample_graph), sample_graph)
    assert len(graph.edges) == 1
    assert graph.edges[0].resolution_method.startswith("deepagents:")
    annotated = next(
        asset for asset in graph.assets if asset.asset_id == graph.edges[0].source_asset_id
    )
    assert annotated.features["agent_graph"]["review_status"] == "agent_reviewed"
    assert graph.snapshot.partial is True


def test_agent_graph_rejects_invented_evidence(sample_graph):
    with pytest.raises(InvalidRepositoryGraphAgentOutput, match="evidence"):
        AgenticRepositoryGraphBuilder._materialize(
            _proposal(sample_graph, evidence_refs=("invented",)), sample_graph
        )


def test_agent_graph_canonicalizes_locations_from_observed_evidence(sample_graph):
    proposal = _proposal(sample_graph)
    proposal = proposal.model_copy(
        update={
            "edges": (
                proposal.edges[0].model_copy(
                    update={
                        "source_location": "wrong/source.py:999",
                        "target_location": "wrong/target.py",
                    }
                ),
            )
        }
    )
    graph = AgenticRepositoryGraphBuilder._materialize(proposal, sample_graph)
    source = next(
        asset for asset in graph.assets if asset.asset_id == graph.edges[0].source_asset_id
    )
    target = next(
        asset for asset in graph.assets if asset.asset_id == graph.edges[0].target_asset_id
    )
    assert graph.edges[0].source_location.startswith(source.path)
    assert graph.edges[0].target_location == target.path


def test_agent_graph_binds_annotations_to_canonical_asset_evidence(sample_graph):
    proposal = _proposal(sample_graph)
    proposal = proposal.model_copy(
        update={
            "asset_annotations": (
                proposal.asset_annotations[0].model_copy(
                    update={"evidence_refs": ("model-miscopied-evidence-id",)}
                ),
            ),
            "analyzed_asset_ids": ("model-miscopied-coverage-id",),
        }
    )
    graph = AgenticRepositoryGraphBuilder._materialize(proposal, sample_graph)
    annotated = next(
        asset for asset in graph.assets if asset.asset_id == proposal.asset_annotations[0].asset_id
    )
    assert annotated.features["agent_graph"]["evidence_refs"] == list(annotated.evidence_refs)


def test_completed_agent_graph_stage_is_checkpointed(sample_graph, tmp_path):
    class Runtime:
        model = "test:agent"
        is_deepagents = True

    graph = AgenticRepositoryGraphBuilder._materialize(_proposal(sample_graph), sample_graph)
    pipeline = SentinelPipeline(runtime=Runtime(), agent_cache_root=tmp_path)  # type: ignore[arg-type]
    pipeline._save_agent_graph_checkpoint(sample_graph, graph)
    restored = pipeline._load_agent_graph_checkpoint(sample_graph)
    assert restored is not None
    assert restored.digest == graph.digest
