from __future__ import annotations

import hashlib
import json

from sentinel.agents.runtime import ContractRepairFailed, SemanticRuntime
from sentinel.contracts import (
    AssetEdge,
    RepositoryAssetGraph,
    RepositoryGraphAgentOutput,
    UnresolvedReference,
)
from sentinel.partitions import Partition
from sentinel.profiles import ScanProfile
from sentinel.telemetry import emit, parallel_map


class InvalidRepositoryGraphAgentOutput(ValueError):
    pass


def _stable_id(prefix: str, *parts: object) -> str:
    material = ":".join(str(part) for part in parts)
    return f"{prefix}:{hashlib.sha256(material.encode()).hexdigest()}"


class AgenticRepositoryGraphBuilder:
    """Materialize a DeepAgents-selected graph without adding semantic relationships."""

    def __init__(self, runtime: SemanticRuntime) -> None:
        if not runtime.is_deepagents:
            raise TypeError("repository graph construction requires a Deep Agents runtime")
        self.runtime = runtime

    def run(
        self,
        observations: RepositoryAssetGraph,
        *,
        partitions: tuple[Partition, ...] | None = None,
        profile: ScanProfile | None = None,
    ) -> RepositoryAssetGraph:
        if not partitions:
            proposal = self.runtime.build_repository_graph(observations, profile=profile)
        else:
            proposal = self.merge(
                tuple(
                    parallel_map(
                        lambda partition: self._build_or_fail_closed(
                            observations, partition, profile
                        ),
                        partitions,
                        profile.partition_concurrency if profile else 1,
                    )
                ),
                tuple(partition.partition_id for partition in partitions),
            )
        return self._materialize(proposal, observations)

    def _build_or_fail_closed(
        self,
        observations: RepositoryAssetGraph,
        partition: Partition,
        profile: ScanProfile | None,
    ) -> RepositoryGraphAgentOutput:
        """One partition's graph; an unrecoverable contract failure fails closed for it only."""
        try:
            return self.runtime.build_repository_graph(
                observations, focus=partition, profile=profile
            )
        except ContractRepairFailed as exc:
            emit("partition_failed_closed", f"graph[{partition.partition_id}]", str(exc))
            return RepositoryGraphAgentOutput(
                asset_annotations=(),
                edges=(),
                unresolved=(),
                analyzed_asset_ids=(),
                coverage_warnings=(
                    "partition graph not built: its output failed contract validation after "
                    f"repair and salvage ({exc}); its assets are unannotated and its parser hints "
                    "are excluded",
                ),
                summary="Partition graph not built (failed closed).",
                specialist_reviews=(),
            )

    @staticmethod
    def merge(
        outputs: tuple[RepositoryGraphAgentOutput, ...], partition_ids: tuple[str, ...]
    ) -> RepositoryGraphAgentOutput:
        """Combine disjoint per-partition proposals; no relationship is added or dropped."""
        return RepositoryGraphAgentOutput(
            asset_annotations=tuple(
                item for output in outputs for item in output.asset_annotations
            ),
            edges=tuple(item for output in outputs for item in output.edges),
            unresolved=tuple(item for output in outputs for item in output.unresolved),
            analyzed_asset_ids=tuple(
                dict.fromkeys(item for output in outputs for item in output.analyzed_asset_ids)
            ),
            coverage_warnings=tuple(
                dict.fromkeys(
                    f"[{partition_id}] {warning}"
                    for partition_id, output in zip(partition_ids, outputs, strict=True)
                    for warning in output.coverage_warnings
                )
            ),
            summary=" ".join(
                f"[{partition_id}] {output.summary}"
                for partition_id, output in zip(partition_ids, outputs, strict=True)
            ),
            specialist_reviews=tuple(
                dict.fromkeys(item for output in outputs for item in output.specialist_reviews)
            ),
            accepted_hint_refs=tuple(
                dict.fromkeys(item for output in outputs for item in output.accepted_hint_refs)
            ),
            rejected_hints=tuple(item for output in outputs for item in output.rejected_hints),
        )

    @staticmethod
    def _materialize(
        proposal: RepositoryGraphAgentOutput,
        observations: RepositoryAssetGraph,
    ) -> RepositoryAssetGraph:
        required_reviews = {"repository-scan", "dependency-graph-building", "graph-review"}
        if not required_reviews <= set(proposal.specialist_reviews):
            raise InvalidRepositoryGraphAgentOutput(
                "graph specialist/reviewer coverage is incomplete"
            )
        assets = {asset.asset_id: asset for asset in observations.assets}
        evidence = {item.evidence_id: item for item in observations.evidence}
        evidence_ids = set(evidence)

        annotations = {}
        for asset_annotation in proposal.asset_annotations:
            if asset_annotation.asset_id not in assets:
                raise InvalidRepositoryGraphAgentOutput("annotation references an unknown asset")
            if asset_annotation.asset_id in annotations:
                raise InvalidRepositoryGraphAgentOutput("duplicate agent asset annotation")
            annotations[asset_annotation.asset_id] = asset_annotation

        materialized_assets = []
        for asset in observations.assets:
            annotation = annotations.get(asset.asset_id)
            features = dict(asset.features)
            if annotation is None:
                features["agent_graph"] = {
                    "review_status": "not_individually_annotated",
                    "file_role": None,
                    "node_priority": None,
                    "security_relevance": None,
                    "evidence_refs": [],
                }
            else:
                canonical_evidence_refs = tuple(
                    dict.fromkeys(
                        (
                            *(
                                evidence_id
                                for evidence_id in annotation.evidence_refs
                                if evidence_id in evidence_ids
                            ),
                            *asset.evidence_refs,
                        )
                    )
                )
                features["agent_graph"] = {
                    "review_status": "agent_reviewed",
                    "file_role": annotation.file_role,
                    "node_priority": annotation.node_priority,
                    "security_relevance": annotation.security_relevance,
                    "evidence_refs": list(canonical_evidence_refs),
                }
            materialized_assets.append(asset.model_copy(update={"features": features}))

        edges: list[AssetEdge] = []
        seen_edges: set[tuple[str, str, str, str]] = set()
        for edge in proposal.edges:
            if edge.source_asset_id not in assets or edge.target_asset_id not in assets:
                raise InvalidRepositoryGraphAgentOutput("edge references an unknown asset")
            if edge.source_asset_id == edge.target_asset_id:
                raise InvalidRepositoryGraphAgentOutput("self-referential repository edge")
            if not edge.evidence_refs or not set(edge.evidence_refs) <= evidence_ids:
                raise InvalidRepositoryGraphAgentOutput("edge lacks valid observed evidence")
            source = assets[edge.source_asset_id]
            target = assets[edge.target_asset_id]
            supporting = [
                evidence[evidence_id]
                for evidence_id in edge.evidence_refs
                if evidence[evidence_id].source_path == source.path
            ]
            if not supporting:
                raise InvalidRepositoryGraphAgentOutput(
                    "edge evidence is not sourced from the source asset"
                )
            location_evidence = min(
                supporting,
                key=lambda item: (item.start_line is None, item.start_line or 0, item.evidence_id),
            )
            source_location = source.path
            if location_evidence.start_line is not None:
                source_location = f"{source.path}:{location_evidence.start_line}"
            target_location = target.path
            key = (
                edge.source_asset_id,
                edge.edge_type.value,
                edge.target_asset_id,
                source_location,
            )
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append(
                AssetEdge(
                    snapshot_id=observations.snapshot.snapshot_id,
                    edge_id=_stable_id("agent-edge", observations.snapshot.snapshot_id, *key),
                    source_asset_id=edge.source_asset_id,
                    target_asset_id=edge.target_asset_id,
                    edge_type=edge.edge_type,
                    confidence=edge.confidence,
                    resolution_method=f"deepagents:{edge.resolution_basis}",
                    source_location=source_location,
                    target_location=target_location,
                    evidence_refs=edge.evidence_refs,
                    is_dynamic_unknown=edge.is_dynamic_unknown,
                )
            )

        # Parser hints the agent accepted by handle keep their observed evidence and location.
        observed_edges = {edge.edge_id: edge for edge in observations.edges}
        rejected = {row.hint_ref for row in proposal.rejected_hints}
        for hint_ref in proposal.accepted_hint_refs:
            hint = observed_edges.get(hint_ref)
            if hint is None:
                raise InvalidRepositoryGraphAgentOutput("accepted hint is not a parser edge")
            if hint_ref in rejected:
                raise InvalidRepositoryGraphAgentOutput("hint is both accepted and rejected")
            key = (
                hint.source_asset_id,
                hint.edge_type.value,
                hint.target_asset_id,
                hint.source_location,
            )
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append(
                hint.model_copy(
                    update={
                        "edge_id": _stable_id(
                            "agent-edge", observations.snapshot.snapshot_id, *key
                        ),
                        "resolution_method": (
                            f"deepagents:accepted_parser_hint:{hint.resolution_method}"
                        ),
                    }
                )
            )
        if rejected - set(observed_edges):
            raise InvalidRepositoryGraphAgentOutput("rejected hint is not a parser edge")

        unresolved = []
        for row in proposal.unresolved:
            if row.source_asset_id not in assets:
                raise InvalidRepositoryGraphAgentOutput("unresolved reference has unknown source")
            unresolved.append(
                UnresolvedReference(
                    snapshot_id=observations.snapshot.snapshot_id,
                    source_asset_id=row.source_asset_id,
                    reference=row.reference,
                    kind=row.kind,
                    location=row.location,
                    reason=f"deepagents:{row.reason}",
                )
            )
        snapshot = observations.snapshot.model_copy(
            update={
                "partial": observations.snapshot.partial or bool(proposal.coverage_warnings),
                "warnings": tuple(
                    dict.fromkeys(
                        (
                            *observations.snapshot.warnings,
                            *proposal.coverage_warnings,
                            (
                                f"Deep Agents individually annotated {len(annotations)} of "
                                f"{len(assets)} assets"
                            ),
                            (
                                f"Deep Agents accepted {len(proposal.accepted_hint_refs)} and "
                                f"rejected {len(rejected)} of {len(observations.edges)} parser "
                                "edge hints"
                            ),
                        )
                    )
                ),
            }
        )
        sorted_assets = tuple(sorted(materialized_assets, key=lambda item: item.path))
        sorted_edges = tuple(
            sorted(
                edges, key=lambda item: (item.source_asset_id, item.edge_type, item.target_asset_id)
            )
        )
        sorted_unresolved = tuple(
            sorted(
                unresolved, key=lambda item: (item.source_asset_id, item.location, item.reference)
            )
        )
        material = {
            "snapshot_id": str(snapshot.snapshot_id),
            "assets": [item.model_dump(mode="json") for item in sorted_assets],
            "edges": [item.model_dump(mode="json") for item in sorted_edges],
            "unresolved": [item.model_dump(mode="json") for item in sorted_unresolved],
            "agent_summary": proposal.summary,
            "specialist_reviews": proposal.specialist_reviews,
        }
        digest = hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return RepositoryAssetGraph(
            snapshot=snapshot,
            assets=sorted_assets,
            edges=sorted_edges,
            unresolved=sorted_unresolved,
            evidence=observations.evidence,
            digest=digest,
        )
