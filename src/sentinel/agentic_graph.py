from __future__ import annotations

import hashlib
import json

from sentinel.agents.runtime import SemanticRuntime
from sentinel.contracts import (
    AssetEdge,
    RepositoryAssetGraph,
    RepositoryGraphAgentOutput,
    UnresolvedReference,
)


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

    def run(self, observations: RepositoryAssetGraph) -> RepositoryAssetGraph:
        proposal = self.runtime.build_repository_graph(observations)
        return self._materialize(proposal, observations)

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
