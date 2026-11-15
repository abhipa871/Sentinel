from __future__ import annotations

import gzip
import json
from importlib import resources
from pathlib import Path

from sentinel.contracts import KnowledgeEntity, KnowledgeGraphSnapshot, KnowledgeRelation
from sentinel.knowledge_etl import graph_digest

RESOURCE_PACKAGE = "sentinel.knowledge_data"
RESOURCE_NAME = "gv_predefined.json.gz"


def dump_predefined_graph(graph: KnowledgeGraphSnapshot, destination: Path) -> None:
    """Write a deterministic compressed G_V snapshot."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        graph.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    ).encode()
    with (
        destination.open("wb") as stream,
        gzip.GzipFile(fileobj=stream, mode="wb", mtime=0) as compressed,
    ):
        compressed.write(payload)


def load_predefined_graph(path: Path | None = None) -> KnowledgeGraphSnapshot:
    """Load G_V and fail closed if its canonical digest does not match."""

    if path is None:
        resource = resources.files(RESOURCE_PACKAGE).joinpath(RESOURCE_NAME)
        with resource.open("rb") as stream:
            payload = gzip.decompress(stream.read())
    else:
        payload = gzip.decompress(path.read_bytes())
    graph = KnowledgeGraphSnapshot.model_validate_json(payload)
    actual = graph_digest(
        graph.entities, graph.relations, graph.source_manifest, graph.parser_version
    )
    if actual != graph.digest:
        raise ValueError("predefined vulnerability graph digest mismatch")
    return graph


class KnowledgeGraphIndex:
    """Small immutable lookup index for Module I/II knowledge enrichment."""

    def __init__(self, graph: KnowledgeGraphSnapshot) -> None:
        self.graph = graph
        self.entities = {entity.entity_id: entity for entity in graph.entities}
        self.outgoing: dict[str, list[KnowledgeRelation]] = {}
        self.incoming: dict[str, list[KnowledgeRelation]] = {}
        for relation in graph.relations:
            self.outgoing.setdefault(relation.source_id, []).append(relation)
            self.incoming.setdefault(relation.target_id, []).append(relation)

    def entity(self, entity_id: str) -> KnowledgeEntity | None:
        return self.entities.get(entity_id)

    def owasp_api_risks(self, entity_id: str) -> tuple[KnowledgeEntity, ...]:
        """OWASP API Top 10 risks that cite this entity, or the entity itself if it is one."""
        entity = self.entities.get(entity_id)
        if entity is not None and entity.entity_type == "OWASP_API_RISK":
            return (entity,)
        risks = {
            relation.source_id: self.entities[relation.source_id]
            for relation in self.incoming.get(entity_id, [])
            if relation.relation_type == "REFERENCES_WEAKNESS"
            and relation.source_id in self.entities
            and self.entities[relation.source_id].entity_type == "OWASP_API_RISK"
        }
        return tuple(
            sorted(risks.values(), key=lambda risk: int(risk.metadata.get("rank", 0) or 0))
        )

    def neighborhood(self, entity_id: str, *, limit: int = 50) -> tuple[KnowledgeRelation, ...]:
        rows = self.outgoing.get(entity_id, []) + self.incoming.get(entity_id, [])
        return tuple(
            sorted(
                rows,
                key=lambda row: (row.relation_type, row.source_id, row.target_id),
            )[:limit]
        )
