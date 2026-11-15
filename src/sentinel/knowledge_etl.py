from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid5

import yaml
from defusedxml import ElementTree

from sentinel.contracts import KnowledgeEntity, KnowledgeGraphSnapshot, KnowledgeRelation
from sentinel.phase0 import NAMESPACE

PARSER_VERSION = "sentinel-gv-etl-v2"
CatalogName = Literal["cwe", "capec", "atlas", "d3fend"]


@dataclass(frozen=True)
class CatalogArtifact:
    catalog: CatalogName
    version: str
    source_url: str
    content: bytes
    retrieved_at: datetime
    expected_sha256: str | None = None
    container_sha256: str | None = None
    member_name: str | None = None

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    def verify(self) -> None:
        if self.expected_sha256 and self.sha256 != self.expected_sha256.lower():
            raise ValueError(f"{self.catalog} checksum mismatch")
        if len(self.content) > 100_000_000:
            raise ValueError(f"{self.catalog} artifact exceeds ETL policy")


def _text(element: Any | None) -> str | None:
    if element is None:
        return None
    value = " ".join(" ".join(element.itertext()).split())
    return value or None


def _metadata(**values: Any) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value not in (None, "", [], {})}


def _mitigation(
    owner: str,
    description: str,
    system: str,
    version: str,
    **metadata: Any,
) -> tuple[KnowledgeEntity, KnowledgeRelation]:
    description = " ".join(description.split())
    digest = hashlib.sha256(
        json.dumps(
            {"system": system, "description": description, "metadata": metadata},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()[:20]
    entity_id = f"MITIGATION:{system.upper().replace(' ', '_')}:{digest}"
    entity = KnowledgeEntity(
        entity_id=entity_id,
        entity_type="MITIGATION",
        name=description.split(". ", 1)[0][:120],
        description=description,
        raw_id=digest,
        metadata=_metadata(**metadata),
        source_system=system,
        source_version=version,
    )
    relation = KnowledgeRelation(
        source_id=owner,
        relation_type="MITIGATED_BY",
        target_id=entity_id,
        source_system=system,
        source_version=version,
    )
    return entity, relation


def parse_cwe(artifact: CatalogArtifact) -> tuple[list[KnowledgeEntity], list[KnowledgeRelation]]:
    root = ElementTree.fromstring(artifact.content)
    entities: list[KnowledgeEntity] = []
    relations: list[KnowledgeRelation] = []
    nature_map = {
        "ChildOf": "CHILD_OF",
        "CanPrecede": "CAN_PRECEDE",
        "Requires": "REQUIRES",
        "PeerOf": "PEER_OF",
        "MemberOf": "MEMBER_OF",
    }
    for kind in ("Weakness", "View"):
        for item in root.findall(f".//{{*}}{kind}"):
            raw_id = item.attrib.get("ID")
            if not raw_id:
                continue
            entity_id = f"CWE-{raw_id}"
            entities.append(
                KnowledgeEntity(
                    entity_id=entity_id,
                    entity_type="CWE",
                    name=item.attrib.get("Name", entity_id),
                    description=_text(item.find("{*}Description"))
                    or _text(item.find("{*}Objective")),
                    raw_id=raw_id,
                    status=item.attrib.get("Status"),
                    metadata=_metadata(
                        catalog_kind=kind.lower(),
                        abstraction=item.attrib.get("Abstraction"),
                        structure=item.attrib.get("Structure"),
                    ),
                    source_system="MITRE CWE",
                    source_version=artifact.version,
                )
            )
            if kind == "View":
                for member in item.findall(".//{*}Has_Member"):
                    if target := member.attrib.get("CWE_ID"):
                        relations.append(
                            KnowledgeRelation(
                                source_id=f"CWE-{target}",
                                relation_type="MEMBER_OF",
                                target_id=entity_id,
                                source_ref=raw_id,
                                source_system="MITRE CWE",
                                source_version=artifact.version,
                            )
                        )
                continue
            for related in item.findall(".//{*}Related_Weakness"):
                target, nature = related.attrib.get("CWE_ID"), related.attrib.get("Nature")
                if target and nature in nature_map:
                    relations.append(
                        KnowledgeRelation(
                            source_id=entity_id,
                            relation_type=nature_map[nature],
                            target_id=f"CWE-{target}",
                            source_ref=related.attrib.get("View_ID"),
                            metadata=_metadata(
                                view_id=related.attrib.get("View_ID"),
                                ordinal=related.attrib.get("Ordinal"),
                            ),
                            source_system="MITRE CWE",
                            source_version=artifact.version,
                        )
                    )
            for item_mitigation in item.findall(".//{*}Potential_Mitigations/{*}Mitigation"):
                if description := _text(item_mitigation.find("{*}Description")):
                    phases = tuple(
                        phase
                        for element in item_mitigation.findall(".//{*}Mitigation_Phase/{*}Phase")
                        if (phase := _text(element))
                    )
                    entity, relation = _mitigation(
                        entity_id,
                        description,
                        "MITRE CWE",
                        artifact.version,
                        phases=phases,
                    )
                    entities.append(entity)
                    relations.append(relation)
    return entities, relations


def parse_capec(
    artifact: CatalogArtifact,
) -> tuple[list[KnowledgeEntity], list[KnowledgeRelation]]:
    root = ElementTree.fromstring(artifact.content)
    entities: list[KnowledgeEntity] = []
    relations: list[KnowledgeRelation] = []
    nature_map = {"ChildOf": "CHILD_OF", "CanPrecede": "CAN_PRECEDE"}
    for kind in ("Attack_Pattern", "Category", "View"):
        for item in root.findall(f".//{{*}}{kind}"):
            raw_id = item.attrib.get("ID")
            if not raw_id:
                continue
            entity_id = f"CAPEC-{raw_id}"
            entities.append(
                KnowledgeEntity(
                    entity_id=entity_id,
                    entity_type="CAPEC",
                    name=item.attrib.get("Name", entity_id),
                    description=_text(item.find("{*}Description"))
                    or _text(item.find("{*}Objective")),
                    raw_id=raw_id,
                    status=item.attrib.get("Status"),
                    metadata=_metadata(
                        catalog_kind=kind.lower(),
                        abstraction=item.attrib.get("Abstraction"),
                        likelihood=_text(item.find("{*}Likelihood_Of_Attack")),
                        severity=_text(item.find("{*}Typical_Severity")),
                    ),
                    source_system="MITRE CAPEC",
                    source_version=artifact.version,
                )
            )
            if kind != "Attack_Pattern":
                for member in item.findall(".//{*}Has_Member"):
                    if target := member.attrib.get("CAPEC_ID"):
                        relations.append(
                            KnowledgeRelation(
                                source_id=f"CAPEC-{target}",
                                relation_type="MEMBER_OF",
                                target_id=entity_id,
                                source_ref=raw_id,
                                source_system="MITRE CAPEC",
                                source_version=artifact.version,
                            )
                        )
                continue
            for related in item.findall(".//{*}Related_Weakness"):
                if target := related.attrib.get("CWE_ID"):
                    relations.append(
                        KnowledgeRelation(
                            source_id=entity_id,
                            relation_type="EXPLOITS_WEAKNESS",
                            target_id=f"CWE-{target}",
                            source_system="MITRE CAPEC",
                            source_version=artifact.version,
                        )
                    )
            for related in item.findall(".//{*}Related_Attack_Pattern"):
                target = related.attrib.get("CAPEC_ID")
                nature = related.attrib.get("Nature")
                if target and nature in nature_map:
                    relations.append(
                        KnowledgeRelation(
                            source_id=entity_id,
                            relation_type=nature_map[nature],
                            target_id=f"CAPEC-{target}",
                            source_system="MITRE CAPEC",
                            source_version=artifact.version,
                        )
                    )
            for item_mitigation in item.findall(".//{*}Mitigations/{*}Mitigation"):
                if description := _text(item_mitigation):
                    entity, relation = _mitigation(
                        entity_id, description, "MITRE CAPEC", artifact.version
                    )
                    entities.append(entity)
                    relations.append(relation)
    return entities, relations


def _atlas_records(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    values = data.get(key, {})
    if isinstance(values, dict):
        return [value for value in values.values() if isinstance(value, dict)]
    if isinstance(values, list):
        return [value for value in values if isinstance(value, dict)]
    raise ValueError(f"ATLAS {key} must be a mapping or list")


def _atlas_relations(data: dict[str, Any]) -> list[dict[str, Any]]:
    values = data.get("relationships", {})
    if isinstance(values, list):
        return [value for value in values if isinstance(value, dict)]
    if not isinstance(values, dict):
        raise ValueError("ATLAS relationships must be a mapping or list")
    return [
        relation
        for groups in values.values()
        if isinstance(groups, dict)
        for group in groups.values()
        if isinstance(group, list)
        for relation in group
        if isinstance(relation, dict)
    ]


def parse_atlas(
    artifact: CatalogArtifact,
) -> tuple[list[KnowledgeEntity], list[KnowledgeRelation]]:
    data = yaml.safe_load(artifact.content) or {}
    if not isinstance(data, dict):
        raise ValueError("ATLAS root must be a mapping")
    format_version = str(data.get("format-version", "legacy"))
    if format_version != "legacy" and format_version.split(".", 1)[0] != "6":
        raise ValueError(f"unsupported ATLAS format-version: {format_version}")
    entities: list[KnowledgeEntity] = []
    relations: list[KnowledgeRelation] = []
    for section, default_type in (
        ("tactics", "ATLAS_TACTIC"),
        ("techniques", "ATLAS_TECHNIQUE"),
        ("mitigations", "MITIGATION"),
        ("case-studies", "ATLAS_CASE"),
    ):
        for item in _atlas_records(data, section):
            raw_id = str(item.get("id") or "")
            if not raw_id:
                continue
            entity_type = default_type
            if section == "techniques" and raw_id.count(".") >= 2:
                entity_type = "ATLAS_SUBTECHNIQUE"
            entities.append(
                KnowledgeEntity(
                    entity_id=f"ATLAS:{raw_id}",
                    entity_type=entity_type,  # type: ignore[arg-type]
                    name=str(item.get("name") or raw_id),
                    description=str(item["description"]) if item.get("description") else None,
                    raw_id=raw_id,
                    status=str(item["status"]) if item.get("status") else None,
                    metadata=_metadata(
                        format_version=format_version,
                        platforms=item.get("platforms"),
                        maturity=item.get("maturity"),
                        created_date=item.get("created-date"),
                        modified_date=item.get("modified-date"),
                    ),
                    source_system="MITRE ATLAS",
                    source_version=artifact.version,
                )
            )
    relation_map = {
        "achieves": "TACTIC_OF",
        "specializes": "SUBTECHNIQUE_OF",
        "mitigates": "MITIGATES",
        "employs": "USES_TECHNIQUE",
    }
    for item in _atlas_relations(data):
        source = str(item.get("source") or "")
        target = str(item.get("target") or "")
        raw_type = str(item.get("relationship-type") or "")
        if source and target and raw_type in relation_map:
            relations.append(
                KnowledgeRelation(
                    source_id=f"ATLAS:{source}",
                    relation_type=relation_map[raw_type],
                    target_id=f"ATLAS:{target}",
                    source_ref=str(item.get("step-id")) if item.get("step-id") else None,
                    metadata=_metadata(
                        step_id=item.get("step-id"),
                        leads_to=item.get("leads-to"),
                        tactic=item.get("tactic"),
                        description=item.get("description"),
                    ),
                    source_system="MITRE ATLAS",
                    source_version=artifact.version,
                )
            )
    return entities, relations


def _jsonld_ids(value: Any) -> set[str]:
    values = value if isinstance(value, list) else [value]
    return {
        item["@id"]
        for item in values
        if isinstance(item, dict) and isinstance(item.get("@id"), str)
    }


def parse_d3fend(
    artifact: CatalogArtifact,
) -> tuple[list[KnowledgeEntity], list[KnowledgeRelation]]:
    data = json.loads(artifact.content)
    records = data.get("@graph") if isinstance(data, dict) else None
    if not isinstance(records, list):
        raise ValueError("D3FEND JSON-LD must contain an @graph list")
    by_iri = {
        item["@id"]: item
        for item in records
        if isinstance(item, dict) and isinstance(item.get("@id"), str)
    }
    parents = {iri: _jsonld_ids(item.get("rdfs:subClassOf", [])) for iri, item in by_iri.items()}
    descendants = {"d3f:DefensiveTechnique"}
    while True:
        expanded = descendants | {
            iri for iri, parent_ids in parents.items() if parent_ids & descendants
        }
        if expanded == descendants:
            break
        descendants = expanded

    def graph_id(iri: str) -> str:
        raw_id = by_iri.get(iri, {}).get("d3f:d3fend-id") or iri.removeprefix("d3f:")
        return f"D3FEND:{raw_id}"

    entities: list[KnowledgeEntity] = []
    relations: list[KnowledgeRelation] = []
    for iri in sorted(descendants):
        item = by_iri.get(iri, {})
        raw_id = str(item.get("d3f:d3fend-id") or iri.removeprefix("d3f:"))
        label = item.get("rdfs:label") or item.get("skos:prefLabel") or raw_id
        if isinstance(label, list):
            label = label[0] if label else raw_id
        synonyms = item.get("d3f:synonym", [])
        if not isinstance(synonyms, list):
            synonyms = [synonyms]
        entities.append(
            KnowledgeEntity(
                entity_id=graph_id(iri),
                entity_type="DEFENSIVE_TECHNIQUE",
                name=str(label),
                description=str(item["d3f:definition"]) if item.get("d3f:definition") else None,
                raw_id=raw_id,
                aliases=tuple(str(value) for value in synonyms if value),
                metadata={"iri": iri},
                source_system="MITRE D3FEND",
                source_version=artifact.version,
            )
        )
        for parent in sorted(parents.get(iri, set()) & descendants):
            relations.append(
                KnowledgeRelation(
                    source_id=graph_id(iri),
                    relation_type="CHILD_OF",
                    target_id=graph_id(parent),
                    source_ref=iri,
                    source_system="MITRE D3FEND",
                    source_version=artifact.version,
                )
            )
    return entities, relations


def graph_digest(
    entities: tuple[KnowledgeEntity, ...],
    relations: tuple[KnowledgeRelation, ...],
    manifest: dict[str, str],
) -> str:
    material = {
        "entities": [entity.model_dump(mode="json") for entity in entities],
        "relations": [relation.model_dump(mode="json") for relation in relations],
        "manifest": manifest,
        "parser_version": PARSER_VERSION,
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class KnowledgeEtl:
    def promote(self, artifacts: tuple[CatalogArtifact, ...]) -> KnowledgeGraphSnapshot:
        parsers = {
            "cwe": parse_cwe,
            "capec": parse_capec,
            "atlas": parse_atlas,
            "d3fend": parse_d3fend,
        }
        entities: dict[str, KnowledgeEntity] = {}
        relations: list[KnowledgeRelation] = []
        manifest: dict[str, str] = {}
        for artifact in artifacts:
            artifact.verify()
            parsed_entities, parsed_relations = parsers[artifact.catalog](artifact)
            for entity in parsed_entities:
                existing = entities.get(entity.entity_id)
                if existing and existing != entity:
                    raise ValueError(f"conflicting catalog entity: {entity.entity_id}")
                entities[entity.entity_id] = entity
            relations.extend(parsed_relations)
            provenance = f"{artifact.source_url}#sha256={artifact.sha256}"
            if artifact.container_sha256:
                provenance += f"&container_sha256={artifact.container_sha256}"
            if artifact.member_name:
                provenance += f"&member={artifact.member_name}"
            manifest[f"{artifact.catalog}:{artifact.version}"] = provenance
        missing = {
            endpoint
            for relation in relations
            for endpoint in (relation.source_id, relation.target_id)
            if endpoint not in entities
        }
        # Current CWE views retain official membership references to historical/category IDs
        # that are not serialized as full records in the comprehensive XML. Preserve those
        # endpoints as explicit reference-only catalog nodes rather than dropping official edges.
        cwe_version = next(
            (artifact.version for artifact in artifacts if artifact.catalog == "cwe"), "unknown"
        )
        for endpoint in sorted(missing):
            if endpoint.startswith("CWE-"):
                entities[endpoint] = KnowledgeEntity(
                    entity_id=endpoint,
                    entity_type="CWE",
                    name=f"{endpoint} reference-only catalog entry",
                    raw_id=endpoint.removeprefix("CWE-"),
                    metadata={"catalog_kind": "reference_only"},
                    source_system="MITRE CWE",
                    source_version=cwe_version,
                )
        missing = {
            endpoint
            for relation in relations
            for endpoint in (relation.source_id, relation.target_id)
            if endpoint not in entities
        }
        if missing:
            raise ValueError(
                f"catalog relations reference missing entities: {sorted(missing)[:10]}"
            )
        unique_relations = {
            (
                relation.source_id,
                relation.relation_type,
                relation.target_id,
                json.dumps(relation.metadata, sort_keys=True, separators=(",", ":")),
            ): relation
            for relation in relations
        }
        entity_rows = tuple(sorted(entities.values(), key=lambda value: value.entity_id))
        relation_rows = tuple(
            sorted(
                unique_relations.values(),
                key=lambda value: (
                    value.source_id,
                    value.relation_type,
                    value.target_id,
                    value.source_ref or "",
                ),
            )
        )
        digest = graph_digest(entity_rows, relation_rows, manifest)
        entity_counts = Counter(entity.entity_type for entity in entity_rows)
        relation_counts = Counter(relation.relation_type for relation in relation_rows)
        statistics = {
            "entities_total": len(entity_rows),
            "relations_total": len(relation_rows),
            **{f"entity:{key}": value for key, value in sorted(entity_counts.items())},
            **{f"relation:{key}": value for key, value in sorted(relation_counts.items())},
        }
        return KnowledgeGraphSnapshot(
            kb_snapshot_id=uuid5(NAMESPACE, f"kb-etl:{digest}"),
            version="+".join(sorted(manifest)),
            parser_version=PARSER_VERSION,
            entities=entity_rows,
            relations=relation_rows,
            source_manifest=manifest,
            statistics=statistics,
            digest=digest,
            created_at=max(
                (artifact.retrieved_at for artifact in artifacts), default=datetime.now(UTC)
            ),
        )
