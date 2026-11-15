from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid5

from sentinel.contracts import KnowledgeEntity, KnowledgeGraphSnapshot, KnowledgeRelation
from sentinel.knowledge_etl import graph_digest
from sentinel.phase0 import NAMESPACE

CWE_ID = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)


def _english(values: Any) -> str | None:
    if not isinstance(values, list):
        return None
    for item in values:
        if isinstance(item, dict) and item.get("lang", "").lower().startswith("en"):
            return str(item.get("value")) if item.get("value") else None
    return None


def _product_id(vendor: str, product: str) -> str:
    digest = hashlib.sha256(f"{vendor.casefold()}\0{product.casefold()}".encode()).hexdigest()[:20]
    return f"PRODUCT:{digest}"


def extend_with_targeted_cves(
    base: KnowledgeGraphSnapshot,
    records: Iterable[dict[str, Any]],
    *,
    source_url: str,
    source_version: str,
    retrieved_at: datetime | None = None,
) -> KnowledgeGraphSnapshot:
    """Add selected CVE List v5 records without creating CVE-to-CVE chain edges."""

    entities = {entity.entity_id: entity for entity in base.entities}
    relations = list(base.relations)
    canonical_records = sorted(
        records, key=lambda row: str(row.get("cveMetadata", {}).get("cveId", ""))
    )
    serialized_records = json.dumps(
        canonical_records, sort_keys=True, separators=(",", ":")
    ).encode()
    for record in canonical_records:
        metadata = record.get("cveMetadata", {})
        cve_id = str(metadata.get("cveId") or "").upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            raise ValueError(f"invalid targeted CVE record ID: {cve_id!r}")
        containers = record.get("containers", {})
        cna = containers.get("cna", {}) if isinstance(containers, dict) else {}
        title = str(cna.get("title") or cve_id)
        entities[cve_id] = KnowledgeEntity(
            entity_id=cve_id,
            entity_type="CVE",
            name=title,
            description=_english(cna.get("descriptions")),
            raw_id=cve_id,
            status=str(metadata.get("state")) if metadata.get("state") else None,
            metadata={
                "date_published": metadata.get("datePublished"),
                "date_updated": metadata.get("dateUpdated"),
                "assigner": metadata.get("assignerShortName"),
            },
            source_system="CVE List V5",
            source_version=source_version,
        )
        cwe_ids: set[str] = set()
        for problem_type in cna.get("problemTypes", []):
            if not isinstance(problem_type, dict):
                continue
            for description in problem_type.get("descriptions", []):
                if not isinstance(description, dict):
                    continue
                if raw := description.get("cweId"):
                    cwe_ids.update(match.upper() for match in CWE_ID.findall(str(raw)))
                if raw := description.get("description"):
                    cwe_ids.update(match.upper() for match in CWE_ID.findall(str(raw)))
        for cwe_id in sorted(cwe_ids):
            if cwe_id not in entities:
                entities[cwe_id] = KnowledgeEntity(
                    entity_id=cwe_id,
                    entity_type="CWE",
                    name=f"{cwe_id} targeted CVE reference",
                    raw_id=cwe_id.removeprefix("CWE-"),
                    metadata={"catalog_kind": "reference_only"},
                    source_system="CVE List V5",
                    source_version=source_version,
                )
            relations.append(
                KnowledgeRelation(
                    source_id=cve_id,
                    relation_type="MAPPED_TO_WEAKNESS",
                    target_id=cwe_id,
                    source_system="CVE List V5",
                    source_version=source_version,
                )
            )
        for affected in cna.get("affected", []):
            if not isinstance(affected, dict):
                continue
            vendor = str(affected.get("vendor") or "unknown")
            product = str(affected.get("product") or "unknown")
            product_id = _product_id(vendor, product)
            entities[product_id] = KnowledgeEntity(
                entity_id=product_id,
                entity_type="PRODUCT",
                name=f"{vendor} / {product}",
                raw_id=product_id.removeprefix("PRODUCT:"),
                metadata={"vendor": vendor, "product": product},
                source_system="CVE List V5",
                source_version=source_version,
            )
            relations.append(
                KnowledgeRelation(
                    source_id=cve_id,
                    relation_type="AFFECTS_PRODUCT",
                    target_id=product_id,
                    metadata={
                        "versions": affected.get("versions", []),
                        "default_status": affected.get("defaultStatus"),
                        "platforms": affected.get("platforms", []),
                    },
                    source_system="CVE List V5",
                    source_version=source_version,
                )
            )
    entity_rows = tuple(sorted(entities.values(), key=lambda row: row.entity_id))
    relation_rows = tuple(
        sorted(
            {
                (
                    row.source_id,
                    row.relation_type,
                    row.target_id,
                    json.dumps(row.metadata, sort_keys=True, separators=(",", ":")),
                ): row
                for row in relations
            }.values(),
            key=lambda row: (row.source_id, row.relation_type, row.target_id),
        )
    )
    manifest = {
        **base.source_manifest,
        f"cve-targeted:{source_version}": (
            f"{source_url}#sha256={hashlib.sha256(serialized_records).hexdigest()}"
        ),
    }
    digest = graph_digest(entity_rows, relation_rows, manifest)
    entity_counts = Counter(row.entity_type for row in entity_rows)
    relation_counts = Counter(row.relation_type for row in relation_rows)
    return KnowledgeGraphSnapshot(
        kb_snapshot_id=uuid5(NAMESPACE, f"kb-etl:{digest}"),
        version=f"{base.version}+cve-targeted:{source_version}",
        graph_schema_version=base.graph_schema_version,
        parser_version=base.parser_version,
        entities=entity_rows,
        relations=relation_rows,
        source_manifest=manifest,
        statistics={
            "entities_total": len(entity_rows),
            "relations_total": len(relation_rows),
            **{f"entity:{key}": value for key, value in sorted(entity_counts.items())},
            **{f"relation:{key}": value for key, value in sorted(relation_counts.items())},
        },
        digest=digest,
        created_at=retrieved_at or datetime.now(UTC),
    )
