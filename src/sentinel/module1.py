from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass
from typing import Any, Literal

from sentinel.agents.runtime import (
    MODULE_ONE_FORBIDDEN_VERDICT,
    ContractRepairFailed,
    SemanticRuntime,
)
from sentinel.contracts import (
    ApplicabilityRule,
    Asset,
    CoverageChecklistItem,
    EdgeType,
    KnowledgeGraphSnapshot,
    KnowledgeSnapshot,
    ModuleOneAgentOutput,
    PotentialVulnerabilityRow,
    RelatedAsset,
    RepositoryAssetGraph,
)
from sentinel.knowledge_graph import KnowledgeGraphIndex
from sentinel.partitions import Partition
from sentinel.profiles import ScanProfile
from sentinel.telemetry import emit, parallel_map


@dataclass(frozen=True)
class PredicateResult:
    result: Literal["match", "no_match", "unknown"]
    evidence_ids: tuple[str, ...]
    missing_conditions: tuple[str, ...]


def _feature_symbols(features: dict[str, Any]) -> set[str]:
    return {str(value) for value in features.get("api_symbols", [])}


def evaluate_rule(asset: Asset, rule: ApplicabilityRule) -> PredicateResult:
    if asset.node_type not in rule.applicable_asset_types:
        return PredicateResult("no_match", (), ())
    if rule.language_tags and asset.language not in rule.language_tags:
        return PredicateResult("no_match", (), ())
    required = rule.required_features
    symbols = _feature_symbols(asset.features)
    if expected := required.get("any_api_symbols"):
        matches = {
            symbol
            for symbol in symbols
            if any(symbol == item or symbol.endswith(f".{item}") for item in expected)
        }
        if not matches:
            return PredicateResult("no_match", (), ())
    if expected_literals := required.get("any_string_literals"):
        literals = {str(value) for value in asset.features.get("string_literals", [])}
        if not literals & set(expected_literals):
            return PredicateResult("no_match", (), ())
    if expected_values := required.get("equals"):
        for key, expected in expected_values.items():
            if key not in asset.features:
                return PredicateResult("unknown", asset.evidence_refs, (f"feature:{key}",))
            if asset.features[key] != expected:
                return PredicateResult("no_match", (), ())
    for key in required.get("nonempty", ()):
        if key not in asset.features:
            return PredicateResult("unknown", asset.evidence_refs, (f"feature:{key}",))
        if not asset.features[key]:
            return PredicateResult("no_match", (), ())
    excluded = rule.excluded_features.get("any_api_symbols", ())
    if any(symbol in symbols for symbol in excluded):
        return PredicateResult("no_match", (), ())
    return PredicateResult("match", asset.evidence_refs, ())


def _candidate_id(
    graph: RepositoryAssetGraph, kb: KnowledgeSnapshot, asset: Asset, rule_id: str
) -> str:
    value = f"{graph.snapshot.snapshot_id}:{kb.kb_snapshot_id}:{asset.asset_id}:{rule_id}"
    return f"candidate:{hashlib.sha256(value.encode()).hexdigest()}"


def _context(
    graph: RepositoryAssetGraph, asset: Asset, depth: int = 2, limit: int = 50
) -> tuple[RelatedAsset, ...]:
    assets = {item.asset_id: item for item in graph.assets}
    adjacency: dict[str, list[tuple[str, str, tuple[str, ...]]]] = {}
    # A manifest is a hub shared by every file of its project. Walking back out of it would make
    # all of those files look related, so reverse manifest edges are only followed from the
    # starting asset itself (when the anchor is the manifest).
    manifest_dependents: dict[str, list[tuple[str, str, tuple[str, ...]]]] = {}
    for edge in graph.edges:
        adjacency.setdefault(edge.source_asset_id, []).append(
            (edge.target_asset_id, edge.edge_type.value, edge.evidence_refs)
        )
        reverse = (
            manifest_dependents if edge.edge_type is EdgeType.DEPENDS_ON_MANIFEST else adjacency
        )
        reverse.setdefault(edge.target_asset_id, []).append(
            (edge.source_asset_id, edge.edge_type.value, edge.evidence_refs)
        )
    queue = deque([(asset.asset_id, 0)])
    seen = {asset.asset_id}
    results: list[RelatedAsset] = []
    while queue and len(results) < limit:
        current, distance = queue.popleft()
        if distance >= depth:
            continue
        grouped: dict[str, tuple[set[str], set[str]]] = {}
        neighbors = adjacency.get(current, [])
        if current == asset.asset_id:
            neighbors = neighbors + manifest_dependents.get(current, [])
        for target, edge_type, refs in neighbors:
            edge_types, evidence = grouped.setdefault(target, (set(), set()))
            edge_types.add(edge_type)
            evidence.update(refs)
        for target, (edge_types, evidence) in sorted(grouped.items()):
            if target in seen:
                continue
            seen.add(target)
            target_asset = assets[target]
            results.append(
                RelatedAsset(
                    asset_id=target,
                    path=target_asset.path,
                    edge_types=tuple(sorted(edge_types)),
                    graph_distance=distance + 1,
                    evidence_refs=tuple(sorted(evidence)),
                )
            )
            queue.append((target, distance + 1))
    return tuple(results)


def _priority(
    asset: Asset, rule: ApplicabilityRule, related: tuple[RelatedAsset, ...]
) -> tuple[float, dict[str, float | None]]:
    evidence_strength = rule.weight
    entrypoint = 1.0 if asset.features.get("entrypoint") else 0.3
    potential_impact = 0.7
    path_relevance = min(1.0, 0.25 + len(related) / 10)
    exploit_signal = None
    specificity = 0.9 if rule.required_features.get("any_api_symbols") else 0.65
    # Missing exploit data is represented as unknown and uses a documented conservative neutral
    # term for ranking; it is not treated as proof or an official severity score.
    exploit_term = 0.5
    score = (
        0.25 * evidence_strength
        + 0.20 * entrypoint
        + 0.20 * potential_impact
        + 0.15 * path_relevance
        + 0.10 * exploit_term
        + 0.10 * specificity
    )
    features = {
        "evidence_strength": evidence_strength,
        "entrypoint_exposure": entrypoint,
        "potential_impact": potential_impact,
        "path_relevance": path_relevance,
        "exploit_signal": exploit_signal,
        "rule_specificity": specificity,
    }
    return round(min(score, 1.0), 4), features


def _knowledge_context(vulnerability_id: str, index: KnowledgeGraphIndex | None) -> dict[str, Any]:
    if index is None:
        return {}
    entity = index.entity(vulnerability_id)
    if entity is None:
        return {"catalog_entity_found": False}
    relationships = []
    for relation in index.neighborhood(vulnerability_id, limit=25):
        other_id = (
            relation.target_id if relation.source_id == vulnerability_id else relation.source_id
        )
        other = index.entity(other_id)
        relationships.append(
            {
                "direction": "outgoing" if relation.source_id == vulnerability_id else "incoming",
                "relation_type": relation.relation_type,
                "entity_id": other_id,
                "entity_type": other.entity_type if other else None,
                "name": other.name if other else other_id,
                "source_system": relation.source_system,
            }
        )
    return {
        "catalog_entity_found": True,
        "entity_type": entity.entity_type,
        "name": entity.name,
        "description": entity.description,
        "source_system": entity.source_system,
        "source_version": entity.source_version,
        "relationships": relationships,
        # Listed explicitly: the bounded neighborhood above is sorted by relation type and can
        # truncate these official OWASP references for well-connected CWEs.
        "owasp_api_risks": [
            {"entity_id": risk.entity_id, "raw_id": risk.raw_id, "name": risk.name}
            for risk in index.owasp_api_risks(vulnerability_id)
        ],
    }


class ModuleOne:
    def run(
        self,
        graph: RepositoryAssetGraph,
        knowledge: KnowledgeSnapshot,
        *,
        vulnerability_graph: KnowledgeGraphSnapshot | None = None,
        max_candidates: int = 10_000,
        graph_depth: int = 2,
    ) -> tuple[PotentialVulnerabilityRow, ...]:
        severity = {item.vulnerability_id: item for item in knowledge.criticality}
        knowledge_index = (
            KnowledgeGraphIndex(vulnerability_graph) if vulnerability_graph is not None else None
        )
        rows: list[PotentialVulnerabilityRow] = []
        rules = sorted(knowledge.rules, key=lambda item: item.rule_id)
        for asset in graph.assets:
            for rule in rules:
                predicate = evaluate_rule(asset, rule)
                if predicate.result == "no_match":
                    continue
                related = _context(graph, asset, depth=graph_depth)
                priority, priority_features = _priority(asset, rule, related)
                signal = severity.get(rule.vulnerability_id)
                warnings = []
                if asset.parser_status.value not in {"supported_full", "supported_partial"}:
                    warnings.append(f"parser coverage: {asset.parser_status.value}")
                if predicate.result == "unknown":
                    warnings.append("required feature evidence is incomplete")
                rows.append(
                    PotentialVulnerabilityRow(
                        candidate_id=_candidate_id(graph, knowledge, asset, rule.rule_id),
                        snapshot_id=graph.snapshot.snapshot_id,
                        kb_snapshot_id=knowledge.kb_snapshot_id,
                        asset_id=asset.asset_id,
                        node=asset.path,
                        asset_type=asset.node_type,
                        vulnerability_id=rule.vulnerability_id,
                        vulnerability_name=rule.vulnerability_name,
                        hypothesis=f"{rule.vulnerability_name} may be present; Module II must test all preconditions",
                        catalog_severity=signal.catalog_severity if signal else None,
                        catalog_cvss=signal.cvss_base_score if signal else None,
                        investigation_priority=priority,
                        priority_features=priority_features,
                        related_nodes=related,
                        rule_ids=(rule.rule_id,),
                        observed_evidence_refs=predicate.evidence_ids,
                        untested_preconditions=rule.necessary_preconditions
                        + predicate.missing_conditions,
                        derivation_kind=rule.derivation_kind,
                        knowledge_context=_knowledge_context(
                            rule.vulnerability_id, knowledge_index
                        ),
                        coverage_warnings=tuple(warnings),
                    )
                )
        rows.sort(key=lambda row: (-row.investigation_priority, row.node, row.vulnerability_id))
        return tuple(rows[:max_candidates])


class InvalidModuleOneAgentOutput(ValueError):
    pass


def _agent_candidate_id(
    graph: RepositoryAssetGraph,
    knowledge: KnowledgeSnapshot,
    asset_id: str,
    vulnerability_id: str,
    hypothesis: str,
) -> str:
    normalized = " ".join(hypothesis.casefold().split())
    value = (
        f"{graph.snapshot.snapshot_id}:{knowledge.kb_snapshot_id}:{asset_id}:"
        f"{vulnerability_id}:{normalized}"
    )
    return f"candidate:{hashlib.sha256(value.encode()).hexdigest()}"


def _selected_related(
    graph: RepositoryAssetGraph, asset: Asset, selected_ids: tuple[str, ...]
) -> tuple[RelatedAsset, ...]:
    if not selected_ids:
        return ()
    available = {item.asset_id: item for item in _context(graph, asset, depth=4, limit=250)}
    missing = set(selected_ids) - set(available) - {asset.asset_id}
    if missing:
        raise InvalidModuleOneAgentOutput("agent selected unrelated or unknown asset IDs")
    return tuple(available[item] for item in selected_ids if item in available)


class AgenticModuleOne:
    """DeepAgents-owned Module I candidate discovery with deterministic contract validation."""

    def __init__(self, runtime: SemanticRuntime) -> None:
        if not runtime.is_deepagents:
            raise TypeError("agentic Module I requires a LangChain Deep Agents runtime")
        self.runtime = runtime
        # Per-partition OWASP API Top 10 examination record of the last run (coverage only).
        self.coverage_checklist: tuple[CoverageChecklistItem, ...] = ()

    def run(
        self,
        graph: RepositoryAssetGraph,
        knowledge: KnowledgeSnapshot,
        vulnerability_graph: KnowledgeGraphSnapshot,
        *,
        max_candidates: int = 500,
        partitions: tuple[Partition, ...] | None = None,
        profile: ScanProfile | None = None,
    ) -> tuple[PotentialVulnerabilityRow, ...]:
        lead_limit = max(100, max_candidates * 2)
        leads = ModuleOne().run(
            graph,
            knowledge,
            vulnerability_graph=vulnerability_graph,
            max_candidates=lead_limit,
            graph_depth=profile.graph_hop_depth if profile else 2,
        )
        if not partitions:
            output = self.runtime.discover_candidates(
                leads,
                graph,
                vulnerability_graph,
                max_candidates=max_candidates,
                profile=profile,
            )
        else:
            outputs = tuple(
                parallel_map(
                    lambda partition: self._discover_or_fail_closed(
                        leads, graph, vulnerability_graph, max_candidates, partition, profile
                    ),
                    partitions,
                    profile.partition_concurrency if profile else 1,
                )
            )
            output = self.merge(outputs, tuple(item.partition_id for item in partitions))
        ranked = sorted(output.candidates, key=lambda item: -item.investigation_priority)
        if len(ranked) > max_candidates:
            # Budget policy: the remainder is queued, never treated as reviewed or safe.
            output = output.model_copy(
                update={
                    "coverage_warnings": (
                        *output.coverage_warnings,
                        f"{len(ranked) - max_candidates} lower-priority agent candidates exceeded "
                        f"the {max_candidates}-candidate budget and were queued, not reviewed",
                    )
                }
            )
        output = output.model_copy(update={"candidates": tuple(ranked[:max_candidates])})
        self.coverage_checklist = output.coverage_checklist
        return self._materialize(
            output,
            leads,
            graph,
            knowledge,
            vulnerability_graph,
            max_candidates=max_candidates,
        )

    def _discover_or_fail_closed(
        self,
        leads: tuple[PotentialVulnerabilityRow, ...],
        graph: RepositoryAssetGraph,
        vulnerability_graph: KnowledgeGraphSnapshot,
        max_candidates: int,
        partition: Partition,
        profile: ScanProfile | None,
    ) -> ModuleOneAgentOutput:
        """One partition's discovery; an unrecoverable contract failure fails closed for it only."""
        try:
            return self.runtime.discover_candidates(
                leads,
                graph,
                vulnerability_graph,
                max_candidates=max_candidates,
                focus=partition,
                profile=profile,
            )
        except ContractRepairFailed as exc:
            emit("partition_failed_closed", f"module1[{partition.partition_id}]", str(exc))
            risks = sorted(
                (
                    item
                    for item in vulnerability_graph.entities
                    if item.entity_type == "OWASP_API_RISK"
                ),
                key=lambda item: int(item.metadata.get("rank", 0) or 0),
            )
            return ModuleOneAgentOutput(
                candidates=(),
                analyzed_asset_ids=(),
                coverage_warnings=(
                    f"partition not analyzed: its Module I output failed contract validation "
                    f"after repair and salvage ({exc}); absence of candidates here is not evidence "
                    "of safety",
                ),
                summary="Partition not analyzed (failed closed).",
                # No specialist provenance is claimed for a partition that produced no output.
                specialist_reviews=(),
                coverage_checklist=tuple(
                    CoverageChecklistItem(
                        entity_id=risk.entity_id,
                        status="not_examined",
                        note="Partition failed closed; not examined.",
                        partition_id=partition.partition_id,
                    )
                    for risk in risks
                ),
            )

    @staticmethod
    def merge(
        outputs: tuple[ModuleOneAgentOutput, ...], partition_ids: tuple[str, ...]
    ) -> ModuleOneAgentOutput:
        """Combine per-partition outputs; dedup and validation happen in _materialize."""
        labeled = tuple(zip(partition_ids, outputs, strict=True))
        return ModuleOneAgentOutput(
            candidates=tuple(item for output in outputs for item in output.candidates),
            analyzed_asset_ids=tuple(
                dict.fromkeys(item for output in outputs for item in output.analyzed_asset_ids)
            ),
            coverage_warnings=tuple(
                dict.fromkeys(
                    f"[{partition_id}] {warning}"
                    for partition_id, output in labeled
                    for warning in output.coverage_warnings
                )
            ),
            summary=" ".join(
                f"[{partition_id}] {output.summary}" for partition_id, output in labeled
            ),
            specialist_reviews=tuple(
                dict.fromkeys(item for output in outputs for item in output.specialist_reviews)
            ),
            coverage_checklist=tuple(
                item for output in outputs for item in output.coverage_checklist
            ),
        )

    @staticmethod
    def _materialize(
        output: ModuleOneAgentOutput,
        leads: tuple[PotentialVulnerabilityRow, ...],
        graph: RepositoryAssetGraph,
        knowledge: KnowledgeSnapshot,
        vulnerability_graph: KnowledgeGraphSnapshot,
        *,
        max_candidates: int,
    ) -> tuple[PotentialVulnerabilityRow, ...]:
        required_reviews = {"repository-mapping", "candidate-discovery", "candidate-review"}
        if not required_reviews <= set(output.specialist_reviews):
            raise InvalidModuleOneAgentOutput("Module I specialist/reviewer coverage is incomplete")
        if len(output.candidates) > max_candidates:
            raise InvalidModuleOneAgentOutput("agent exceeded the Module I candidate budget")
        assets = {asset.asset_id: asset for asset in graph.assets}
        evidence_ids = {item.evidence_id for item in graph.evidence}
        knowledge_index = KnowledgeGraphIndex(vulnerability_graph)
        severity = {item.vulnerability_id: item for item in knowledge.criticality}
        if not set(output.analyzed_asset_ids) <= set(assets):
            raise InvalidModuleOneAgentOutput("agent reported unknown analyzed assets")
        lead_rules: dict[tuple[str, str], set[str]] = {}
        for lead in leads:
            lead_rules.setdefault((lead.asset_id, lead.vulnerability_id), set()).update(
                lead.rule_ids
            )
        rows: list[PotentialVulnerabilityRow] = []
        seen: set[tuple[str, str, str]] = set()
        forbidden_verdict = MODULE_ONE_FORBIDDEN_VERDICT
        for proposal in output.candidates:
            asset = assets.get(proposal.primary_asset_id)
            if asset is None:
                raise InvalidModuleOneAgentOutput("candidate references an unknown primary asset")
            entity = knowledge_index.entity(proposal.vulnerability_id)
            if entity is None:
                raise InvalidModuleOneAgentOutput("candidate references an unknown G_V entity")
            if not proposal.observed_evidence_refs:
                raise InvalidModuleOneAgentOutput("agent candidate lacks observed evidence")
            if not set(proposal.observed_evidence_refs) <= evidence_ids:
                raise InvalidModuleOneAgentOutput("agent candidate invents evidence IDs")
            if forbidden_verdict.search(proposal.hypothesis) or forbidden_verdict.search(
                proposal.discovery_basis
            ):
                raise InvalidModuleOneAgentOutput("Module I agent emitted a verification verdict")
            key = (
                proposal.primary_asset_id,
                proposal.vulnerability_id,
                " ".join(proposal.hypothesis.casefold().split()),
            )
            if key in seen:
                continue
            seen.add(key)
            related = _selected_related(graph, asset, proposal.related_asset_ids)
            signal = severity.get(proposal.vulnerability_id)
            rules = lead_rules.get((proposal.primary_asset_id, proposal.vulnerability_id), set())
            rules.add("agent.module1.discovery.v1")
            warnings = tuple(
                dict.fromkeys((*output.coverage_warnings, *proposal.coverage_warnings))
            )
            rows.append(
                PotentialVulnerabilityRow(
                    candidate_id=_agent_candidate_id(
                        graph,
                        knowledge,
                        proposal.primary_asset_id,
                        proposal.vulnerability_id,
                        proposal.hypothesis,
                    ),
                    snapshot_id=graph.snapshot.snapshot_id,
                    kb_snapshot_id=knowledge.kb_snapshot_id,
                    asset_id=asset.asset_id,
                    node=asset.path,
                    asset_type=asset.node_type,
                    vulnerability_id=proposal.vulnerability_id,
                    vulnerability_name=entity.name,
                    hypothesis=proposal.hypothesis,
                    catalog_severity=signal.catalog_severity if signal else None,
                    catalog_cvss=signal.cvss_base_score if signal else None,
                    investigation_priority=proposal.investigation_priority,
                    priority_features={
                        "agent_priority": proposal.investigation_priority,
                        "evidence_strength": None,
                        "entrypoint_exposure": None,
                        "potential_impact": None,
                        "path_relevance": None,
                        "exploit_signal": None,
                        "rule_specificity": None,
                    },
                    related_nodes=related,
                    rule_ids=tuple(sorted(rules)),
                    observed_evidence_refs=proposal.observed_evidence_refs,
                    untested_preconditions=proposal.untested_preconditions,
                    derivation_kind="agent_inference",
                    knowledge_context=_knowledge_context(
                        proposal.vulnerability_id, knowledge_index
                    ),
                    coverage_warnings=warnings,
                )
            )
        rows.sort(key=lambda row: (-row.investigation_priority, row.node, row.vulnerability_id))
        return tuple(rows)
