from uuid import uuid5

from sentinel.contracts import (
    ApplicabilityRule,
    AssetType,
    CriticalitySignal,
    KnowledgeGraphSnapshot,
    KnowledgeSnapshot,
)
from sentinel.phase0 import NAMESPACE


def curated_mvp_knowledge(
    vulnerability_graph: KnowledgeGraphSnapshot | None = None,
) -> KnowledgeSnapshot:
    """Return the reviewed, versioned vertical-slice rules.

    These rules generate investigation candidates only. Their untested preconditions are resolved
    by Module II Deep Agents specialists, never by this deterministic matcher.
    """

    version = "mvp-2026-11-14"
    snapshot_id = (
        vulnerability_graph.kb_snapshot_id
        if vulnerability_graph
        else uuid5(NAMESPACE, f"sentinel-kb:{version}")
    )
    graph_manifest = vulnerability_graph.source_manifest if vulnerability_graph else {}
    return KnowledgeSnapshot(
        kb_snapshot_id=snapshot_id,
        version=f"{version}+{vulnerability_graph.version}" if vulnerability_graph else version,
        source_manifest={
            **graph_manifest,
            "CWE-89": "https://cwe.mitre.org/data/definitions/89.html",
            "CWE-862": "https://cwe.mitre.org/data/definitions/862.html",
            "CWE-502": "https://cwe.mitre.org/data/definitions/502.html",
            "AI-TOOL-AUTHZ": "curated:sentinel-ai-tool-authorization-v1",
        },
        rules=(
            ApplicabilityRule(
                rule_id="rule.cwe-89.python.sql-api.v1",
                vulnerability_id="CWE-89",
                vulnerability_name="Improper Neutralization of Special Elements in an SQL Command",
                rule_version=1,
                applicable_asset_types=(AssetType.SOURCE_FILE,),
                language_tags=("python",),
                required_features={
                    "any_api_symbols": (
                        "execute",
                        "executemany",
                        "cursor.execute",
                        "connection.execute",
                        "raw",
                    )
                },
                necessary_preconditions=(
                    "input_is_untrusted",
                    "input_changes_query_structure",
                    "safe_parameter_binding_is_absent_or_ineffective",
                    "sink_is_reachable",
                ),
                derivation_kind="curated_derived",
                source_refs=("https://cwe.mitre.org/data/definitions/89.html",),
                weight=0.9,
            ),
            ApplicabilityRule(
                rule_id="rule.cwe-862.python.route.v1",
                vulnerability_id="CWE-862",
                vulnerability_name="Missing Authorization",
                rule_version=1,
                applicable_asset_types=(AssetType.SOURCE_FILE,),
                language_tags=("python",),
                required_features={"equals": {"has_route": True}},
                necessary_preconditions=(
                    "operation_requires_authorization",
                    "actor_identity_reaches_operation",
                    "effective_authorization_check_is_absent",
                ),
                derivation_kind="curated_derived",
                source_refs=("https://cwe.mitre.org/data/definitions/862.html",),
                weight=0.75,
            ),
            ApplicabilityRule(
                rule_id="rule.cwe-502.python.deserialize-api.v1",
                vulnerability_id="CWE-502",
                vulnerability_name="Deserialization of Untrusted Data",
                rule_version=1,
                applicable_asset_types=(AssetType.SOURCE_FILE,),
                language_tags=("python",),
                required_features={
                    "any_api_symbols": (
                        "pickle.load",
                        "pickle.loads",
                        "yaml.load",
                        "torch.load",
                        "marshal.loads",
                    )
                },
                necessary_preconditions=(
                    "serialized_input_is_untrusted",
                    "loader_configuration_is_unsafe",
                    "deserializer_is_reachable",
                ),
                derivation_kind="curated_derived",
                source_refs=("https://cwe.mitre.org/data/definitions/502.html",),
                weight=0.95,
            ),
        ),
        criticality=(
            CriticalitySignal(
                vulnerability_id="CWE-89",
                catalog_severity="high_typical",
                source_refs=("https://cwe.mitre.org/data/definitions/89.html",),
            ),
            CriticalitySignal(
                vulnerability_id="CWE-862",
                catalog_severity="high_typical",
                source_refs=("https://cwe.mitre.org/data/definitions/862.html",),
            ),
            CriticalitySignal(
                vulnerability_id="CWE-502",
                catalog_severity="high_typical",
                source_refs=("https://cwe.mitre.org/data/definitions/502.html",),
            ),
        ),
    )
