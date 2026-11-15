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
            *signal_rules(),
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


_SOURCE_LANGS = ("python", "java", "go", "javascript", "typescript")

# (rule_id, CWE, name, required_features, excluded_features, preconditions, weight)
_SIGNAL_RULES: tuple[tuple[str, str, str, dict, dict, tuple[str, ...], float], ...] = (
    (
        "rule.cwe-639.bola.v1",
        "CWE-639",
        "Authorization Bypass Through User-Controlled Key",
        {"all_signals": ("object_id_param", "lookup_by_client_id")},
        {},
        ("identifier_is_client_controlled", "lookup_not_scoped_to_caller", "object_is_sensitive"),
        0.85,
    ),
    (
        "rule.cwe-285.bfla-admin.v1",
        "CWE-285",
        "Improper Authorization",
        {"all_signals": ("admin_route",)},
        {},
        ("route_is_privileged", "role_check_absent_or_ineffective"),
        0.8,
    ),
    (
        "rule.cwe-306.unauth-handler.v1",
        "CWE-306",
        "Missing Authentication for Critical Function",
        {"all_signals": ("unauthenticated_handler", "lookup_by_client_id")},
        {},
        ("handler_exposes_sensitive_data_or_action", "no_upstream_authentication"),
        0.8,
    ),
    (
        "rule.cwe-307.auth-bruteforce.v1",
        "CWE-307",
        "Improper Restriction of Excessive Authentication Attempts",
        {"all_signals": ("auth_sensitive_route",)},
        {"any_signals": ("rate_limit_marker",)},
        ("secret_space_is_enumerable", "no_attempt_limit_upstream"),
        0.7,
    ),
    (
        "rule.cwe-918.ssrf.v1",
        "CWE-918",
        "Server-Side Request Forgery (SSRF)",
        {"all_signals": ("outbound_request_dynamic", "request_body_input")},
        {},
        (
            "url_or_host_is_attacker_controlled",
            "no_allowlist",
            "response_or_side_effect_observable",
        ),
        0.9,
    ),
    (
        "rule.cwe-770.repeat-amplification.v1",
        "CWE-770",
        "Allocation of Resources Without Limits or Throttling",
        {"all_signals": ("request_repeat_param", "outbound_request_dynamic")},
        {},
        ("repeat_count_is_client_controlled", "bound_is_ineffective"),
        0.7,
    ),
    (
        "rule.cwe-89.concat.v1",
        "CWE-89",
        "Improper Neutralization of Special Elements used in an SQL Command",
        {"all_signals": ("raw_sql_concat",)},
        {},
        ("concatenated_value_is_untrusted", "sink_is_reachable"),
        0.95,
    ),
    (
        "rule.cwe-943.nosql-filter.v1",
        "CWE-943",
        "Improper Neutralization of Special Elements in Data Query Logic",
        {"all_signals": ("nosql_query", "untyped_request_filter")},
        {},
        ("request_object_reaches_query_filter", "operators_not_stripped"),
        0.9,
    ),
    (
        "rule.cwe-915.mass-assignment.v1",
        "CWE-915",
        "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        {"any_signals": ("attr_from_request", "serializer_all_fields")},
        {},
        ("field_is_security_relevant", "no_allowlist_or_server_side_validation"),
        0.75,
    ),
    (
        "rule.cwe-347.jwt-header-trust.v1",
        "CWE-347",
        "Improper Verification of Cryptographic Signature",
        {"all_signals": ("jwt_header_trust",)},
        {},
        ("algorithm_or_key_selected_from_token", "verification_accepts_attacker_key"),
        0.95,
    ),
    (
        "rule.cwe-213.exposure.v1",
        "CWE-213",
        "Exposure of Sensitive Information Due to Incompatible Policies",
        {"any_signals": ("sensitive_json_field", "jpa_entity_unfiltered", "serializer_all_fields")},
        {},
        ("object_is_returned_to_other_users", "field_is_sensitive"),
        0.6,
    ),
    (
        "rule.cwe-1427.prompt-injection.v1",
        "CWE-1427",
        "Improper Neutralization of Input Used for LLM Prompting",
        {"all_signals": ("llm_client", "llm_tools_or_agent")},
        {},
        ("untrusted_text_reaches_prompt", "model_output_drives_tools_or_data_access"),
        0.85,
    ),
    (
        "rule.cwe-441.confused-deputy.v1",
        "CWE-441",
        "Unintended Proxy or Intermediary ('Confused Deputy')",
        {"all_signals": ("tool_server", "static_service_credential")},
        {},
        ("tool_calls_use_service_identity", "end_user_authorization_not_propagated"),
        0.85,
    ),
)


def signal_rules() -> tuple[ApplicabilityRule, ...]:
    return tuple(
        ApplicabilityRule(
            rule_id=rule_id,
            vulnerability_id=cwe,
            vulnerability_name=name,
            rule_version=1,
            applicable_asset_types=(AssetType.SOURCE_FILE,),
            language_tags=_SOURCE_LANGS,
            required_features=required,
            excluded_features=excluded,
            necessary_preconditions=pre,
            derivation_kind="curated_derived",
            source_refs=(f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html",),
            weight=weight,
        )
        for rule_id, cwe, name, required, excluded, pre, weight in _SIGNAL_RULES
    )
