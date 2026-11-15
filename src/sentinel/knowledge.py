from typing import Any
from uuid import uuid5

from sentinel.contracts import (
    ApplicabilityRule,
    AssetType,
    CriticalitySignal,
    KnowledgeGraphSnapshot,
    KnowledgeSnapshot,
)
from sentinel.phase0 import NAMESPACE

CWE_NAMES = {
    "CWE-89": "Improper Neutralization of Special Elements in an SQL Command",
    "CWE-295": "Improper Certificate Validation",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-862": "Missing Authorization",
    "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-943": "Improper Neutralization of Special Elements in Data Query Logic",
}

AUTHORIZATION_PRECONDITIONS = (
    "operation_requires_authorization",
    "actor_identity_reaches_operation",
    "effective_authorization_check_is_absent",
)
SSRF_PRECONDITIONS = (
    "request_target_is_influenced_by_client_input",
    "destination_allowlist_is_absent_or_ineffective",
    "response_or_side_effect_reaches_the_attacker",
)
SQL_PRECONDITIONS = (
    "input_is_untrusted",
    "input_changes_query_structure",
    "safe_parameter_binding_is_absent_or_ineffective",
    "sink_is_reachable",
)


def _cwe_url(vulnerability_id: str) -> str:
    return f"https://cwe.mitre.org/data/definitions/{vulnerability_id.removeprefix('CWE-')}.html"


def _rule(
    rule_id: str,
    vulnerability_id: str,
    languages: tuple[str, ...],
    required: dict[str, Any],
    preconditions: tuple[str, ...],
    weight: float,
) -> ApplicabilityRule:
    return ApplicabilityRule(
        rule_id=rule_id,
        vulnerability_id=vulnerability_id,
        vulnerability_name=CWE_NAMES[vulnerability_id],
        rule_version=1,
        applicable_asset_types=(AssetType.SOURCE_FILE,),
        language_tags=languages,
        required_features=required,
        necessary_preconditions=preconditions,
        derivation_kind="curated_derived",
        source_refs=(_cwe_url(vulnerability_id),),
        weight=weight,
    )


def curated_mvp_knowledge(
    vulnerability_graph: KnowledgeGraphSnapshot | None = None,
) -> KnowledgeSnapshot:
    """Return the reviewed, versioned vertical-slice rules.

    These rules generate investigation candidates only. Their untested preconditions are resolved
    by Module II Deep Agents specialists, never by this deterministic matcher. Every predicate is
    over Phase 0 syntax facts; none of them asserts a vulnerability.
    """

    version = "mvp-2026-11-14.2"
    snapshot_id = (
        vulnerability_graph.kb_snapshot_id
        if vulnerability_graph
        else uuid5(NAMESPACE, f"sentinel-kb:{version}")
    )
    graph_manifest = vulnerability_graph.source_manifest if vulnerability_graph else {}
    rules = (
        _rule(
            "rule.cwe-89.python.sql-api.v1",
            "CWE-89",
            ("python",),
            {
                "any_api_symbols": (
                    "execute",
                    "executemany",
                    "cursor.execute",
                    "connection.execute",
                    "raw",
                )
            },
            SQL_PRECONDITIONS,
            0.9,
        ),
        _rule(
            "rule.cwe-862.python.route.v1",
            "CWE-862",
            ("python",),
            {"equals": {"has_route": True}},
            AUTHORIZATION_PRECONDITIONS,
            0.75,
        ),
        _rule(
            "rule.cwe-502.python.deserialize-api.v1",
            "CWE-502",
            ("python",),
            {
                "any_api_symbols": (
                    "pickle.load",
                    "pickle.loads",
                    "yaml.load",
                    "torch.load",
                    "marshal.loads",
                )
            },
            (
                "serialized_input_is_untrusted",
                "loader_configuration_is_unsafe",
                "deserializer_is_reachable",
            ),
            0.95,
        ),
        # OWASP API1:2023 Broken Object Level Authorization references CWE-639.
        _rule(
            "rule.cwe-639.route-object-identifier.v1",
            "CWE-639",
            ("python", "java", "go"),
            {"nonempty": ("route_params",)},
            (
                "route_parameter_identifies_an_object_from_client_input",
                "object_ownership_or_tenant_check_is_absent_or_ineffective",
                "actor_can_reach_the_route",
            ),
            0.8,
        ),
        _rule(
            "rule.cwe-862.jvm-go.route.v1",
            "CWE-862",
            ("java", "go"),
            {"equals": {"has_route": True}},
            AUTHORIZATION_PRECONDITIONS,
            0.75,
        ),
        # OWASP API3:2023 Broken Object Property Level Authorization references CWE-915.
        _rule(
            "rule.cwe-915.python.serializer-all-fields.v1",
            "CWE-915",
            ("python",),
            {"any_string_literals": ("__all__",)},
            (
                "serializer_binds_client_input_to_model_fields",
                "sensitive_or_privileged_fields_are_writable_or_exposed",
                "field_allowlist_is_absent_or_ineffective",
            ),
            0.7,
        ),
        _rule(
            "rule.cwe-915.jvm-go.request-body-binding.v1",
            "CWE-915",
            ("java", "go"),
            {"equals": {"request_body_binding": True, "has_route": True}},
            (
                "request_body_is_bound_to_a_persistent_model",
                "sensitive_or_privileged_fields_are_writable",
                "field_allowlist_is_absent_or_ineffective",
            ),
            0.65,
        ),
        # OWASP API7:2023 Server Side Request Forgery references CWE-918.
        _rule(
            "rule.cwe-918.python.outbound-http.v1",
            "CWE-918",
            ("python",),
            {
                "any_api_symbols": (
                    "requests.get",
                    "requests.post",
                    "requests.put",
                    "requests.request",
                    "httpx.get",
                    "httpx.post",
                    "httpx.request",
                    "urlopen",
                )
            },
            SSRF_PRECONDITIONS,
            0.7,
        ),
        _rule(
            "rule.cwe-918.java.outbound-http.v1",
            "CWE-918",
            ("java",),
            {
                "any_api_symbols": (
                    "getForObject",
                    "getForEntity",
                    "postForObject",
                    "postForEntity",
                    "exchange",
                    "openConnection",
                )
            },
            SSRF_PRECONDITIONS,
            0.7,
        ),
        _rule(
            "rule.cwe-918.go.outbound-http.v1",
            "CWE-918",
            ("go",),
            {
                "any_api_symbols": (
                    "http.Get",
                    "http.Post",
                    "http.NewRequest",
                    "http.NewRequestWithContext",
                )
            },
            SSRF_PRECONDITIONS,
            0.7,
        ),
        _rule(
            "rule.cwe-295.tls-verification-disabled.v1",
            "CWE-295",
            ("python", "go"),
            {"equals": {"tls_verification_disabled": True}},
            (
                "disabled_verification_applies_to_production_traffic",
                "network_path_is_reachable_by_an_attacker",
            ),
            0.85,
        ),
        _rule(
            "rule.cwe-347.python.jwt-signature-not-verified.v1",
            "CWE-347",
            ("python",),
            {"equals": {"jwt_signature_verification_disabled": True}},
            (
                "decoded_claims_drive_authentication_or_authorization",
                "no_other_effective_signature_check_precedes_use",
            ),
            0.9,
        ),
        _rule(
            "rule.cwe-347.jvm-go.jwt-validation.v1",
            "CWE-347",
            ("java", "go"),
            {
                "any_api_symbols": (
                    # jjwt
                    "parseClaimsJws",
                    "parseClaimsJwt",
                    "parserBuilder",
                    "Jwts.parser",
                    # Nimbus JOSE + JWT
                    "JWTParser.parse",
                    "SignedJWT.parse",
                    "PlainJWT.parse",
                    "JWKSet.load",
                    "getJWKURL",
                    # golang-jwt
                    "jwt.Parse",
                    "jwt.ParseWithClaims",
                )
            },
            (
                "token_signature_or_key_selection_can_be_influenced",
                "claims_are_trusted_before_signature_verification",
            ),
            0.55,
        ),
        _rule(
            "rule.cwe-943.go.mongo-query-document.v1",
            "CWE-943",
            ("go",),
            {"any_api_symbols": ("bson.M", "bson.D")},
            (
                "query_document_includes_client_controlled_values",
                "operator_injection_is_not_prevented_by_typing_or_validation",
            ),
            0.6,
        ),
        _rule(
            "rule.cwe-89.java.sql-api.v1",
            "CWE-89",
            ("java",),
            {
                "any_api_symbols": (
                    "createNativeQuery",
                    "createQuery",
                    "createStatement",
                    "executeQuery",
                    "executeUpdate",
                    "queryForObject",
                    "queryForList",
                )
            },
            SQL_PRECONDITIONS,
            0.75,
        ),
        _rule(
            "rule.cwe-89.go.sql-api.v1",
            "CWE-89",
            ("go",),
            {"any_api_symbols": ("QueryRow", "QueryRowContext", "Exec", "ExecContext")},
            SQL_PRECONDITIONS,
            0.7,
        ),
    )
    referenced = sorted({rule.vulnerability_id for rule in rules})
    return KnowledgeSnapshot(
        kb_snapshot_id=snapshot_id,
        version=f"{version}+{vulnerability_graph.version}" if vulnerability_graph else version,
        source_manifest={
            **graph_manifest,
            **{vulnerability_id: _cwe_url(vulnerability_id) for vulnerability_id in referenced},
            "AI-TOOL-AUTHZ": "curated:sentinel-ai-tool-authorization-v1",
        },
        rules=(*signal_rules(), *rules),
        criticality=tuple(
            CriticalitySignal(
                vulnerability_id=vulnerability_id,
                catalog_severity="high_typical",
                source_refs=(_cwe_url(vulnerability_id),),
            )
            # Severity signals are kept only for the originally reviewed weaknesses; none are
            # invented for the newer rules.
            for vulnerability_id in ("CWE-89", "CWE-862", "CWE-502")
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
