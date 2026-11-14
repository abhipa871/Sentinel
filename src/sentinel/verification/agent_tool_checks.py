def inspect_agent_tools(context, inputs):
    selected = set(inputs["node_ids"])
    edges = [
        e
        for e in context.graph.edges
        if e.type == "CAN_INVOKE" and (e.source in selected or e.target in selected)
    ]
    configs = [
        n for n in context.graph.nodes if n.path == inputs["path"] and "declared_scopes" in n.attributes
    ]
    risks = []
    if edges:
        risks.append("Declared tool access may enable privileged requests; backend acceptance is unknown")
    if any(
        "*" in scope or scope.endswith(":*") for n in configs for scope in n.attributes["declared_scopes"]
    ):
        risks.append("Broad declared tool scope; actual deployed authority is unknown")
    return {
        "declared_tools": [
            {"agent_id": e.source, "tool_id": e.target, "status": e.epistemic_status} for e in edges
        ],
        "declared_scopes": [s for n in configs for s in n.attributes["declared_scopes"]],
        "risk_signals": risks,
        "backend_acceptance": "unknown",
        "runtime_information_flow": "unknown",
        "evidence_ids": sorted(
            {i for e in edges for i in e.evidence_ids} | {i for n in configs for i in n.evidence_ids}
        ),
    }
