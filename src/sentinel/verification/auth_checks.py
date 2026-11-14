def inspect_authorization(context, inputs):
    selected = [n for n in context.graph.nodes if n.id in inputs["node_ids"]]
    guards = sorted(
        {guard for node in selected for guard in node.attributes.get("auth_guard_candidates", [])}
    )
    return {
        "auth_guard_candidates": guards,
        "status": "inconclusive",
        "condition_truth": "unknown",
        "claim": "Authorization-like calls are present"
        if guards
        else "No recognized authorization call in selected symbols",
        "unknowns": [
            "Guard effectiveness",
            "Caller identity binding",
            "Deployment policy",
            "Authorization outside selected symbols",
        ],
        "evidence_ids": sorted({e for n in selected for e in n.evidence_ids}),
    }
