def evaluate_formula(formula, values):
    if formula.condition_id:
        return values.get(formula.condition_id, "unknown")
    children = [evaluate_formula(child, values) for child in formula.children]
    if formula.op == "NOT":
        return {"true": "false", "false": "true", "unknown": "unknown"}[children[0]]
    if formula.op == "AND":
        return "false" if "false" in children else ("unknown" if "unknown" in children else "true")
    return "true" if "true" in children else ("unknown" if "unknown" in children else "false")


def simulate_compromise(component_id, attack_graph, known_facts=None):
    values = {c.id: c.truth for c in attack_graph.conditions}
    if known_facts:
        if not set(known_facts) <= set(values) or any(
            v not in {"true", "false", "unknown"} for v in known_facts.values()
        ):
            raise ValueError("Invalid facts")
        values.update(known_facts)
    matched = [
        c for c in attack_graph.conditions if component_id in c.asset_ids and c.id.endswith("_compromised")
    ]
    if not matched:
        raise ValueError("Component has no modeled compromise condition")
    assumptions = []
    for condition in matched:
        values[condition.id] = "true"
        assumptions.append(f"COMPROMISED({component_id})")
    truth = evaluate_formula(attack_graph.formula, values)
    return {
        "assumed_compromise": component_id,
        "assumptions": assumptions,
        "truth": truth,
        "reachability": {
            "true": "reachable_under_assumptions",
            "false": "blocked_within_model",
            "unknown": "conditionally_reachable",
        }[truth],
        "reachable_outcomes": [attack_graph.outcome_id] if truth == "true" else [],
        "conditional_outcomes": [attack_graph.outcome_id] if truth == "unknown" else [],
        "explanations": [{"condition_id": k, "truth": v} for k, v in sorted(values.items())],
    }
