from importlib.resources import files
from itertools import product

import yaml

from sentinel.models.attack import AttackGraph, Condition, Formula


def knowledge(name):
    return yaml.safe_load(files("sentinel.knowledge").joinpath(name).read_text(encoding="utf-8"))


def suggest_outcomes(graph):
    suggestions = []
    for outcome in knowledge("outcomes.yaml")["outcomes"]:
        matched = sorted(
            n.id
            for n in graph.nodes
            if n.type in outcome["target_types"]
            and any(s in n.name.lower() for s in outcome["relevant_signals"])
        )
        if matched:
            suggestions.append({**outcome, "signal_node_ids": matched})
    return suggestions


def minimal_paths(formula: Formula, limit: int = 30):
    """Bounded DNF expansion, preserving negation; reports incomplete enumeration."""
    truncated = False

    def expand(f, negate=False):
        nonlocal truncated
        if f.condition_id:
            return [frozenset([("!" if negate else "") + f.condition_id])]
        if f.op == "NOT":
            return expand(f.children[0], not negate)
        op = f.op if not negate else {"AND": "OR", "OR": "AND"}[f.op]
        children = [expand(c, negate) for c in f.children]
        result = []
        combinations = ([p] for group in children for p in group) if op == "OR" else product(*children)
        for combination in combinations:
            path = frozenset().union(*combination)
            if any((lit[1:] if lit.startswith("!") else "!" + lit) in path for lit in path):
                continue
            if any(existing <= path for existing in result):
                continue
            result = [existing for existing in result if not path < existing]
            result.append(path)
            if len(result) > limit:
                truncated = True
                result = result[:limit]
                break
        return result

    result = expand(formula)
    return sorted([sorted(p) for p in result]), truncated


def _bindings(graph):
    nodes = sorted(graph.nodes, key=lambda n: ("refund" not in n.name.lower(), n.id))

    def first(kind):
        return next((n for n in nodes if n.type == kind), None)

    tool, agent = first("TOOL"), first("AI_AGENT")
    # Prefer a declared callable tool of the selected agent.
    if agent:
        targets = {e.target for e in graph.edges if e.source == agent.id and e.type == "CAN_INVOKE"}
        tool = next((n for n in nodes if n.id in targets and n.type == "TOOL"), tool)
    backend = None
    if tool:
        targets = {e.target for e in graph.edges if e.source == tool.id and e.type == "CALLS"}
        backend = next((n for n in nodes if n.id in targets and n.type == "FUNCTION"), None)
    backend = backend or next((n for n in nodes if n.type == "FUNCTION" and "refund" in n.name.lower()), None)
    return {
        "agent": agent,
        "tool": tool,
        "backend": backend,
        "identity": first("IDENTITY"),
        "datastore": first("DATASTORE"),
    }


def backward_expand(outcome, graph, max_depth=5, max_paths=30, mechanisms=None):
    if not 1 <= max_depth <= 10 or not 1 <= max_paths <= 100:
        raise ValueError("Search bounds exceeded")
    templates = mechanisms or knowledge("mechanisms.yaml")
    if outcome not in templates["rules"]:
        raise ValueError("Unsupported dangerous outcome")
    bindings, conditions, truncated = _bindings(graph), {}, False

    def leaf(name, bounded=False):
        cid = "condition:" + name
        if cid in conditions:
            return Formula(condition_id=cid)
        spec = templates["conditions"].get(
            name,
            {
                "description": "Unexpanded condition at search bound",
                "binding": "backend",
                "mechanism_id": "search-bound",
                "analyzer": "retrieve_graph",
            },
        )
        asset = bindings.get(spec["binding"])
        evidence_ids = list(asset.evidence_ids) if asset else []
        truth, status = "unknown", "unknown"
        if name == "tool_callable" and bindings["agent"] and bindings["tool"]:
            links = [
                e
                for e in graph.edges
                if e.source == bindings["agent"].id
                and e.target == bindings["tool"].id
                and e.type == "CAN_INVOKE"
                and e.epistemic_status == "observed"
            ]
            if links:
                truth, status = "true", "observed"
                evidence_ids = sorted({i for e in links for i in e.evidence_ids})
        assumptions = []
        if name in {"agent_compromised", "identity_compromised"}:
            assumptions = [spec["description"]]
        if name in {"privileged_authority", "data_access"}:
            assumptions = ["Source declarations do not establish deployed privileges"]
        conditions[cid] = Condition(
            id=cid,
            **spec,
            asset_ids=[asset.id] if asset else [],
            status=status,
            truth=truth,
            evidence_ids=evidence_ids,
            assumptions=assumptions,
        )
        return Formula(condition_id=cid)

    def expand(item, stack=(), depth=0):
        nonlocal truncated
        if isinstance(item, dict):
            return Formula(op=item["op"], children=[expand(c, stack, depth + 1) for c in item["children"]])
        if item not in templates["rules"]:
            return leaf(item)
        if item in stack or depth >= max_depth:
            truncated = True
            return leaf("unexpanded_" + item, True)
        return expand(templates["rules"][item], stack + (item,), depth + 1)

    formula = expand(outcome)
    paths, path_truncated = minimal_paths(formula, max_paths)
    applicable = outcome in {x["id"] for x in suggest_outcomes(graph)}
    return AttackGraph(
        outcome_id=outcome,
        formula=formula,
        conditions=list(conditions.values()),
        paths=paths,
        bounds={"max_depth": max_depth, "max_paths": max_paths, "truncated": truncated or path_truncated},
        applicable=applicable,
        limitations=[
            "Bounded template search can miss attack paths.",
            "One representative asset per role is modeled; source names are relevance signals only.",
            "Deployment privileges, guard effectiveness, and successful prompt influence remain unknown.",
        ],
    )
