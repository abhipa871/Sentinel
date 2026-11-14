from sentinel.models.attack import Formula
from sentinel.reasoning.backward import backward_expand, minimal_paths
from sentinel.reasoning.counterfactual import evaluate_formula, simulate_compromise
from sentinel.reasoning.shared_dependencies import rank_shared_conditions


def test_backward_and_gate_requires_all_conditions():
    formula = Formula(op="AND", children=[Formula(condition_id="a"), Formula(condition_id="b")])
    assert evaluate_formula(formula, {"a": "true", "b": "unknown"}) == "unknown"
    assert evaluate_formula(formula, {"a": "true", "b": "false"}) == "false"
    assert evaluate_formula(formula, {"a": "true", "b": "true"}) == "true"


def test_backward_or_gate_accepts_alternate_route():
    formula = Formula(op="OR", children=[Formula(condition_id="a"), Formula(condition_id="b")])
    assert evaluate_formula(formula, {"a": "false", "b": "true"}) == "true"
    assert evaluate_formula(formula, {"a": "unknown", "b": "false"}) == "unknown"


def test_not_unknown_is_unknown():
    formula = Formula(op="NOT", children=[Formula(condition_id="auth")])
    assert evaluate_formula(formula, {}) == "unknown"


def test_counterfactual_does_not_mutate_observed_facts(context):
    before = context.attack.model_dump_json()
    component = next(
        c.asset_ids[0] for c in context.attack.conditions if c.id == "condition:agent_compromised"
    )
    result = simulate_compromise(component, context.attack)
    assert result["reachability"] == "conditionally_reachable"
    assert not result["reachable_outcomes"]
    assert context.attack.model_dump_json() == before


def test_backend_control_blocks_both_routes(context):
    values = {c.id: "true" for c in context.attack.conditions}
    assert evaluate_formula(context.attack.formula, values) == "false"
    values["condition:independent_authorization"] = "false"
    assert evaluate_formula(context.attack.formula, values) == "true"


def test_shared_dependency_ranking(context):
    shared = rank_shared_conditions(context.attack.paths, context.attack.conditions)
    assert {s["condition_id"] for s in shared} == {
        "condition:privileged_authority",
        "condition:independent_authorization",
    }
    assert all(s["blocks_all_enumerated_paths"] for s in shared)
    assert len(context.attack.paths) == 2
    assert not context.attack.bounds["truncated"]


def test_prime_implicants_preserve_negation_and_remove_supersets():
    formula = Formula.model_validate(
        {
            "op": "OR",
            "children": [
                {"condition_id": "a"},
                {"op": "AND", "children": [{"condition_id": "a"}, {"condition_id": "b"}]},
                {
                    "op": "AND",
                    "children": [{"condition_id": "c"}, {"op": "NOT", "children": [{"condition_id": "c"}]}],
                },
            ],
        }
    )
    paths, truncated = minimal_paths(formula)
    assert paths == [["a"]]
    assert not truncated


def test_bounded_cycles_and_path_enumeration(context):
    graph = backward_expand("unauthorized_refund", context.graph, max_paths=1)
    assert len(graph.paths) == 1 and graph.bounds["truncated"]
    cyclic = {"rules": {"unauthorized_refund": "loop", "loop": "unauthorized_refund"}, "conditions": {}}
    graph = backward_expand("unauthorized_refund", context.graph, mechanisms=cyclic)
    assert graph.bounds["truncated"]
    assert all(c.truth == "unknown" for c in graph.conditions)
