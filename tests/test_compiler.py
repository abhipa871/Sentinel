from dataclasses import replace

import pytest

from sentinel.compiler.invalidation import task_cache_key
from sentinel.compiler.passes import topological_schedule
from sentinel.compiler.planner import compile_request, default_requests, specialize_remaining
from sentinel.models.investigation import InvestigationQuestion, InvestigationRequest
from sentinel.runtime.executor import execute
from sentinel.runtime.policy import PolicyError


def test_compiler_deduplicates_identical_read_only_tasks(context):
    request = default_requests(context)[0]
    request.questions.append(request.questions[0])
    workflow = compile_request(request, context)
    assert sum(t.kind == "retrieve_graph" for t in workflow.tasks) == 1
    assert len({t.id for t in workflow.tasks}) == len(workflow.tasks)


def test_compiler_reuses_tasks_across_agent_proposals(context, cache):
    workflows = [compile_request(r, context) for r in default_requests(context)]
    first = execute(workflows[0], context, cache)
    second = execute(workflows[1], context, cache)
    assert not any(r.cache_hit for r in first)
    assert any(r.cache_hit and r.kind == "retrieve_graph" for r in second)


def test_cache_closes_database_handles(context, cache):
    workflow = compile_request(default_requests(context)[0], context)
    execute(workflow, context, cache)
    # Windows cannot rename this database if a connection has leaked.
    moved = cache.path.with_suffix(".closed.sqlite3")
    cache.path.rename(moved)
    assert moved.exists()


def test_cache_invalidates_only_dependent_tasks(context, cache):
    workflows = [compile_request(r, context) for r in default_requests(context)]
    for workflow in workflows:
        execute(workflow, context, cache)
    invalidated = cache.invalidate(context.snapshot.repository_id, ["app/agent.py"])
    assert invalidated
    for workflow in workflows:
        for task in workflow.tasks:
            cached = cache.get(task_cache_key(task, context))
            if "app/agent.py" in task.file_dependencies:
                assert cached is None
            else:
                assert cached is not None


def test_compiler_preserves_mandatory_policy_checks(context, cache):
    workflow = compile_request(default_requests(context)[0], context)
    execute(workflow, context, cache)
    workflow.tasks[0].policy_rules = []
    with pytest.raises(PolicyError):
        execute(workflow, context, cache)


def test_executor_rejects_unapproved_tool(context, cache):
    workflow = compile_request(default_requests(context)[0], context)
    # Simulate a malicious unvalidated deserializer bypassing Pydantic.
    object.__setattr__(workflow.tasks[0], "kind", "shell")
    with pytest.raises(PolicyError):
        execute(workflow, context, cache)


def test_executor_rejects_paths_and_unknown_inputs(context, cache):
    workflow = compile_request(default_requests(context)[0], context)
    task = next(t for t in workflow.tasks if t.kind == "inspect_source")
    task.inputs["path"] = "../.env"
    with pytest.raises(PolicyError):
        execute(workflow, context, cache)
    task.inputs = {"path": "app/payment.py", "node_ids": [], "shell": "not allowed"}
    with pytest.raises(ValueError):
        execute(workflow, context, cache)


def test_workflow_cycle_is_rejected(context):
    workflow = compile_request(default_requests(context)[0], context)
    workflow.tasks[0].depends_on = [workflow.tasks[-1].id]
    workflow.tasks[-1].depends_on = [workflow.tasks[0].id]
    with pytest.raises(ValueError):
        topological_schedule(workflow.tasks)


def test_runtime_specialization_eliminates_resolved_questions(context):
    request = default_requests(context)[0]
    resolved = {q.condition_id for q in request.questions}
    workflow = specialize_remaining(request, context, resolved)
    assert workflow.tasks == []
    assert workflow.policy_version == context.policy_version


def test_policy_change_never_reuses_old_cache(context, cache):
    workflow = compile_request(default_requests(context)[0], context)
    execute(workflow, context, cache)
    changed = replace(context, policy_version="new-policy")
    with pytest.raises(PolicyError):
        execute(workflow, changed, cache)
    new_workflow = compile_request(default_requests(changed)[0], changed)
    assert not any(r.cache_hit for r in execute(new_workflow, changed, cache))


def test_mock_requires_explicit_opt_in_and_inspection_dependencies(context, cache):
    request = InvestigationRequest(
        outcome_id=context.attack.outcome_id,
        questions=[
            InvestigationQuestion(
                hypothesis_id="test",
                condition_id=context.attack.conditions[0].id,
                analyzer="mock_verify",
                fixture_id="refund_vulnerable",
                reason="Synthetic comparison",
            )
        ],
    )
    with pytest.raises(PolicyError):
        compile_request(request, context)
    authorized = replace(context, allow_mock=True)
    workflow = compile_request(request, authorized)
    mock = next(t for t in workflow.tasks if t.kind == "mock_verify")
    kinds = {t.kind for t in workflow.tasks if t.id in mock.depends_on}
    assert {"inspect_auth", "inspect_agent_tools", "retrieve_graph"} <= kinds
    results = execute(workflow, authorized, cache)
    assert next(r.data for r in results if r.kind == "mock_verify")["backend_accepted"]
    mock.depends_on = []
    with pytest.raises(PolicyError):
        execute(workflow, authorized, cache)
