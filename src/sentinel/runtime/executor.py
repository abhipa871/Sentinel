from concurrent.futures import ThreadPoolExecutor
from time import perf_counter

from sentinel.compiler.invalidation import task_cache_key
from sentinel.compiler.passes import topological_schedule
from sentinel.models.workflow import TaskResult

from .policy import PolicyError, validate_task, validate_workflow
from .tools import REGISTRY


def execute(workflow, context, cache):
    validate_workflow(workflow, context)
    by_id = {t.id: t for t in workflow.tasks}
    results = []

    def invoke(task):
        started = perf_counter()
        validate_task(task, context, workflow.scope)  # Mandatory, including cache hits.
        if task.kind not in REGISTRY:
            raise PolicyError("Tool not registered")
        key = task_cache_key(task, context)
        data = cache.get(key) if task.cacheable else None
        hit = data is not None
        if data is None:
            data = REGISTRY[task.kind](context, task.inputs)
            validate_result(task, context, data)
            if task.cacheable:
                cache.put(key, task, context, data)
        validate_result(task, context, data)
        return TaskResult(
            task_id=task.id,
            kind=task.kind,
            cache_hit=hit,
            data=data,
            duration_ms=round((perf_counter() - started) * 1000, 3),
            cache_key=key,
        )

    # Recompute schedule so a caller cannot bypass dependency ordering by changing schedule metadata.
    for group in topological_schedule(workflow.tasks):
        read_only = [by_id[i] for i in group if by_id[i].kind != "mock_verify"]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results.extend(pool.map(invoke, read_only))
        for task_id in group:
            if by_id[task_id].kind == "mock_verify":
                results.append(invoke(by_id[task_id]))
    return results


def validate_result(task, context, data):
    known = {e.id for e in context.graph.evidence}
    if data.get("evidence") or data.get("findings"):
        raise PolicyError("Deterministic verification tools cannot emit semantic findings")
    if not set(data.get("evidence_ids", [])) <= known:
        raise PolicyError("Tool returned stale or fabricated evidence")
