from sentinel.models.base import digest


def task_signature(task, commit, policy_context):
    return digest(
        {
            "kind": task.kind,
            "inputs": task.inputs,
            "commit": commit,
            "policy": policy_context,
            "sandbox": task.sandbox_required,
            "cacheable": task.cacheable,
        }
    )


def deduplicate(tasks, outputs, commit, policy_context):
    signatures, replacements, kept = {}, {}, {}
    for task in tasks:
        key = task_signature(task, commit, policy_context)
        if task.cacheable and key in signatures:
            canonical = signatures[key]
            replacements[task.id] = canonical
            kept[canonical].depends_on = sorted(set(kept[canonical].depends_on + task.depends_on))
            kept[canonical].evidence_requirements = sorted(
                set(kept[canonical].evidence_requirements + task.evidence_requirements)
            )
        else:
            signatures[key] = task.id
            replacements[task.id] = task.id
            kept[task.id] = task.model_copy(deep=True)
    for task in kept.values():
        task.depends_on = sorted({replacements[d] for d in task.depends_on if replacements[d] != task.id})
    return list(kept.values()), sorted({replacements[o] for o in outputs})


def eliminate_dead_tasks(tasks, outputs):
    by_id = {t.id: t for t in tasks}
    needed = set()

    def visit(task_id):
        if task_id in needed:
            return
        needed.add(task_id)
        for dep in by_id[task_id].depends_on:
            visit(dep)

    for output in outputs:
        visit(output)
    # Policy checks live in the executor, never in removable DAG tasks.
    return [task for task in tasks if task.id in needed]


def topological_schedule(tasks, max_workers=4):
    pending = {t.id: set(t.depends_on) for t in tasks}
    if len(pending) != len(tasks) or any(not deps <= set(pending) for deps in pending.values()):
        raise ValueError("Invalid workflow dependencies")
    result = []
    while pending:
        ready = sorted(t for t, deps in pending.items() if not deps)
        if not ready:
            raise ValueError("Workflow cycle detected")
        for index in range(0, len(ready), max_workers):
            result.append(ready[index : index + max_workers])
        for task_id in ready:
            pending.pop(task_id)
        for deps in pending.values():
            deps.difference_update(ready)
    return result
